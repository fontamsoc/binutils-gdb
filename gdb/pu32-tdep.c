// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#include "defs.h"
#include "frame.h"
#include "frame-unwind.h"
#include "frame-base.h"
#include "symtab.h"
#include "gdbtypes.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "value.h"
#include "inferior.h"
#include "symfile.h"
#include "objfiles.h"
#include "linux-tdep.h"
#include "osabi.h"
#include "solib-svr4.h"
#include "language.h"
#include "arch-utils.h"
#include "regcache.h"
#include "regset.h"
#include "trad-frame.h"
#include "dis-asm.h"
#include "record.h"
#include "record-full.h"

#include "pu32-tdep.h"
#include <algorithm>

// Uncomment to generate debug outputs.
//#define PU32_DEBUG

// Use an invalid address value as 'not available' marker.
enum { REG_UNAVAIL = (CORE_ADDR)-1 };

// Implement the "frame_align" gdbarch method.
static CORE_ADDR pu32_frame_align (struct gdbarch *gdbarch, CORE_ADDR sp) {
	// Align to the size of a gpr.
	return sp & ~0b11;
}

constexpr gdb_byte pu32_break_insn[] = { 0x02, 0x00 };
typedef BP_MANIPULATION (pu32_break_insn) pu32_breakpoint;

static const char *pu32_register_names[] = {
	"r0",  "r1",  "r2",  "r3",
	"r4",  "r5",  "r6",  "r7",
	"r8",  "r9",  "r10", "r11",
	"r12", "r13", "r14", "r15",
	"pc"
};

// Implement the "register_name" gdbarch method.
static const char *pu32_register_name (struct gdbarch *gdbarch, int reg_nr) {

	#if defined(PU32_DEBUG) && 0
	debug_printf (
		"pu32-gdb: %s: reg_nr == %d\n",
		__FUNCTION__, reg_nr);
	#endif

	if ((unsigned)reg_nr >= PU32_NUM_REGS)
		return NULL;
	return pu32_register_names[reg_nr];
}

// Implement the "register_type" gdbarch method.
static struct type *pu32_register_type (struct gdbarch *gdbarch, int reg_nr) {

	#if defined(PU32_DEBUG) && 0
	debug_printf (
		"pu32-gdb: %s: reg_nr == %d\n",
		__FUNCTION__, reg_nr);
	#endif

	if (reg_nr == PU32_PC_REGNUM)
		return builtin_type (gdbarch)->builtin_func_ptr;
	else if (reg_nr == PU32_SP_REGNUM || reg_nr == PU32_FP_REGNUM)
		return builtin_type (gdbarch)->builtin_data_ptr;
	else
		return builtin_type (gdbarch)->builtin_int32;
}

static void pu32_extract_return_value (
	struct type *type,
	struct regcache *regcache,
	gdb_byte *dst) {

	ULONGEST tmp;
	regcache_cooked_read_unsigned (regcache, PU32_RETVAL_REGNUM, &tmp);
	store_unsigned_integer (dst, 4, BFD_ENDIAN_LITTLE, tmp);

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: PU32_RETVAL_REGNUM == 0x%x\n",
		__FUNCTION__, (unsigned int)tmp);
	#endif
}

static void pu32_store_return_value (
	struct type *type,
	struct regcache *regcache,
	const gdb_byte *valbuf) {

	CORE_ADDR regval;

	// Things always get returned in PU32_RETVAL_REGNUM.
	regval = extract_unsigned_integer (valbuf, 4, BFD_ENDIAN_LITTLE);
	regcache_cooked_write_unsigned (regcache, PU32_RETVAL_REGNUM, regval);

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: PU32_RETVAL_REGNUM == 0x%x\n",
		__FUNCTION__, (unsigned int)regval);
	#endif
}

// Implement the "return_value" gdbarch method.
static enum return_value_convention pu32_return_value (
	struct gdbarch *gdbarch,
	struct value *function,
	struct type *valtype,
	struct regcache *regcache,
	gdb_byte *readbuf,
	const gdb_byte *writebuf) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s\n",
		__FUNCTION__);
	#endif

	if (TYPE_LENGTH (valtype) > 4)
		return RETURN_VALUE_STRUCT_CONVENTION;
	else {
		if (readbuf != NULL)
			pu32_extract_return_value (valtype, regcache, readbuf);
		if (writebuf != NULL)
			pu32_store_return_value (valtype, regcache, writebuf);
		return RETURN_VALUE_REGISTER_CONVENTION;
	}
}

// Implement the "unwind_sp" gdbarch method.
static CORE_ADDR pu32_unwind_sp (
	struct gdbarch *gdbarch,
	struct frame_info *next_frame) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s\n",
		__FUNCTION__);
	#endif

	return frame_unwind_register_unsigned (next_frame, PU32_SP_REGNUM);
}

struct pu32_frame_cache {
	CORE_ADDR funcaddr; // Address of the function associated with this frame.
	ULONGEST framesize; // Size of the frame.
	CORE_ADDR framebase; // Base of the frame; it is also the %sp value in the previous frame.
	CORE_ADDR pc; // Program-counter.
	CORE_ADDR sp; // Stack-pointer.
	CORE_ADDR fp; // Frame-pointer.
	CORE_ADDR savedregs[PU32_NUM_REGS]; // Location of the saved registers in the strackframe.
};

static CORE_ADDR pu32_decode_prologue (
	CORE_ADDR start_addr,
	CORE_ADDR end_addr,
	struct pu32_frame_cache *cache) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: start_addr == 0x%x; end_addr == 0x%x\n",
		__FUNCTION__, (unsigned int)start_addr, (unsigned int)end_addr);
	#endif

	// GCC generate prologue as follow:
	// inc8 %sp, -4; st32 %rp, %sp                      # None or once.             # Save return-pointer.
	// inc8 %sp, -4; st32 %fp, %sp                      # None or once.             # Save frame-pointer.
	// cpy %fp, %sp;                                    # None or once.             # Set frame-pointer using stack-pointer.
	// inc8 %sp, -4; st32 %gpr, %sp                     # None, once or more times. # Save registers.
	// inc8 %sp, imm | inc16 %sp, imm | inc32 %sp, imm  # None or once.             # Localvars + outargs (Include pretendargs).

	#define ISINC8SP(inst) ((inst & 0xf0f0) == 0x9000)
	#define ISINC16SP(inst) ((inst & 0xfff0) == 0xa100)
	#define ISINC32SP(inst) ((inst & 0xfff0) == 0xa200)
	#define ISST32SP(inst) ((inst & 0xff0f) == 0xf200)
	#define ISCPYFPSP(inst) (inst == 0xc7e0)

	#define INC8SPIMM(inst) ((((int32_t)(((inst&0x0f00)>>4)|(inst&0xf)))<<24)>>24)
	#define ISST32SPREG(inst) ((inst&0xf0)>>4)

	if (start_addr >= end_addr)
		return end_addr;

	// Used to recall what was
	// the previous instruction parsed.
	enum {
		NOOP,
		INC8SP,
		INC16SP,
		INC32SP,
		ST32SP,
		CPYFPSP,
	} previnst = NOOP;

	CORE_ADDR next_addr = start_addr;

	while (next_addr < end_addr) {

		ULONGEST inst = read_memory_unsigned_integer (next_addr, 2, BFD_ENDIAN_BIG);
		next_addr += 2;

		if (ISINC8SP(inst)) {

			signed imm = INC8SPIMM(inst);

			#if defined(PU32_DEBUG)
			debug_printf (
				"pu32-gdb: %s: inc8.imm == %d; inst == 0x%x\n",
				__FUNCTION__, imm, (unsigned int)inst);
			#endif

			// The immediate must be negative.
			if (imm >= 0)
				goto done;

			if (cache)
				cache->framesize -= imm;

			previnst = INC8SP;

		} else if (ISINC16SP(inst)) {

			signed imm = read_memory_integer (next_addr, 2, BFD_ENDIAN_LITTLE);

			#if defined(PU32_DEBUG)
			debug_printf (
				"pu32-gdb: %s: inc16.imm == %d; inst == 0x%x\n",
				__FUNCTION__, imm, (unsigned int)inst);
			#endif

			// The immediate must be negative.
			if (imm >= 0)
				goto done;

			next_addr += 2;

			if (cache)
				cache->framesize -= imm;

			previnst = INC16SP;

		} else if (ISINC32SP(inst)) {

			signed imm = read_memory_integer (next_addr, 4, BFD_ENDIAN_LITTLE);

			#if defined(PU32_DEBUG)
			debug_printf (
				"pu32-gdb: %s: inc32.imm == %d; inst == 0x%x\n",
				__FUNCTION__, imm, (unsigned int)inst);
			#endif

			// The immediate must be negative.
			if (imm >= 0)
				goto done;

			next_addr += 4;

			if (cache)
				cache->framesize -= imm;

			previnst = INC32SP;

		} else if (ISST32SP(inst)) {

			if (previnst != INC8SP) {
				// ST32SP must be preceeded by INC8SP.
				goto done;
			}

			#if defined(PU32_DEBUG)
			debug_printf (
				"pu32-gdb: %s: saved %%%u\n",
				__FUNCTION__, ISST32SPREG(inst));
			#endif

			if (cache) {
				// Note the offset within the frame
				// at which the register is being saved.
				cache->savedregs[ISST32SPREG(inst)] = cache->framesize;
			}

			previnst = ST32SP;

		} else if (ISCPYFPSP(inst)) {

			if (previnst != ST32SP) {
				// CPYFPSP must be preceeded by ST32SP
				// which is the instruction that would
				// have saved %fp.
				goto done;
			}

			previnst = CPYFPSP;

		} else {
			done:

			// Undo the last increment, since inst is
			// not a recognized prologue instruction.
			next_addr -= 2;

			break;
		}
	}

	if (cache) {
		// The call instruction move the caller's PC in the callee's RP.
		// Copy the location of RP into PC so that a request for PC
		// will be converted into a request for RP.
		cache->savedregs[PU32_PC_REGNUM] = cache->savedregs[PU32_RP_REGNUM];
	}

	#if defined(PU32_DEBUG)
	if (cache) {
		debug_printf (
			"pu32-gdb: %s: cache->framesize == 0x%x\n",
			__FUNCTION__, (unsigned int)cache->framesize);
	}
	#endif

	return next_addr;
}

// Find the end of function prologue.
static CORE_ADDR pu32_skip_prologue (
	struct gdbarch *gdbarch,
	CORE_ADDR pc) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: pc == 0x%x\n",
		__FUNCTION__, (unsigned int)pc);
	#endif

	CORE_ADDR func_addr = 0, func_end = 0;
	const char *func_name;

	// See if we can determine the end of the prologue via the symbol table.
	// If so, then return either PC, or the PC after the prologue, whichever
	// is greater.
	if (find_pc_partial_function (pc, &func_name, &func_addr, &func_end)) {
		CORE_ADDR post_prologue_pc =
			skip_prologue_using_sal (gdbarch, func_addr);
		if (post_prologue_pc)
			return std::max (pc, post_prologue_pc);
		else {
			struct symbol *sym = lookup_symbol (func_name, NULL, VAR_DOMAIN, NULL).symbol;
			// Don't use line number debug info for assembly source files.
			if (sym && sym->language () != language_asm) {
				struct symtab_and_line sal = find_pc_line (func_addr, 0);
				if (sal.end && sal.end < func_end)
					return sal.end;
			}
			return pu32_decode_prologue (
				func_addr, func_end,
				(struct pu32_frame_cache *)0);
		}
	}

	// No function symbol; return the PC.
	return (CORE_ADDR) pc;
}

// Implement the "software_single_step" gdbarch method.
static std::vector<CORE_ADDR> pu32_software_single_step (
	struct regcache *regcache) {

	CORE_ADDR addr = regcache_read_pc (regcache);

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: addr == 0x%x\n",
		__FUNCTION__, (unsigned int)addr);
	#endif

	uint16_t inst = ({

		gdb_byte buf[2];
		uint16_t ret;

		if (target_read_memory (addr, buf, 2)) {
			if (record_debug)
				debug_printf (
					_("pu32-gdb: error reading memory at "
						"addr 0x%s len = %d.\n"),
					paddress (target_gdbarch(), addr), 2);
			ret = -1;
		} else ret = extract_unsigned_integer (buf, 2, BFD_ENDIAN_BIG);

		ret;
	});

	std::vector<CORE_ADDR> next_pcs;

	if (inst == -1)
		return next_pcs;

	uint8_t opcode = inst >> 8;

	if ((opcode & 0xe0) == 0x80 ||
		(opcode & 0xf0) == 0xe0) {
		// inc8/li8/rli8 instruction.
		next_pcs.push_back (addr + 2);

	} else switch (opcode) {
		// 16bits instructions.
		case 0xb8: // add
		case 0xb9: // sub
		case 0xca: // mul
		case 0xcb: // mulh
		case 0xce: // div
		case 0xcf: // mod
		case 0xc8: // mulu
		case 0xc9: // mulhu
		case 0xcc: // divu
		case 0xcd: // modu
		case 0xc3: // and
		case 0xc4: // or
		case 0xc5: // xor
		case 0xc6: // not
		case 0xc7: // cpy
		case 0xc0: // sll
		case 0xc1: // srl
		case 0xc2: // sra
		case 0xd8: // fadd
		case 0xd9: // fsub
		case 0xda: // fmul
		case 0xdb: // fdiv
		case 0xba: // seq
		case 0xbb: // sne
		case 0xbc: // slt
		case 0xbd: // slte
		case 0xbe: // sltu
		case 0xbf: // slteu
		case 0xb0: // sgt
		case 0xb1: // sgte
		case 0xb2: // sgtu
		case 0xb3: // sgteu
		case 0xf4: // ld8
		case 0xf5: // ld16
		case 0xf6: // ld32
		case 0xf0: // st8
		case 0xf1: // st16
		case 0xf2: // st32
		case 0x74: // ld8v
		case 0x75: // ld16v
		case 0x76: // ld32v
		case 0x70: // st8v
		case 0x71: // st16v
		case 0x72: // st32v
		case 0xf8: // ldst8
		case 0xf9: // ldst16
		case 0xfa: // ldst32
		case 0xfc: // cldst8
		case 0xfd: // cldst16
		case 0xfe: // cldst32
		case 0x03: // halt
		case 0x04: // icacherst
		case 0x05: // dcacherst
		case 0x20: // setextinthandleraddr // TODO: Instruction no longer in use ...
		case 0x21: // setpagefaultinthandleraddr // TODO: Instruction no longer in use ...
		case 0x22: // setsysopinthandleraddr // TODO: Instruction no longer in use ...
		case 0x39: // setksl
		case 0x3c: // setasid
		case 0x3d: // setuip
		case 0x3e: // setflags
		case 0x3f: // settimer
		case 0x28: // getsysopcode
		case 0x29: // getuip
		case 0x38: // setksysopfaulthdlr
		case 0x3a: // settlb
		case 0x3b: // clrtlb
		case 0x79: // setkgpr
		case 0x7a: // setugpr
		case 0x7b: // setgpr
		case 0x2a: // getfaultaddr
		case 0x2b: // getfaultreason
		case 0x2c: // getclkcyclecnt
		case 0x2d: // getclkcyclecnth
		case 0x2e: // gettlbsize
		case 0x2f: // geticachesize
		case 0x10: // getcoreid
		case 0x11: // getclkfreq
		case 0x12: // getdcachesize
		case 0x13: // gettlb
		case 0x14: // getcap
		case 0x15: // getver
			next_pcs.push_back (addr + 2);
			break;

		// 32bits instructions.
		case 0xa1: // inc16
		case 0xa9: // li16
		case 0xad: // rli16
			next_pcs.push_back (addr + 4);
			break;

		// 48bits instructions.
		case 0xa2: // inc32
		case 0xaa: // li32
		case 0xae: // rli32
		case 0xac: // drli
			next_pcs.push_back (addr + 6);
			break;

		// Conditional branching.
		case 0xd0: { // jz
			uint32_t tmpu32;
			regcache->raw_read ((inst&0xf0)>>4, (gdb_byte *)&tmpu32);
			if (!tmpu32) {
				regcache->raw_read (inst&0xf, (gdb_byte *)&tmpu32);
				next_pcs.push_back (tmpu32);
			} else
				next_pcs.push_back (addr + 2);
			break;
		}

		case 0xd1: { // jnz
			uint32_t tmpu32;
			regcache->raw_read ((inst&0xf0)>>4, (gdb_byte *)&tmpu32);
			if (tmpu32) {
				regcache->raw_read (inst&0xf, (gdb_byte *)&tmpu32);
				next_pcs.push_back (tmpu32);
			} else
				next_pcs.push_back (addr + 2);
			break;
		}

		case 0xd2: { // jl
			uint32_t tmpu32;
			regcache->raw_read (inst&0xf, (gdb_byte *)&tmpu32);
			tmpu32 = pu32_decode_prologue (
				tmpu32, -1,
				(struct pu32_frame_cache *)0);
			next_pcs.push_back (tmpu32);
			break;
		}
	}

	// sysret, syscall, brk, ksysret instructions
	// are unsupported for now.

	return next_pcs;
}

// Implement the "process_record" gdbarch method.
static int pu32_process_record (
	struct gdbarch *gdbarch,
	struct regcache *regcache,
	CORE_ADDR addr) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: addr == 0x%x\n",
		__FUNCTION__, (unsigned int)addr);
	#endif

	if (record_debug > 1)
		debug_printf (
			"Process record: pu32_process_record "
				"addr = 0x%s\n",
			paddress (target_gdbarch (), addr));

	uint16_t inst = ({

		gdb_byte buf[2];
		uint16_t ret;

		if (target_read_memory (addr, buf, 2)) {
			if (record_debug)
				debug_printf (
					_("pu32-gdb: error reading memory at "
						"addr 0x%s len = %d.\n"),
					paddress (target_gdbarch(), addr), 2);
			ret = -1;
		} else ret = extract_unsigned_integer (buf, 2, BFD_ENDIAN_BIG);

		ret;
	});

	if (inst == -1)
		return -1;

	uint8_t opcode = inst >> 8;

	if ((opcode & 0xe0) == 0x80 ||
		(opcode & 0xf0) == 0xe0) {
		// inc8/li8/rli8 instruction.
		if (record_full_arch_list_add_reg (regcache, (inst&0xf0)>>4))
			return -1;

	} else switch (opcode) {
		case 0xb8: // add
		case 0xb9: // sub
		case 0xca: // mul
		case 0xcb: // mulh
		case 0xce: // div
		case 0xcf: // mod
		case 0xc8: // mulu
		case 0xc9: // mulhu
		case 0xcc: // divu
		case 0xcd: // modu
		case 0xc3: // and
		case 0xc4: // or
		case 0xc5: // xor
		case 0xc6: // not
		case 0xc7: // cpy
		case 0xc0: // sll
		case 0xc1: // srl
		case 0xc2: // sra
		case 0xd8: // fadd
		case 0xd9: // fsub
		case 0xda: // fmul
		case 0xdb: // fdiv
		case 0xa1: // inc16
		case 0xa9: // li16
		case 0xa2: // inc32
		case 0xaa: // li32
		case 0xba: // seq
		case 0xbb: // sne
		case 0xbc: // slt
		case 0xbd: // slte
		case 0xbe: // sltu
		case 0xbf: // slteu
		case 0xb0: // sgt
		case 0xb1: // sgte
		case 0xb2: // sgtu
		case 0xb3: // sgteu
		case 0xd2: // jl
		case 0xad: // rli16
		case 0xae: // rli32
		case 0xac: // drli
		case 0xf4: // ld8
		case 0xf5: // ld16
		case 0xf6: // ld32
		case 0x74: // ld8v
		case 0x75: // ld16v
		case 0x76: // ld32v
		case 0x28: // getsysopcode
		case 0x29: // getuip
		case 0x79: // setkgpr
		//case 0x7a: // setugpr
		//case 0x7b: // setgpr
		case 0x2a: // getfaultaddr
		case 0x2b: // getfaultreason
		case 0x2c: // getclkcyclecnt
		case 0x2d: // getclkcyclecnth
		case 0x2e: // gettlbsize
		case 0x2f: // geticachesize
		case 0x10: // getcoreid
		case 0x11: // getclkfreq
		case 0x12: // getdcachesize
		case 0x13: // gettlb
		case 0x14: // getcap
		case 0x15: // getver
			if (record_full_arch_list_add_reg (regcache, (inst&0xf0)>>4))
				return -1;
			break;

		case 0xf0: // st8
		case 0x70: /* st8v */ {
			uint32_t tmpu32;
			regcache->raw_read (inst&0xf, (gdb_byte *)&tmpu32);
			if (record_full_arch_list_add_mem (tmpu32, 1))
				return -1;
			break;
		}

		case 0xf1: // st16
		case 0x71: /* st16v */ {
			uint32_t tmpu32;
			regcache->raw_read (inst&0xf, (gdb_byte *)&tmpu32);
			if (record_full_arch_list_add_mem (tmpu32, 2))
				return -1;
			break;
		}

		case 0xf2: // st32
		case 0x72: /* st32v */ {
			uint32_t tmpu32;
			regcache->raw_read (inst&0xf, (gdb_byte *)&tmpu32);
			if (record_full_arch_list_add_mem (tmpu32, 4))
				return -1;
			break;
		}

		case 0xf8: // ldst8
		case 0xfc: /* cldst8 */ {
			if (record_full_arch_list_add_reg (regcache, (inst&0xf0)>>4))
				return -1;
			uint32_t tmpu32;
			regcache->raw_read (inst&0xf, (gdb_byte *)&tmpu32);
			if (record_full_arch_list_add_mem (tmpu32, 1))
				return -1;
			break;
		}

		case 0xf9: // ldst16
		case 0xfd: /* cldst16 */ {
			if (record_full_arch_list_add_reg (regcache, (inst&0xf0)>>4))
				return -1;
			uint32_t tmpu32;
			regcache->raw_read (inst&0xf, (gdb_byte *)&tmpu32);
			if (record_full_arch_list_add_mem (tmpu32, 2))
				return -1;
			break;
		}

		case 0xfa: // ldst32
		case 0xfe: /* cldst32 */ {
			if (record_full_arch_list_add_reg (regcache, (inst&0xf0)>>4))
				return -1;
			uint32_t tmpu32;
			regcache->raw_read (inst&0xf, (gdb_byte *)&tmpu32);
			if (record_full_arch_list_add_mem (tmpu32, 4))
				return -1;
			break;
		}

		case 0x20: // setextinthandleraddr // TODO: Instruction no longer in use ...
		case 0x21: // setpagefaultinthandleraddr // TODO: Instruction no longer in use ...
		case 0x22: // setsysopinthandleraddr // TODO: Instruction no longer in use ...
			// TODO: to remove ...
			break;

		#if 0
		case 0xd0: // jz
		case 0xd1: // jnz
		case 0x03: // halt
		case 0x04: // icacherst
		case 0x05: // dcacherst
		case 0x39: // setksl
		case 0x3c: // setasid
		case 0x3d: // setuip
		case 0x3e: // setflags
		case 0x3f: // settimer
		case 0x38: // setksysopfaulthdlr
		case 0x3a: // settlb
		case 0x3b: // clrtlb
			// Do nothing.
			break;
		#endif
	}

	if (record_full_arch_list_add_reg (regcache, PU32_PC_REGNUM))
		return -1;
	if (record_full_arch_list_add_end ())
		return -1;
	return 0;
}

// Populate a pu32_frame_cache object for this_frame.
static struct pu32_frame_cache *pu32_get_frame_cache (
	struct frame_info *this_frame,
	void **this_cache) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: *this_cache == 0x%x; "
		"this_cache->funcaddr == 0x%x; "
		"this_cache->framebase == 0x%x\n",
		__FUNCTION__, *this_cache,
		(*this_cache ? (*(struct pu32_frame_cache **)this_cache)->funcaddr : 0),
		(*this_cache ? (*(struct pu32_frame_cache **)this_cache)->framebase : 0));
	#endif

	if (*this_cache)
		return (struct pu32_frame_cache *) *this_cache;

	struct pu32_frame_cache *cache =
		FRAME_OBSTACK_ZALLOC (struct pu32_frame_cache);

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: cache == 0x%x\n",
		__FUNCTION__, cache);
	#endif

	cache->funcaddr = 0;
	cache->framesize = 0;
	cache->framebase = 0;
	cache->pc = REG_UNAVAIL;
	cache->sp = REG_UNAVAIL;
	cache->fp = REG_UNAVAIL;
	for (int i = 0; i < PU32_NUM_REGS; ++i)
		cache->savedregs[i] = REG_UNAVAIL;

	CORE_ADDR pc = get_frame_register_unsigned (this_frame, PU32_PC_REGNUM);
	CORE_ADDR sp = get_frame_register_unsigned (this_frame, PU32_SP_REGNUM);
	CORE_ADDR fp = get_frame_register_unsigned (this_frame, PU32_FP_REGNUM);

	cache->funcaddr = get_frame_func (this_frame);
	if (cache->funcaddr) {
		#if defined(PU32_DEBUG)
		CORE_ADDR addr =
		#endif
		pu32_decode_prologue (
			cache->funcaddr,
			get_frame_pc (this_frame),
			cache);

		#if defined(PU32_DEBUG)
		debug_printf (
			"pu32-gdb: %s: pu32_decode_prologue() == 0x%x\n",
			__FUNCTION__, (unsigned int)addr);
		#endif

		cache->framebase = sp + cache->framesize;

		for (int i = (PU32_SP_REGNUM+1); i < PU32_NUM_REGS; ++i)
			if (cache->savedregs[i] != REG_UNAVAIL)
				cache->savedregs[i] = cache->framebase - cache->savedregs[i];
	}

	cache->pc = pc;
	cache->sp = sp;
	cache->fp = fp;

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: cache == 0x%x; cache->funcaddr == 0x%x; pc == 0x%x; "
		"sp == 0x%x; fp == 0x%x; cache->framesize == 0x%x; cache->framebase == 0x%x\n",
		__FUNCTION__, cache, cache->funcaddr, (unsigned int)pc,
		(unsigned int)sp, (unsigned int)fp, (unsigned int)cache->framesize,
		(unsigned int)cache->framebase);
	#endif

	return (struct pu32_frame_cache *)(*this_cache = cache);
}

// Implement the "unwind_pc" gdbarch method.
static CORE_ADDR pu32_unwind_pc (
	struct gdbarch *gdbarch,
	struct frame_info *next_frame) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s\n",
		__FUNCTION__);
	#endif

	return frame_unwind_register_unsigned (next_frame, PU32_PC_REGNUM);
}

static const struct regcache_map_entry pu32_gregmap[] = {
	{ PU32_NUM_REGS, 0, sizeof(uint32_t) },
	{ 0 }
};

static const struct regset pu32_gregset = {
	pu32_gregmap,
	regcache_supply_regset,
	regcache_collect_regset,
};

static void pu32_iterate_over_regset_sections (
	struct gdbarch *gdbarch,
	iterate_over_regset_sections_cb *cb,
	void *cb_data,
	const struct regcache *regcache) {
	cb (".reg", PU32_NUM_REGS * sizeof(uint32_t), PU32_NUM_REGS * sizeof(uint32_t), &pu32_gregset, NULL, cb_data);
}

// Given a GDB frame, determine the address of the calling function's frame.
// This will be used to create a new GDB frame struct.
static void pu32_frame_this_id (
	struct frame_info *this_frame,
	void **this_prologue_cache,
	struct frame_id *this_id) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s\n",
		__FUNCTION__);
	#endif

	struct pu32_frame_cache *cache =
		pu32_get_frame_cache (this_frame, this_prologue_cache);

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: cache == 0x%x; cache->funcaddr == 0x%x; cache->pc == 0x%x\n",
		__FUNCTION__, cache, (unsigned int)cache->funcaddr, (unsigned int)cache->pc);
	#endif

	*this_id = frame_id_build (cache->sp, cache->pc);
}

// Get the value of register regnum in the caller function.
static struct value *pu32_frame_prev_register (
	struct frame_info *this_frame,
	 void **this_prologue_cache,
	 int regnum) {

	struct pu32_frame_cache *cache =
		pu32_get_frame_cache (
			this_frame, this_prologue_cache);

	gdb_assert (regnum >= 0 && regnum < PU32_NUM_REGS);

	auto decrement_by_sizeof_uint16_t = [&](
		struct value *regval)
	/*struct value *decrement_by_sizeof_uint16_t (
		struct value *regval)*/ {

		/* ### Disabled for now; was used to set the %pc
		   ### at the address of the instruction jl instead
		   ### of the return address.
		struct gdbarch *gdbarch = target_gdbarch ();
		enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

		store_unsigned_integer (
			value_contents_writeable (regval),
			register_size (gdbarch, regnum),
			byte_order,
			extract_unsigned_integer (
				value_contents_writeable (regval),
				register_size (gdbarch, regnum),
				byte_order) - sizeof(uint16_t));*/

		return regval;
	};

	struct value *regval;

	if (regnum == PU32_SP_REGNUM)
		if (cache->framebase)
			regval = frame_unwind_got_constant (
				this_frame, regnum, cache->framebase);
		else // Returning callee's SP when caller's SP has not yet been cached.
			regval = frame_unwind_got_register (
				this_frame, regnum, regnum);
	else if (regnum == PU32_FP_REGNUM)
		if (cache->savedregs[regnum] != REG_UNAVAIL)
			regval = frame_unwind_got_memory (
				this_frame, regnum, cache->savedregs[regnum]);
		else // Returning callee's FP when caller's FP was not saved.
			regval = frame_unwind_got_register (
				this_frame, regnum, regnum);
	else if (regnum == PU32_PC_REGNUM)
		if (cache->savedregs[regnum] != REG_UNAVAIL)
			regval = decrement_by_sizeof_uint16_t (
				frame_unwind_got_memory (
					this_frame, regnum, cache->savedregs[regnum]));
		else if (cache->framebase)
			// ### This assume that %rp has the previous-frame pc; which may
			// ### not be true if the compiler temporarily allocated %rp
			// ### for a use other than for returning from the current-frame.
			regval = decrement_by_sizeof_uint16_t (
				frame_unwind_got_register (
					this_frame, regnum, PU32_RP_REGNUM));
		else // Returning callee's PC when caller's PC was not saved.
			regval = frame_unwind_got_register (
				this_frame, regnum, regnum);
	else if (cache->savedregs[regnum] != REG_UNAVAIL)
		regval = frame_unwind_got_memory (
			this_frame, regnum, cache->savedregs[regnum]);
	else // Returning callee's regnum when caller's regnum was not saved.
		regval = frame_unwind_got_register (
			this_frame, regnum, regnum);

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: regnum == %d; regval == 0x%x; cache == 0x%x; cache->funcaddr == 0x%x; cache->framebase == 0x%x; "
		"cache->savedregs[regnum] == 0x%x\n",
		__FUNCTION__, regnum,
		extract_unsigned_integer (
			value_contents_writeable (regval),
			register_size (target_gdbarch (), regnum),
			gdbarch_byte_order (target_gdbarch ())),
		cache, cache->funcaddr, cache->framebase, cache->savedregs[regnum]);
	#endif

	return regval;
}

static const struct frame_unwind pu32_frame_unwind = {
	"pu32 prologue",
	NORMAL_FRAME,
	default_frame_unwind_stop_reason,
	pu32_frame_this_id,
	pu32_frame_prev_register,
	NULL,
	default_frame_sniffer
};

// Return the frame-pointer value for this_frame.
static CORE_ADDR pu32_frame_base_address (
	struct frame_info *this_frame,
	void **this_cache) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s: *this_cache == 0x%x; this_cache->funcaddr == 0x%x\n",
		__FUNCTION__, *this_cache,
		(*this_cache ? (*(struct pu32_frame_cache **)this_cache)->funcaddr : 0));
	#endif

	return pu32_get_frame_cache (this_frame, this_cache)->fp;
}

static const struct frame_base pu32_frame_base = {
	&pu32_frame_unwind,
	pu32_frame_base_address,
	pu32_frame_base_address,
	pu32_frame_base_address
};

static struct frame_id pu32_dummy_id (
	struct gdbarch *gdbarch,
	struct frame_info *this_frame) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s\n",
		__FUNCTION__);
	#endif

	return frame_id_build (
		get_frame_register_unsigned (this_frame, PU32_SP_REGNUM),
		get_frame_pc (this_frame));
}

static void pu32_gdbarch_config (struct gdbarch *gdbarch) {

	set_gdbarch_wchar_bit (gdbarch, 32);
	set_gdbarch_wchar_signed (gdbarch, 0);

	set_gdbarch_unwind_sp (gdbarch, pu32_unwind_sp);

	set_gdbarch_num_regs (gdbarch, PU32_NUM_REGS);
	set_gdbarch_sp_regnum (gdbarch, PU32_SP_REGNUM);
	set_gdbarch_pc_regnum (gdbarch, PU32_PC_REGNUM);
	set_gdbarch_register_name (gdbarch, pu32_register_name);
	set_gdbarch_register_type (gdbarch, pu32_register_type);

	set_gdbarch_return_value (gdbarch, pu32_return_value);

	set_gdbarch_skip_prologue (gdbarch, pu32_skip_prologue);
	set_gdbarch_skip_entrypoint (gdbarch, pu32_skip_prologue);
	set_gdbarch_inner_than (gdbarch, core_addr_lessthan);
	set_gdbarch_breakpoint_kind_from_pc (gdbarch, pu32_breakpoint::kind_from_pc);
	set_gdbarch_sw_breakpoint_from_kind (gdbarch, pu32_breakpoint::bp_from_kind);
	set_gdbarch_frame_align (gdbarch, pu32_frame_align);

	frame_base_set_default (gdbarch, &pu32_frame_base);

	set_gdbarch_dummy_id (gdbarch, pu32_dummy_id);
	// TODO: set_gdbarch_push_dummy_call (gdbarch, pu32_push_dummy_call);

	set_gdbarch_unwind_pc (gdbarch, pu32_unwind_pc);

	set_gdbarch_iterate_over_regset_sections (gdbarch, pu32_iterate_over_regset_sections);

	// Hook in the default unwinders.
	frame_unwind_append_unwinder (gdbarch, &pu32_frame_unwind);

	// Single stepping.
	set_gdbarch_software_single_step (gdbarch, pu32_software_single_step);

	// Support simple overlay manager.
	set_gdbarch_overlay_update (gdbarch, simple_overlay_update);

	// Support reverse debugging.
	set_gdbarch_process_record (gdbarch, pu32_process_record);
}

// Allocate and initialize the pu32 gdbarch object.
static struct gdbarch *pu32_gdbarch_init (
	struct gdbarch_info info,
	struct gdbarch_list *arches) {

	#if defined(PU32_DEBUG)
	debug_printf (
		"pu32-gdb: %s\n",
		__FUNCTION__);
	#endif

	struct gdbarch *gdbarch;
	struct gdbarch_tdep *tdep;

	// If there is already a candidate, use it.
	arches = gdbarch_list_lookup_by_info (arches, &info);
	if (arches != NULL)
		return arches->gdbarch;

	// Allocate space for the new architecture.
	tdep = XCNEW (struct gdbarch_tdep);
	gdbarch = gdbarch_alloc (&info, tdep);

	// Hook in ABI-specific overrides, if they have been registered.
	gdbarch_init_osabi (info, gdbarch);

	pu32_gdbarch_config (gdbarch);

	return gdbarch;
}

static void pu32_linux_init_osabi (struct gdbarch_info info, struct gdbarch *gdbarch) {

	linux_init_abi (info, gdbarch, 0);

	set_gdbarch_fetch_tls_load_module_address (gdbarch, svr4_fetch_objfile_link_map);
	set_gdbarch_skip_trampoline_code (gdbarch, find_solib_trampoline_target);

	set_solib_svr4_fetch_link_map_offsets (gdbarch, svr4_ilp32_fetch_link_map_offsets);

	pu32_gdbarch_config (gdbarch);
}

void _initialize_pu32_tdep ();
// Register this machine's init routine.
// The regex within Makefile.in used to generate init.c
// require an _initialize_ function name to be at
// the begining of the line, otherwise it will not match.
void
_initialize_pu32_tdep ()
{
	gdbarch_register_osabi (bfd_arch_pu32, 0, GDB_OSABI_LINUX, pu32_linux_init_osabi);

	// Reserve file-descriptor numbers used by target sim.
	#define PU32_RESERVED_FDS 8 /* must match sim/pu32/sim-main.h */
	int devnullfd = open("/dev/null", O_RDWR);
	if (devnullfd == -1) {
		debug_printf (
			"pu32-gdb: %s: open(\"/dev/null\") failed\n",
			__FUNCTION__);
		exit(1);
	}
	for (unsigned i = 3; i < PU32_RESERVED_FDS; ++i) {
		if (dup2(devnullfd, i) == -1) {
			debug_printf (
				"pu32-gdb: %s: dup2(devnullfd, %u) failed\n",
				__FUNCTION__, i);
			exit(1);
		}
	}

	register_gdbarch_init (bfd_arch_pu32, pu32_gdbarch_init);
}
