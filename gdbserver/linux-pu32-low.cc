// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#include "server.h"
#include "linux-low.h"
#include "tdesc.h"

#include <linux/elf.h>

#define TRAP_S_1_OPCODE 0x0002
#define TRAP_S_1_SIZE   2

class pu32_target : public linux_process_target {

public:

	const regs_info *get_regs_info () override;

	const gdb_byte *sw_breakpoint_from_kind (int kind, int *size) override;

protected:

	void low_arch_setup () override;

	bool low_cannot_fetch_register (int regno) override;

	bool low_cannot_store_register (int regno) override;

	bool low_supports_breakpoints () override;

	CORE_ADDR low_get_pc (regcache *regcache) override;

	void low_set_pc (regcache *regcache, CORE_ADDR newpc) override;

	bool low_breakpoint_at (CORE_ADDR where) override;
};

static pu32_target the_pu32_target;

bool pu32_target::low_supports_breakpoints() {
	return true;
}

CORE_ADDR pu32_target::low_get_pc (regcache *regcache) {
	return linux_get_pc_32bit (regcache);
}

void pu32_target::low_set_pc (regcache *regcache, CORE_ADDR pc) {
	linux_set_pc_32bit (regcache, pc);
}

void pu32_target::low_arch_setup () {

	target_desc_up tdesc = allocate_target_description ();

	#ifndef IN_PROCESS_AGENT
	set_tdesc_architecture (tdesc.get(), "pu32");
	set_tdesc_osabi (tdesc.get(), "GNU/Linux");
	#endif

	struct tdesc_feature *feature =
		tdesc_create_feature (tdesc.get(), "org.gnu.gdb.pu32.core");
	tdesc_create_reg (feature, "r0",  0,  1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r1",  1,  1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r2",  2,  1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r3",  3,  1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r4",  4,  1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r5",  5,  1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r6",  6,  1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r7",  7,  1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r8",  8,  1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r9",  9,  1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r10", 10, 1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r11", 11, 1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r12", 12, 1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r13", 13, 1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r14", 14, 1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "r15", 15, 1, NULL, 32, "uint32");
	tdesc_create_reg (feature, "pc",  16, 1, NULL, 32, "uint32");

	static const char *expedite_regs[] = { "r0", "r14", "r15", "pc", NULL };
	init_target_desc (tdesc.get(), expedite_regs);

	current_process()->tdesc = tdesc.release();
}

// Must agree with the number registers defined in "struct pt_regs"
// at arch/pu32/include/uapi/asm/ptrace.h in Linux.
#define PU32_NUM_REGS 17

bool pu32_target::low_cannot_fetch_register (int regno) {
	return (regno >= PU32_NUM_REGS);
}

bool pu32_target::low_cannot_store_register (int regno) {
	return (regno >= PU32_NUM_REGS);
}

static gdb_byte pu32_linux_trap_s[TRAP_S_1_SIZE] =
	{ (TRAP_S_1_OPCODE && 0xFF), (TRAP_S_1_OPCODE >> 8) };

const gdb_byte *pu32_target::sw_breakpoint_from_kind (int kind, int *size) {
	*size = TRAP_S_1_SIZE;
	return pu32_linux_trap_s;
}

bool pu32_target::low_breakpoint_at (CORE_ADDR where) {
	uint16_t insn;
	this->read_memory (where, (gdb_byte *)&insn, TRAP_S_1_SIZE);
	return (insn == TRAP_S_1_OPCODE);
}

// Fetch the thread-local storage pointer for libthread_db.
// Note that this function is not called from GDB, but is called from libthread_db.
ps_err_e ps_get_thread_area (struct ps_prochandle *ph, lwpid_t lwpid, int idx, void **base) {
	if (ptrace (PTRACE_GET_THREAD_AREA, lwpid, NULL, base) != 0)
		return PS_ERR;
	// IDX is the bias from the thread pointer to the beginning of the
	// thread descriptor. It has to be subtracted due to implementation
	// quirks in libthread_db.
	*base = (void *) ((char *) *base - idx);
	return PS_OK;
}

// Populate a ptrace NT_PRSTATUS regset from a regcache.
static void pu32_fill_gregset (struct regcache *regcache, void *buf) {
	for (unsigned i = 0; i < PU32_NUM_REGS; ++i) {
		uint32_t regval;
		collect_register (regcache, i, &regval);
		((uint32_t *)buf)[i] = regval;
	}
}

// Populate a regcache from a ptrace NT_PRSTATUS regset.
static void pu32_store_gregset (struct regcache *regcache, const void *buf) {
	for (unsigned i = 0; i < PU32_NUM_REGS; ++i)
		supply_register (regcache, i, &((uint32_t *)buf)[i]);
}

static struct regset_info pu32_regsets[] = {
	{
		PTRACE_GETREGSET, PTRACE_SETREGSET, NT_PRSTATUS,
		(PU32_NUM_REGS*sizeof(uint32_t)), GENERAL_REGS,
		pu32_fill_gregset, pu32_store_gregset
	},
	NULL_REGSET
};

static struct regsets_info pu32_regsets_info = {
	pu32_regsets, 0, NULL,
};

static struct regs_info pu32_regs_info = {
	NULL, NULL, &pu32_regsets_info
};

const regs_info *pu32_target::get_regs_info () {
	return &pu32_regs_info;
}

linux_process_target *the_linux_target = &the_pu32_target;

// It is required for _initialize_ function name to be at
// the begining of the line, otherwise it fails to be used.
void
initialize_low_arch (void)
{
	initialize_regsets_info (&pu32_regsets_info);
}
