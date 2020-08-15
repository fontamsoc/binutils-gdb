// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#include "sysdep.h"
#include <stdio.h>
#include "disassemble.h"

static const char * regnames[16] = {
	"%sp", "%1", "%2", "%3", "%4", "%5", "%6", "%7",
	"%8", "%9", "%tp", "%11", "%12", "%sr", "%fp", "%rp"
};

int print_insn_pu32 (bfd_vma addr, struct disassemble_info * info) {

	void * stream = info->stream;
	unsigned char buffer[4];
	static intptr_t imm;
	fprintf_ftype fpr = info->fprintf_func;

	int status;

	if ((status = info->read_memory_func (addr, buffer, 2, info)))
		goto fail;

	info->bytes_per_line = 6; // Largest instruction size (ie: li32, inc32).

	int length = 2;

	switch (buffer[0]) {

		case 0xb8:
			// Specification from the
			// instruction set manual:
			// add %gpr1, %gpr2 |23|000|rrrr|rrrr|

			fpr (stream, "add %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xb9:
			// Specification from the
			// instruction set manual:
			// sub %gpr1, %gpr2 |23|001|rrrr|rrrr|

			fpr (stream, "sub %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xca:
			// Specification from the
			// instruction set manual:
			// mul %gpr1, %gpr2 |25|010|rrrr|rrrr|

			fpr (stream, "mul %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xcb:
			// Specification from the
			// instruction set manual:
			// mulh %gpr1, %gpr2 |25|011|rrrr|rrrr|

			fpr (stream, "mulh %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xce:
			// Specification from the
			// instruction set manual:
			// div %gpr1, %gpr2 |25|110|rrrr|rrrr|

			fpr (stream, "div %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xcf:
			// Specification from the
			// instruction set manual:
			// mod %gpr1, %gpr2 |25|111|rrrr|rrrr|

			fpr (stream, "mod %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xc8:
			// Specification from the
			// instruction set manual:
			// mulu %gpr1, %gpr2 |25|000|rrrr|rrrr|

			fpr (stream, "mulu %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xc9:
			// Specification from the
			// instruction set manual:
			// mulhu %gpr1, %gpr2 |25|001|rrrr|rrrr|

			fpr (stream, "mulhu %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xcc:
			// Specification from the
			// instruction set manual:
			// divu %gpr1, %gpr2 |25|100|rrrr|rrrr|

			fpr (stream, "divu %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xcd:
			// Specification from the
			// instruction set manual:
			// modu %gpr1, %gpr2 |25|101|rrrr|rrrr|

			fpr (stream, "modu %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xd8:
			// Specification from the
			// instruction set manual:
			// fadd %gpr1, %gpr2 |22|100|rrrr|rrrr|

			fpr (stream, "fadd %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xd9:
			// Specification from the
			// instruction set manual:
			// fsub %gpr1, %gpr2 |22|101|rrrr|rrrr|

			fpr (stream, "fsub %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xda:
			// Specification from the
			// instruction set manual:
			// fmul %gpr1, %gpr2 |22|110|rrrr|rrrr|

			fpr (stream, "fmul %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xdb:
			// Specification from the
			// instruction set manual:
			// fdiv %gpr1, %gpr2 |22|111|rrrr|rrrr|

			fpr (stream, "fdiv %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xc3:
			// Specification from the
			// instruction set manual:
			// and %gpr1, %gpr2 |24|011|rrrr|rrrr|

			fpr (stream, "and %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xc4:
			// Specification from the
			// instruction set manual:
			// or %gpr1, %gpr2 |24|100|rrrr|rrrr|

			fpr (stream, "or %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xc5:
			// Specification from the
			// instruction set manual:
			// xor %gpr1, %gpr2 |24|101|rrrr|rrrr|

			fpr (stream, "xor %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xc6:
			// Specification from the
			// instruction set manual:
			// not %gpr1, %gpr2 |24|110|rrrr|rrrr|

			fpr (stream, "not %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xc7: {
			// Specification from the
			// instruction set manual:
			// cpy %gpr1, %gpr2 |24|111|rrrr|rrrr|

			unsigned gpr1 = (buffer[1]>>4)&0xf;
			unsigned gpr2 = buffer[1]&0xf;

			if (!gpr1 && !gpr2)
				fpr (stream, "nop");
			else
				fpr (stream, "cpy %s, %s",
					regnames[gpr1],
					regnames[gpr2]);

			break;
		}

		case 0xc0:
			// Specification from the
			// instruction set manual:
			// sll %gpr1, %gpr2 |24|000|rrrr|rrrr|

			fpr (stream, "sll %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xc1:
			// Specification from the
			// instruction set manual:
			// srl %gpr1, %gpr2 |24|001|rrrr|rrrr|

			fpr (stream, "srl %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xc2:
			// Specification from the
			// instruction set manual:
			// sra %gpr1, %gpr2 |24|010|rrrr|rrrr|

			fpr (stream, "sra %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xba:
			// Specification from the
			// instruction set manual:
			// seq %gpr1, %gpr2 |23|010|rrrr|rrrr|

			fpr (stream, "seq %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xbb:
			// Specification from the
			// instruction set manual:
			// sne %gpr1, %gpr2 |23|011|rrrr|rrrr|

			fpr (stream, "sne %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xbc:
			// Specification from the
			// instruction set manual:
			// slt %gpr1, %gpr2 |23|100|rrrr|rrrr|

			fpr (stream, "slt %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xbd:
			// Specification from the
			// instruction set manual:
			// slte %gpr1, %gpr2 |23|101|rrrr|rrrr|

			fpr (stream, "slte %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xbe:
			// Specification from the
			// instruction set manual:
			// sltu %gpr1, %gpr2 |23|110|rrrr|rrrr|

			fpr (stream, "sltu %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xbf:
			// Specification from the
			// instruction set manual:
			// slteu %gpr1, %gpr2 |23|111|rrrr|rrrr|

			fpr (stream, "slteu %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xb0:
			// Specification from the
			// instruction set manual:
			// sgt %gpr1, %gpr2 |19|000|rrrr|rrrr|

			fpr (stream, "sgt %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xb1:
			// Specification from the
			// instruction set manual:
			// sgte %gpr1, %gpr2 |19|001|rrrr|rrrr|

			fpr (stream, "sgte %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xb2:
			// Specification from the
			// instruction set manual:
			// sgtu %gpr1, %gpr2 |19|010|rrrr|rrrr|

			fpr (stream, "sgtu %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xb3:
			// Specification from the
			// instruction set manual:
			// sgteu %gpr1, %gpr2 |19|011|rrrr|rrrr|

			fpr (stream, "sgteu %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0xd0: {
			// Specification from the
			// instruction set manual:
			// jz %gpr1 %gpr2 |26|000|rrrr|rrrr|

			unsigned gpr1 = (buffer[1]>>4)&0xf;
			unsigned gpr2 = buffer[1]&0xf;

			if (gpr1 == gpr2)
				fpr (stream, "j %s",
					regnames[gpr1]);
			else
				fpr (stream, "jz %s, %s",
					regnames[gpr1],
					regnames[gpr2]);

			// By convention, the use of %sr is the hint used
			// that an address to branch-to was computed in imm.
			if (gpr2 == 13 /* %sr */) {
				// Below is used by --visualize-jumps.
				info->insn_info_valid = 1;
				info->insn_type = dis_condbranch;
				info->target = addr + imm;
			}

			break;
		}

		case 0xd1: {
			// Specification from the
			// instruction set manual:
			// jnz %gpr1 %gpr2 |26|001|rrrr|rrrr|

			unsigned gpr1 = (buffer[1]>>4)&0xf;
			unsigned gpr2 = buffer[1]&0xf;

			if (gpr1 == gpr2)
				fpr (stream, "j %s",
					regnames[gpr1]);
			else
				fpr (stream, "jnz %s, %s",
					regnames[gpr1],
					regnames[gpr2]);

			// By convention, the use of %sr is the hint used
			// that an address to branch-to was computed in imm.
			if (gpr2 == 13 /* %sr */) {
				// Below is used by --visualize-jumps.
				info->insn_info_valid = 1;
				info->insn_type = dis_condbranch;
				info->target = addr + imm;
			}

			break;
		}

		case 0xd2: {
			// Specification from the
			// instruction set manual:
			// jl %gpr1 %gpr2 |26|010|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "jl %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xad:
			// Specification from the
			// instruction set manual:
			// rli16 %gpr, imm |21|101|rrrr|0000|
			//                 |iiiiiiiiiiiiiiii|

			fpr (stream, "rli16 %s, ",
				regnames[(buffer[1]>>4)&0xf]);

			if ((status = info->read_memory_func (addr + 2, buffer, 2, info)))
				goto fail;

			imm = buffer[0] + (buffer[1]<<8);

			// Sign extend the immediate value.
			imm <<= ((sizeof(imm)*8)-16);
			imm >>= ((sizeof(imm)*8)-16);

			fpr (stream, "%d # 0x%x", (int16_t)imm, (int16_t)imm);

			length += 2;

			fpr (stream, " # ");
			info->print_address_func (addr + length + imm, info);

			break;

		case 0xae:
			// Specification from the
			// instruction set manual:
			// rli32 %gpr, imm |21|110|rrrr|0000|
			//                 |iiiiiiiiiiiiiiii| 16 msb.
			//                 |iiiiiiiiiiiiiiii| 16 lsb.

			fpr (stream, "rli32 %s, ",
				regnames[(buffer[1]>>4)&0xf]);

			if ((status = info->read_memory_func (addr + 2, buffer, 4, info)))
				goto fail;

			imm = buffer[0] + (buffer[1]<<8) + (buffer[2]<<16) + (buffer[3]<<24);

			// Sign extend the immediate value.
			imm <<= ((sizeof(imm)*8)-32);
			imm >>= ((sizeof(imm)*8)-32);

			fpr (stream, "%d # 0x%x", (int32_t)imm, (int32_t)imm);

			length += 4;

			fpr (stream, " # ");
			info->print_address_func (addr + length + imm, info);

			break;

		case 0xac:
			// Specification from the
			// instruction set manual:
			// drli %gpr, imm |21|000|rrrr|0000|
			//                  |iiiiiiiiiiiiiiii| 16 msb.
			//                  |iiiiiiiiiiiiiiii| 16 lsb.

			fpr (stream, "drli %s, ",
				regnames[(buffer[1]>>4)&0xf]);

			if ((status = info->read_memory_func (addr + 2, buffer, 4, info)))
				goto fail;

			imm = buffer[0] + (buffer[1]<<8) + (buffer[2]<<16) + (buffer[3]<<24);

			// Sign extend the immediate value.
			imm <<= ((sizeof(imm)*8)-32);
			imm >>= ((sizeof(imm)*8)-32);

			fpr (stream, "%d # 0x%x", (int32_t)imm, (int32_t)imm);

			length += 4;

			fpr (stream, " # ");
			info->print_address_func (addr + length + imm, info);

			break;

		case 0xa1: {
			// Specification from the
			// instruction set manual:
			// inc16 %gpr1, %gpr2, imm |20|001|rrrr|rrrr|
			//                         |iiiiiiiiiiiiiiii|

			unsigned gpr1 = (buffer[1]>>4)&0xf;
			unsigned gpr2 = buffer[1]&0xf;

			if (gpr1 == gpr2)
				fpr (stream, "inc16 %s, ",
					regnames[gpr1]);
			else
				fpr (stream, "inc16 %s, %s, ",
					regnames[gpr1],
					regnames[gpr2]);

			if ((status = info->read_memory_func (addr + 2, buffer, 2, info)))
				goto fail;

			imm = buffer[0] + (buffer[1]<<8);

			// Sign extend the immediate value.
			imm <<= ((sizeof(imm)*8)-16);
			imm >>= ((sizeof(imm)*8)-16);

			fpr (stream, "%d # 0x%x", (int16_t)imm, (int16_t)imm);

			length += 2;

			break; }

		case 0xa2: {
			// Specification from the
			// instruction set manual:
			// inc32 %gpr1, %gpr2, imm |20|010|rrrr|rrrr|
			//                         |iiiiiiiiiiiiiiii| 16 msb.
			//                         |iiiiiiiiiiiiiiii| 16 lsb.

			unsigned gpr1 = (buffer[1]>>4)&0xf;
			unsigned gpr2 = buffer[1]&0xf;

			if (gpr1 == gpr2)
				fpr (stream, "inc32 %s, ",
					regnames[gpr1]);
			else
				fpr (stream, "inc32 %s, %s, ",
					regnames[gpr1],
					regnames[gpr2]);

			if ((status = info->read_memory_func (addr + 2, buffer, 4, info)))
				goto fail;

			imm = buffer[0] + (buffer[1]<<8) + (buffer[2]<<16) + (buffer[3]<<24);

			// Sign extend the immediate value.
			imm <<= ((sizeof(imm)*8)-32);
			imm >>= ((sizeof(imm)*8)-32);

			fpr (stream, "%d # 0x%x", (int32_t)imm, (int32_t)imm);

			length += 4;

			break; }

		case 0xa9:
			// Specification from the
			// instruction set manual:
			// li16 %gpr, imm |21|001|rrrr|0000|
			//                |iiiiiiiiiiiiiiii|

			fpr (stream, "li16 %s, ",
				regnames[(buffer[1]>>4)&0xf]);

			if ((status = info->read_memory_func (addr + 2, buffer, 2, info)))
				goto fail;

			imm = buffer[0] + (buffer[1]<<8);

			// Sign extend the immediate value.
			imm <<= ((sizeof(imm)*8)-16);
			imm >>= ((sizeof(imm)*8)-16);

			fpr (stream, "0x%x # %d", (int16_t)imm, (int16_t)imm);

			length += 2;

			break;

		case 0xaa:
			// Specification from the
			// instruction set manual:
			// li32 %gpr, imm |21|010|rrrr|0000|
			//                |iiiiiiiiiiiiiiii| 16 msb.
			//                |iiiiiiiiiiiiiiii| 16 lsb.

			fpr (stream, "li32 %s, ",
				regnames[(buffer[1]>>4)&0xf]);

			if ((status = info->read_memory_func (addr + 2, buffer, 4, info)))
				goto fail;

			imm = buffer[0] + (buffer[1]<<8) + (buffer[2]<<16) + (buffer[3]<<24);

			// Sign extend the immediate value.
			imm <<= ((sizeof(imm)*8)-32);
			imm >>= ((sizeof(imm)*8)-32);

			fpr (stream, "0x%x # %d", (int32_t)imm, (int32_t)imm);

			length += 4;

			break;

		case 0xf4: {
			// Specification from the
			// instruction set manual:
			// ld8 %gpr1, %gpr2 |30|100|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "ld8 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xf5: {
			// Specification from the
			// instruction set manual:
			// ld16 %gpr1, %gpr2 |30|101|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "ld16 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xf6: {
			// Specification from the
			// instruction set manual:
			// ld32 %gpr1, %gpr2 |30|110|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "ld32 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xf0: {
			// Specification from the
			// instruction set manual:
			// st8 %gpr1, %gpr2 |30|000|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "st8 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xf1: {
			// Specification from the
			// instruction set manual:
			// st16 %gpr1, %gpr2 |30|001|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "st16 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xf2: {
			// Specification from the
			// instruction set manual:
			// st32 %gpr1, %gpr2 |30|010|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "st32 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0x74: {
			// Specification from the
			// instruction set manual:
			// ld8v %gpr1, %gpr2 |14|100|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "ld8v %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0x75: {
			// Specification from the
			// instruction set manual:
			// ld16v %gpr1, %gpr2 |14|101|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "ld16v %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0x76: {
			// Specification from the
			// instruction set manual:
			// ld32v %gpr1, %gpr2 |14|110|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "ld32v %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0x70: {
			// Specification from the
			// instruction set manual:
			// st8v %gpr1, %gpr2 |14|000|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "st8v %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0x71: {
			// Specification from the
			// instruction set manual:
			// st16v %gpr1, %gpr2 |14|001|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "st16v %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0x72: {
			// Specification from the
			// instruction set manual:
			// st32v %gpr1, %gpr2 |14|010|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "st32v %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xf8: {
			// Specification from the
			// instruction set manual:
			// ldst8 %gpr1, %gpr2 |31|000|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "ldst8 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xf9: {
			// Specification from the
			// instruction set manual:
			// ldst16 %gpr1, %gpr2 |31|001|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "ldst16 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xfa: {
			// Specification from the
			// instruction set manual:
			// ldst32 %gpr1, %gpr2 |31|010|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "ldst32 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xfc: {
			// Specification from the
			// instruction set manual:
			// cldst8 %gpr1, %gpr2 |31|100|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "cldst8 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xfd: {
			// Specification from the
			// instruction set manual:
			// cldst16 %gpr1, %gpr2 |31|101|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "cldst16 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0xfe: {
			// Specification from the
			// instruction set manual:
			// cldst32 %gpr1, %gpr2 |31|110|rrrr|rrrr|

			unsigned gpr2 = buffer[1]&0xf;

			fpr (stream, "cldst32 %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[gpr2]);

			break;
		}

		case 0x00:
			// Specification from the
			// instruction set manual:
			// sysret |0|000|0000|0000|

			fpr (stream, "sysret");

			break;

		case 0x01:
			// Specification from the
			// instruction set manual:
			// syscall |0|001|0000|0000|

			fpr (stream, "syscall");

			break;

		case 0x02:
			// Specification from the
			// instruction set manual:
			// brk |0|010|0000|0000|

			fpr (stream, "brk");

			break;

		case 0x03:
			// Specification from the
			// instruction set manual:
			// halt |0|011|0000|0000|

			fpr (stream, "halt");

			break;

		case 0x04:
			// Specification from the
			// instruction set manual:
			// icacherst |0|100|0000|0000|

			fpr (stream, "icacherst");

			break;

		case 0x05:
			// Specification from the
			// instruction set manual:
			// dcacherst |0|101|0000|0000|

			fpr (stream, "dcacherst");

			break;

		case 0x07:
			// Specification from the
			// instruction set manual:
			// ksysret |0|111|0000|0000|

			fpr (stream, "ksysret");

			break;

		case 0x39:
			// Specification from the
			// instruction set manual:
			// setksl %gpr |7|001|rrrr|0000|

			fpr (stream, "setksl %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x3c:
			// Specification from the
			// instruction set manual:
			// setasid %gpr |7|100|rrrr|0000|

			fpr (stream, "setasid %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x3d:
			// Specification from the
			// instruction set manual:
			// setuip %gpr |7|101|rrrr|0000|

			fpr (stream, "setuip %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x3e:
			// Specification from the
			// instruction set manual:
			// setflags %gpr |7|110|rrrr|0000|

			fpr (stream, "setflags %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x3f:
			// Specification from the
			// instruction set manual:
			// settimer %gpr |7|111|rrrr|0000|

			fpr (stream, "settimer %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x38:
			// Specification from the
			// instruction set manual:
			// setksysopfaulthdlr %gpr |7|000|rrrr|0000|

			fpr (stream, "setksysopfaulthdlr %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x3a:
			// Specification from the
			// instruction set manual:
			// settlb %gpr1, %gpr2 |7|010|rrrr|rrrr|

			fpr (stream, "settlb %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0x3b:
			// Specification from the
			// instruction set manual:
			// clrtlb %gpr1, %gpr2 |7|011|rrrr|rrrr|

			fpr (stream, "clrtlb %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0x79:
			// Specification from the
			// instruction set manual:
			// setkgpr %gpr1 %gpr2 |15|001|rrrr|rrrr|

			fpr (stream, "setkgpr %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0x7a:
			// Specification from the
			// instruction set manual:
			// setugpr %gpr1 %gpr2 |15|010|rrrr|rrrr|

			fpr (stream, "setugpr %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0x7b:
			// Specification from the
			// instruction set manual:
			// setgpr %gpr1 %gpr2 |15|011|rrrr|rrrr|

			fpr (stream, "setgpr %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0x28:
			// Specification from the
			// instruction set manual:
			// getsysopcode %gpr |5|000|rrrr|0000|

			fpr (stream, "getsysopcode %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x29:
			// Specification from the
			// instruction set manual:
			// getuip %gpr |5|001|rrrr|0000|

			fpr (stream, "getuip %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x2a:
			// Specification from the
			// instruction set manual:
			// getfaultaddr %gpr |5|010|rrrr|0000|

			fpr (stream, "getfaultaddr %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x2b:
			// Specification from the
			// instruction set manual:
			// getfaultreason %gpr |5|011|rrrr|0000|

			fpr (stream, "getfaultreason %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x2c:
			// Specification from the
			// instruction set manual:
			// getclkcyclecnt %gpr 5|100|rrrr|0000|

			fpr (stream, "getclkcyclecnt %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x2d:
			// Specification from the
			// instruction set manual:
			// getclkcyclecnth %gpr |5|101|rrrr|0000|

			fpr (stream, "getclkcyclecnth %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x2e:
			// Specification from the
			// instruction set manual:
			// gettlbsize %gpr |5|110|rrrr|0000|

			fpr (stream, "gettlbsize %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x2f:
			// Specification from the
			// instruction set manual:
			// geticachesize %gpr |5|111|rrrr|0000|

			fpr (stream, "geticachesize %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x10:
			// Specification from the
			// instruction set manual:
			// getcoreid %gpr |2|000|rrrr|0000|

			fpr (stream, "getcoreid %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x11:
			// Specification from the
			// instruction set manual:
			// getclkfreq %gpr |2|001|rrrr|0000|

			fpr (stream, "getclkfreq %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x12:
			// Specification from the
			// instruction set manual:
			// getdcachesize %gpr |2|010|rrrr|0000|

			fpr (stream, "getdcachesize %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x13:
			// Specification from the
			// instruction set manual:
			// gettlb %gpr1, %gpr2 |2|011|rrrr|rrrr|

			fpr (stream, "gettlb %s, %s",
				regnames[(buffer[1]>>4)&0xf],
				regnames[buffer[1]&0xf]);

			break;

		case 0x14:
			// Specification from the
			// instruction set manual:
			// getcap %gpr |2|100|rrrr|0000|

			fpr (stream, "getcap %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		case 0x15:
			// Specification from the
			// instruction set manual:
			// getver %gpr |2|101|rrrr|0000|

			fpr (stream, "getver %s",
				regnames[(buffer[1]>>4)&0xf]);

			break;

		default: {

			unsigned x = (buffer[0] >> 4);

			if ((x == 0x8 && buffer[1]) || x == 0x9 || x == 0xe) {

				if (buffer[1] || (buffer[0]&0xf) || x != 0x9) {
					// Specification from the
					// instruction set manual:
					// li8 %gpr, imm |1000|iiii|rrrr|iiii|

					// Specification from the
					// instruction set manual:
					// inc8 %gpr, imm |1001|iiii|rrrr|iiii|

					// Specification from the
					// instruction set manual:
					// rli8 %gpr, imm |1110|iiii|rrrr|iiii|

					imm = ((buffer[0]&0xf)<<4) + (buffer[1]&0xf);

					// Sign extend the immediate value.
					imm <<= ((sizeof(imm)*8)-8);
					imm >>= ((sizeof(imm)*8)-8);

					if (x == 0x8)
						fpr (stream, "li8 %s, 0x%x # %d",
							regnames[(buffer[1]>>4)&0xf],
							(int8_t)imm, (int8_t)imm);
					else if (x == 0x9)
						fpr (stream, "inc8 %s, %d # 0x%x",
							regnames[(buffer[1]>>4)&0xf],
							(int8_t)imm, (int8_t)imm);
					else {
						fpr (stream, "rli8 %s, %d # 0x%x",
							regnames[(buffer[1]>>4)&0xf],
							(int8_t)imm, (int8_t)imm);

						fpr (stream, " # ");
						info->print_address_func (addr + length + imm, info);
					}

				} else {
					// Instruction "inc8 %0, 0" preempt current context.
					fpr (stream, "preemptctx");
				}

			} else fpr (stream, "???");

			break;
		}
	}

	return length;

	fail:
	info->memory_error_func (status, addr, info);
	return -1;
}
