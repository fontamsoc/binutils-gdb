// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#include "as.h"
#include "safe-ctype.h"
#include "elf/pu32.h"

const char *md_shortopts = "";

static int relax = 0;

struct option md_longopts[] = {
	{"mrelax", no_argument, &relax, 1},
};

size_t md_longopts_size = sizeof (md_longopts);

int md_parse_option (int c ATTRIBUTE_UNUSED, const char *arg ATTRIBUTE_UNUSED) {
	return 1;
}

void md_show_usage (FILE *fp) {
	fprintf (fp, _("PU32 assembler options:\n"));
	fprintf (fp, _("  -mrelax                 enable relaxation\n"));
}

const char comment_chars[]        = "#";
const char line_separator_chars[] = ";";
const char line_comment_chars[]   = "#";

static htab_t opcode_htab;

const pseudo_typeS md_pseudo_table[] = {
	{0, 0, 0}
};

const char FLT_CHARS[] = "rRsSfFdDxXpP";
const char EXP_CHARS[] = "eE";

// Turn a string in input_line_pointer
// into a floating point constant
// of type type, and store
// the appropriate bytes in *LITP.
// The number of LITTLENUMS emitted
// is stored in *SIZEP . An error
// message is returned, or NULL on OK.
const char *md_atof (int type, char *litP, int *sizeP) {

	int prec;
	LITTLENUM_TYPE words[4];
	char *t;
	int i;

	switch (type) {

		case 'f':
			prec = 2;
			break;

		case 'd':
			prec = 4;
			break;

		default:
			*sizeP = 0;
			return _("bad call to md_atof");
	}

	t = atof_ieee (input_line_pointer, type, words);

	if (t) input_line_pointer = t;

	*sizeP = prec * 2;

	for (i = prec - 1; i >= 0; i--) {

		md_number_to_chars (litP, (valueT) words[i], 2);

		litP += 2;
	}

	return NULL;
}

// Put number into target byte order.
void md_number_to_chars (char * ptr, valueT use, int nbytes) {
	number_to_chars_littleendian (ptr, use, nbytes);
}

void md_operand (expressionS *op __attribute__((unused))) {}

// This function is called once, at assembler startup time.
// It sets up the hash table with all the opcodes in it.
void md_begin (void) {

	opcode_htab = str_htab_create();

	/* Insert names into hash table.  */
	str_hash_insert (opcode_htab, "add", (void*)0xb8, 0);
	str_hash_insert (opcode_htab, "sub", (void*)0xb9, 0);
	str_hash_insert (opcode_htab, "mul", (void*)0xca, 0);
	str_hash_insert (opcode_htab, "mulh", (void*)0xcb, 0);
	str_hash_insert (opcode_htab, "div", (void*)0xce, 0);
	str_hash_insert (opcode_htab, "mod", (void*)0xcf, 0);
	str_hash_insert (opcode_htab, "mulu", (void*)0xc8, 0);
	str_hash_insert (opcode_htab, "mulhu", (void*)0xc9, 0);
	str_hash_insert (opcode_htab, "divu", (void*)0xcc, 0);
	str_hash_insert (opcode_htab, "modu", (void*)0xcd, 0);
	str_hash_insert (opcode_htab, "fadd", (void*)0xd8, 0);
	str_hash_insert (opcode_htab, "fsub", (void*)0xd9, 0);
	str_hash_insert (opcode_htab, "fmul", (void*)0xda, 0);
	str_hash_insert (opcode_htab, "fdiv", (void*)0xdb, 0);
	str_hash_insert (opcode_htab, "and", (void*)0xc3, 0);
	str_hash_insert (opcode_htab, "or", (void*)0xc4, 0);
	str_hash_insert (opcode_htab, "xor", (void*)0xc5, 0);
	str_hash_insert (opcode_htab, "not", (void*)0xc6, 0);
	str_hash_insert (opcode_htab, "cpy", (void*)0xc7, 0);
	str_hash_insert (opcode_htab, "sll", (void*)0xc0, 0);
	str_hash_insert (opcode_htab, "srl", (void*)0xc1, 0);
	str_hash_insert (opcode_htab, "sra", (void*)0xc2, 0);
	str_hash_insert (opcode_htab, "seq", (void*)0xba, 0);
	str_hash_insert (opcode_htab, "sne", (void*)0xbb, 0);
	str_hash_insert (opcode_htab, "slt", (void*)0xbc, 0);
	str_hash_insert (opcode_htab, "slte", (void*)0xbd, 0);
	str_hash_insert (opcode_htab, "sltu", (void*)0xbe, 0);
	str_hash_insert (opcode_htab, "slteu", (void*)0xbf, 0);
	str_hash_insert (opcode_htab, "sgt", (void*)0xb0, 0);
	str_hash_insert (opcode_htab, "sgte", (void*)0xb1, 0);
	str_hash_insert (opcode_htab, "sgtu", (void*)0xb2, 0);
	str_hash_insert (opcode_htab, "sgteu", (void*)0xb3, 0);
	str_hash_insert (opcode_htab, "jz", (void*)0xd0, 0);
	str_hash_insert (opcode_htab, "jnz", (void*)0xd1, 0);
	str_hash_insert (opcode_htab, "jl", (void*)0xd2, 0);
	str_hash_insert (opcode_htab, "inc8", (void*)0x90, 0);
	str_hash_insert (opcode_htab, "inc16", (void*)0xa1, 0);
	str_hash_insert (opcode_htab, "inc32", (void*)0xa2, 0);
	str_hash_insert (opcode_htab, "inc", (void*)0xffa2, 0);
	str_hash_insert (opcode_htab, "li8", (void*)0x80, 0);
	str_hash_insert (opcode_htab, "li16", (void*)0xa9, 0);
	str_hash_insert (opcode_htab, "li32", (void*)0xaa, 0);
	str_hash_insert (opcode_htab, "li", (void*)0xffaa, 0);
	str_hash_insert (opcode_htab, "rli8", (void*)0xe0, 0);
	str_hash_insert (opcode_htab, "rli16", (void*)0xad, 0);
	str_hash_insert (opcode_htab, "rli32", (void*)0xae, 0);
	str_hash_insert (opcode_htab, "drli", (void*)0xac, 0);
	str_hash_insert (opcode_htab, "rli", (void*)0xffae, 0);
	str_hash_insert (opcode_htab, "ld8", (void*)0xf4, 0);
	str_hash_insert (opcode_htab, "ld16", (void*)0xf5, 0);
	str_hash_insert (opcode_htab, "ld32", (void*)0xf6, 0);
	str_hash_insert (opcode_htab, "ld", (void*)0xfff6, 0);
	str_hash_insert (opcode_htab, "st8", (void*)0xf0, 0);
	str_hash_insert (opcode_htab, "st16", (void*)0xf1, 0);
	str_hash_insert (opcode_htab, "st32", (void*)0xf2, 0);
	str_hash_insert (opcode_htab, "st", (void*)0xfff2, 0);
	str_hash_insert (opcode_htab, "ld8v", (void*)0x74, 0);
	str_hash_insert (opcode_htab, "ld16v", (void*)0x75, 0);
	str_hash_insert (opcode_htab, "ld32v", (void*)0x76, 0);
	str_hash_insert (opcode_htab, "vld", (void*)0xff76, 0);
	str_hash_insert (opcode_htab, "st8v", (void*)0x70, 0);
	str_hash_insert (opcode_htab, "st16v", (void*)0x71, 0);
	str_hash_insert (opcode_htab, "st32v", (void*)0x72, 0);
	str_hash_insert (opcode_htab, "vst", (void*)0xff72, 0);
	str_hash_insert (opcode_htab, "ldst8", (void*)0xf8, 0);
	str_hash_insert (opcode_htab, "ldst16", (void*)0xf9, 0);
	str_hash_insert (opcode_htab, "ldst32", (void*)0xfa, 0);
	str_hash_insert (opcode_htab, "ldst", (void*)0xfffa, 0);
	str_hash_insert (opcode_htab, "cldst8", (void*)0xfc, 0);
	str_hash_insert (opcode_htab, "cldst16", (void*)0xfd, 0);
	str_hash_insert (opcode_htab, "cldst32", (void*)0xfe, 0);
	str_hash_insert (opcode_htab, "cldst", (void*)0xfffe, 0);
	str_hash_insert (opcode_htab, "j", (void*)0xffd1, 0);
	str_hash_insert (opcode_htab, "nop", (void*)0xffc7, 0);
	str_hash_insert (opcode_htab, "preemptctx", (void*)0xff90, 0);
	str_hash_insert (opcode_htab, "sysret", (void*)0xff00, 0); // Using 0x00 would not work.
	str_hash_insert (opcode_htab, "syscall", (void*)0x01, 0);
	str_hash_insert (opcode_htab, "brk", (void*)0x02, 0);
	str_hash_insert (opcode_htab, "halt", (void*)0x03, 0);
	str_hash_insert (opcode_htab, "icacherst", (void*)0x04, 0);
	str_hash_insert (opcode_htab, "dcacherst", (void*)0x05, 0);
	str_hash_insert (opcode_htab, "ksysret", (void*)0x07, 0);
	str_hash_insert (opcode_htab, "setksl", (void*)0x39, 0);
	str_hash_insert (opcode_htab, "setasid", (void*)0x3c, 0);
	str_hash_insert (opcode_htab, "setuip", (void*)0x3d, 0);
	str_hash_insert (opcode_htab, "setflags", (void*)0x3e, 0);
	str_hash_insert (opcode_htab, "settimer", (void*)0x3f, 0);
	str_hash_insert (opcode_htab, "setksysopfaulthdlr", (void*)0x38, 0);
	str_hash_insert (opcode_htab, "settlb", (void*)0x3a, 0);
	str_hash_insert (opcode_htab, "clrtlb", (void*)0x3b, 0);
	str_hash_insert (opcode_htab, "setkgpr", (void*)0x79, 0);
	str_hash_insert (opcode_htab, "setugpr", (void*)0x7a, 0);
	str_hash_insert (opcode_htab, "setgpr", (void*)0x7b, 0);
	str_hash_insert (opcode_htab, "getsysopcode", (void*)0x28, 0);
	str_hash_insert (opcode_htab, "getuip", (void*)0x29, 0);
	str_hash_insert (opcode_htab, "getfaultaddr", (void*)0x2a, 0);
	str_hash_insert (opcode_htab, "getfaultreason", (void*)0x2b, 0);
	str_hash_insert (opcode_htab, "getclkcyclecnt", (void*)0x2c, 0);
	str_hash_insert (opcode_htab, "getclkcyclecnth", (void*)0x2d, 0);
	str_hash_insert (opcode_htab, "gettlbsize", (void*)0x2e, 0);
	str_hash_insert (opcode_htab, "geticachesize", (void*)0x2f, 0);
	str_hash_insert (opcode_htab, "getcoreid", (void*)0x10, 0);
	str_hash_insert (opcode_htab, "getclkfreq", (void*)0x11, 0);
	str_hash_insert (opcode_htab, "getdcachesize", (void*)0x12, 0);
	str_hash_insert (opcode_htab, "gettlb", (void*)0x13, 0);
	str_hash_insert (opcode_htab, "getcap", (void*)0x14, 0);
	str_hash_insert (opcode_htab, "getver", (void*)0x15, 0);

	bfd_set_arch_mach (stdoutput, TARGET_ARCH, 0);
}

#define SIZEOF_OPCODE sizeof(uint16_t)

#define PU32_FR_SUBTYPE_NEGATE	1
#define PU32_FR_SUBTYPE_PCREL	(1<<1)

// This is the guts of the machine-dependent assembler.
// STR points to a machine-dependent instruction.
// This function emit the frags/bytes it assembles.
void md_assemble (char *str) {
	// Tag to return to when an error is thrown.
	__label__ error;

	// Parse an expression and then
	// restore the input line pointer.
	char *parse_exp_save_ilp (char *s, expressionS *op) {

		char *save = input_line_pointer;

		input_line_pointer = s;

		expression (op);

		s = input_line_pointer;

		input_line_pointer = save;

		return s;
	}

	unsigned parse_register_operand (char **ptr) {

		char *s = *ptr;

		if (*s != '%') {

			as_bad (_("expecting register"));

			goto error;
		}

		s++;

		char *saved_s = s;

		unsigned reg = 0;

		if (s[0] == 's' && s[1] == 'p') {

			reg = 0;

			s += 2;

		} else if (s[0] == 't' && s[1] == 'p') {

			reg = 10;

			s += 2;

		} else if (s[0] == 's' && s[1] == 'r') {

			reg = 13;

			s += 2;

		} else if (s[0] == 'f' && s[1] == 'p') {

			reg = 14;

			s += 2;

		} else if (s[0] == 'r' && s[1] == 'p') {

			reg = 15;

			s += 2;

		} else while (*s >= '0' && *s <= '9') {

			reg = ((reg*10) + (*s - '0'));

			s++;
		}

		if (s == saved_s) {

			as_bad (_("illegal register"));

			goto error;
		}

		if (reg > 15) {

			as_bad (_("illegal register number"));

			goto error;

		} else *ptr = s;

		return reg;
	}

	// Drop leading whitespace.
	while (ISSPACE(*str))
		str++;

	char *opstart;
	char *opend;

	unsigned nlen = 0;

	// Find the op code end.
	opstart = str;
	for (opend = str;
		*opend && !is_end_of_line[(unsigned)*opend] && !ISSPACE(*opend);
		opend++)
		nlen++;

	if (nlen == 0) {
		as_bad (_("can't find opcode "));
		return;
	}

	char pend = *opend;
	*opend = 0;

	uintptr_t opcode = (uintptr_t) str_hash_find (opcode_htab, opstart);

	*opend = pend;

	if (!opcode) {
		as_bad (_("unknown opcode %s"), opstart);
		return;
	}

	char *p = 0;

	switch (opcode) {
		case 0xffa2: // inc
		case 0xffaa: // li
		case 0xffae: // rli
			break;
		default:
			// Encode the opcode.
			(p = frag_more (SIZEOF_OPCODE))[0] = opcode;
			break;
	}

	uintptr_t reg1, reg2;

	expressionS arg;

	relax_substateT fr_subtype;

	char *where;

	switch (opcode) {

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
		case 0xd8: // fadd
		case 0xd9: // fsub
		case 0xda: // fmul
		case 0xdb: // fdiv
		case 0xc3: // and
		case 0xc4: // or
		case 0xc5: // xor
		case 0xc6: // not
		case 0xc7: // cpy
		case 0xc0: // sll
		case 0xc1: // srl
		case 0xc2: // sra
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
		case 0xd0: // jz
		case 0xd1: // jnz
		case 0xd2: // jl
		case 0xf4: // ld8
		case 0xf5: // ld16
		case 0xf6: // ld32
		case 0xfff6: // ld
		case 0xf0: // st8
		case 0xf1: // st16
		case 0xf2: // st32
		case 0xfff2: // st
		case 0x74: // ld8v
		case 0x75: // ld16v
		case 0x76: // ld32v
		case 0xff76: // vld
		case 0x70: // st8v
		case 0x71: // st16v
		case 0x72: // st32v
		case 0xff72: // vst
		case 0xf8: // ldst8
		case 0xf9: // ldst16
		case 0xfa: // ldst32
		case 0xfffa: // ldst
		case 0xfc: // cldst8
		case 0xfd: // cldst16
		case 0xfe: // cldst32
		case 0xfffe: // cldst
		case 0x3a: // settlb
		case 0x3b: // clrtlb
		case 0x79: // setkgpr
		case 0x7a: // setugpr
		case 0x7b: // setgpr
		case 0x13: // gettlb

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			reg2  = parse_register_operand (&opend);

			p[1] = ((reg1 << 4) + reg2);

			break;

		case 0x39: // setksl
		case 0x3c: // setasid
		case 0x3d: // setuip
		case 0x3e: // setflags
		case 0x3f: // settimer
		case 0x38: // setksysopfaulthdlr
		case 0x28: // getsysopcode
		case 0x29: // getuip
		case 0x2a: // getfaultaddr
		case 0x2b: // getfaultreason
		case 0x2c: // getclkcyclecnt
		case 0x2d: // getclkcyclecnth
		case 0x2e: // gettlbsize
		case 0x2f: // geticachesize
		case 0x10: // getcoreid
		case 0x11: // getclkfreq
		case 0x12: // getdcachesize
		case 0x14: // getcap
		case 0x15: // getver

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			p[1] = (reg1 << 4);

			break;

		case 0xffd1: // j

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			p[1] = ((reg1 << 4) + reg1);

			break;

		case 0xffc7: // nop
		case 0xff90: // preemptctx
		case 0xff00: // sysret
		case 0x01: // syscall
		case 0x02: // brk
		case 0x03: // halt
		case 0x04: // icacherst
		case 0x05: // dcacherst
		case 0x07: // ksysret

			p[1] = 0;

			break;

		case 0x90: // inc8
		case 0x80: // li8

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			p[1] = (reg1 << 4);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			// This signalling on whether the immediate
			// should be negated is used because gnu-gas
			// throw the following error when trying to
			// li/inc the negation of an absolute label
			// address using li %8, -.Label or inc %8, -.Label:
			// Error: can't resolve `0' {.text section} - `.Label' {.text section}
			if (*opend == '-') {

				// Signal that the immediate should be negated.
				fr_subtype = PU32_FR_SUBTYPE_NEGATE;

				opend++;

				while (ISSPACE (*opend))
					opend++;

			} else
				fr_subtype = 0; // Signal that the immediate should not be negated.

			opend = parse_exp_save_ilp (opend, &arg);

			fix_new_exp (frag_now,
				(p - frag_now->fr_literal),
				SIZEOF_OPCODE,
				&arg,
				FALSE,
				BFD_RELOC_8)->fx_frag->fr_subtype =
					fr_subtype;

			// Start a new fragS to preserve
			// the value of frag_now->fr_subtype.
			frag_wane (frag_now);
			frag_new (0);

			break;

		case 0xa1: // inc16

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			if (*opend == '%') {

				reg2  = parse_register_operand (&opend);

				while (ISSPACE (*opend))
					opend++;

				if (*opend != ',') {
					as_bad (_("expecting comma"));
					return;
				}

				opend++;

				while (ISSPACE (*opend))
					opend++;

			} else
				reg2 = reg1;

			p[1] = ((reg1 << 4) + reg2);

			// This signalling on whether the immediate
			// should be negated is used because gnu-gas
			// throw the following error when trying to
			// li/inc the negation of an absolute label
			// address using li %8, -.Label or inc %8, -.Label:
			// Error: can't resolve `0' {.text section} - `.Label' {.text section}
			if (*opend == '-') {

				// Signal that the immediate should be negated.
				fr_subtype = PU32_FR_SUBTYPE_NEGATE;

				opend++;

				while (ISSPACE (*opend))
					opend++;

			} else
				fr_subtype = 0; // Signal that the immediate should not be negated.

			opend = parse_exp_save_ilp (opend, &arg);

			where = frag_more (sizeof(uint16_t));
			fix_new_exp (frag_now,
				(where - frag_now->fr_literal),
				sizeof(uint16_t),
				&arg,
				FALSE,
				BFD_RELOC_16)->fx_frag->fr_subtype =
					fr_subtype;

			// Start a new fragS to preserve
			// the value of frag_now->fr_subtype.
			frag_wane (frag_now);
			frag_new (0);

			break;

		case 0xa9: // li16

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			p[1] = (reg1 << 4);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			// This signalling on whether the immediate
			// should be negated is used because gnu-gas
			// throw the following error when trying to
			// li/inc the negation of an absolute label
			// address using li %8, -.Label or inc %8, -.Label:
			// Error: can't resolve `0' {.text section} - `.Label' {.text section}
			if (*opend == '-') {

				// Signal that the immediate should be negated.
				fr_subtype = PU32_FR_SUBTYPE_NEGATE;

				opend++;

				while (ISSPACE (*opend))
					opend++;

			} else
				fr_subtype = 0; // Signal that the immediate should not be negated.

			opend = parse_exp_save_ilp (opend, &arg);

			where = frag_more (sizeof(uint16_t));
			fix_new_exp (frag_now,
				(where - frag_now->fr_literal),
				sizeof(uint16_t),
				&arg,
				FALSE,
				BFD_RELOC_16)->fx_frag->fr_subtype =
					fr_subtype;

			// Start a new fragS to preserve
			// the value of frag_now->fr_subtype.
			frag_wane (frag_now);
			frag_new (0);

			break;

		case 0xa2: // inc32

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			if (*opend == '%') {

				reg2  = parse_register_operand (&opend);

				while (ISSPACE (*opend))
					opend++;

				if (*opend != ',') {
					as_bad (_("expecting comma"));
					return;
				}

				opend++;

				while (ISSPACE (*opend))
					opend++;

			} else
				reg2 = reg1;

			p[1] = ((reg1 << 4) + reg2);

			// This signalling on whether the immediate
			// should be negated is used because gnu-gas
			// throw the following error when trying to
			// li/inc the negation of an absolute label
			// address using li %8, -.Label or inc %8, -.Label:
			// Error: can't resolve `0' {.text section} - `.Label' {.text section}
			if (*opend == '-') {

				// Signal that the immediate should be negated.
				fr_subtype = PU32_FR_SUBTYPE_NEGATE;

				opend++;

				while (ISSPACE (*opend))
					opend++;

			} else
				fr_subtype = 0; // Signal that the immediate should not be negated.

			opend = parse_exp_save_ilp (opend, &arg);

			where = frag_more (sizeof(uint32_t));
			fix_new_exp (frag_now,
				(where - frag_now->fr_literal),
				sizeof(uint32_t),
				&arg,
				FALSE,
				BFD_RELOC_32)->fx_frag->fr_subtype =
					fr_subtype;

			// Start a new fragS to preserve
			// the value of frag_now->fr_subtype.
			frag_wane (frag_now);
			frag_new (0);

			break;

		case 0xaa: // li32

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			p[1] = (reg1 << 4);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			// This signalling on whether the immediate
			// should be negated is used because gnu-gas
			// throw the following error when trying to
			// li/inc the negation of an absolute label
			// address using li %8, -.Label or inc %8, -.Label:
			// Error: can't resolve `0' {.text section} - `.Label' {.text section}
			if (*opend == '-') {

				// Signal that the immediate should be negated.
				fr_subtype = PU32_FR_SUBTYPE_NEGATE;

				opend++;

				while (ISSPACE (*opend))
					opend++;

			} else
				fr_subtype = 0; // Signal that the immediate should not be negated.

			opend = parse_exp_save_ilp (opend, &arg);

			where = frag_more (sizeof(uint32_t));
			fix_new_exp (frag_now,
				(where - frag_now->fr_literal),
				sizeof(uint32_t),
				&arg,
				FALSE,
				BFD_RELOC_32)->fx_frag->fr_subtype =
					fr_subtype;

			// Start a new fragS to preserve
			// the value of frag_now->fr_subtype.
			frag_wane (frag_now);
			frag_new (0);

			break;

		case 0xffa2: // inc

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			if (*opend == '%') {

				reg2  = parse_register_operand (&opend);

				while (ISSPACE (*opend))
					opend++;

				if (*opend != ',') {
					as_bad (_("expecting comma"));
					return;
				}

				opend++;

				while (ISSPACE (*opend))
					opend++;

			} else
				reg2 = reg1;

			// This signalling on whether the immediate
			// should be negated is used because gnu-gas
			// throw the following error when trying to
			// li/inc the negation of an absolute label
			// address using li %8, -.Label or inc %8, -.Label:
			// Error: can't resolve `0' {.text section} - `.Label' {.text section}
			if (*opend == '-') {

				// Signal that the immediate should be negated.
				fr_subtype = PU32_FR_SUBTYPE_NEGATE;

				opend++;

				while (ISSPACE (*opend))
					opend++;

			} else
				fr_subtype = 0; // Signal that the immediate should not be negated.

			opend = parse_exp_save_ilp (opend, &arg);

			if (relax) {
				// frag_var() starts a new fragS preserving
				// the value of frag_now->fr_subtype.
				p = frag_var (rs_machine_dependent,
					SIZEOF_OPCODE + sizeof(uint32_t) /* Max needed */,
					0 /* fr_var */,
					fr_subtype,
					arg.X_add_symbol,
					arg.X_add_number,
					0);
			} else {
				p = frag_more (SIZEOF_OPCODE);
				where = frag_more (sizeof(uint32_t));
				fix_new_exp (frag_now,
					(where - frag_now->fr_literal),
					sizeof(uint32_t),
					&arg,
					FALSE,
					BFD_RELOC_32)->fx_frag->fr_subtype =
						fr_subtype;
				// Start a new fragS to preserve
				// the value of frag_now->fr_subtype.
				frag_wane (frag_now);
				frag_new (0);
			}

			p[0] = opcode;
			p[1] = ((reg1 << 4) + reg2);

			break;

		case 0xffaa: // li

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			// This signalling on whether the immediate
			// should be negated is used because gnu-gas
			// throw the following error when trying to
			// li/inc the negation of an absolute label
			// address using li %8, -.Label or inc %8, -.Label:
			// Error: can't resolve `0' {.text section} - `.Label' {.text section}
			if (*opend == '-') {

				// Signal that the immediate should be negated.
				fr_subtype = PU32_FR_SUBTYPE_NEGATE;

				opend++;

				while (ISSPACE (*opend))
					opend++;

			} else
				fr_subtype = 0; // Signal that the immediate should not be negated.

			opend = parse_exp_save_ilp (opend, &arg);

			if (relax) {
				// frag_var() starts a new fragS preserving
				// the value of frag_now->fr_subtype.
				p = frag_var (rs_machine_dependent,
					SIZEOF_OPCODE + sizeof(uint32_t) /* Max needed */,
					0 /* fr_var */,
					fr_subtype,
					arg.X_add_symbol,
					arg.X_add_number,
					0);
			} else {
				p = frag_more (SIZEOF_OPCODE);
				where = frag_more (sizeof(uint32_t));
				fix_new_exp (frag_now,
					(where - frag_now->fr_literal),
					sizeof(uint32_t),
					&arg,
					FALSE,
					BFD_RELOC_32)->fx_frag->fr_subtype =
						fr_subtype;
				// Start a new fragS to preserve
				// the value of frag_now->fr_subtype.
				frag_wane (frag_now);
				frag_new (0);
			}

			p[0] = opcode;
			p[1] = (reg1 << 4);

			break;

		case 0xe0: // rli8

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			p[1] = (reg1 << 4);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			opend = parse_exp_save_ilp (opend, &arg);

			fix_new_exp (frag_now,
				(p - frag_now->fr_literal),
				SIZEOF_OPCODE,
				&arg,
				TRUE,
				BFD_RELOC_8_PCREL)->fx_frag->fr_subtype =
					PU32_FR_SUBTYPE_PCREL;

			// Start a new fragS to preserve
			// the value of frag_now->fr_subtype.
			frag_wane (frag_now);
			frag_new (0);

			break;

		case 0xad: // rli16

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			p[1] = (reg1 << 4);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			opend = parse_exp_save_ilp (opend, &arg);

			where = frag_more (sizeof(uint16_t));
			fix_new_exp (frag_now,
				(where - frag_now->fr_literal),
				sizeof(uint16_t),
				&arg,
				TRUE,
				BFD_RELOC_16_PCREL)->fx_frag->fr_subtype =
					PU32_FR_SUBTYPE_PCREL;

			// Start a new fragS to preserve
			// the value of frag_now->fr_subtype.
			frag_wane (frag_now);
			frag_new (0);

			break;

		case 0xae: // rli32
		case 0xac: // drli

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			p[1] = (reg1 << 4);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				as_bad (_("expecting comma"));
				return;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			opend = parse_exp_save_ilp (opend, &arg);

			where = frag_more (sizeof(uint32_t));
			fix_new_exp (frag_now,
				(where - frag_now->fr_literal),
				sizeof(uint32_t),
				&arg,
				TRUE,
				BFD_RELOC_32_PCREL)->fx_frag->fr_subtype =
					PU32_FR_SUBTYPE_PCREL;

			// Start a new fragS to preserve
			// the value of frag_now->fr_subtype.
			frag_wane (frag_now);
			frag_new (0);

			break;

		case 0xffae: // rli

			while (ISSPACE (*opend))
				opend++;

			reg1 = parse_register_operand (&opend);

			while (ISSPACE (*opend))
				opend++;

			if (*opend != ',') {
				p = frag_more (SIZEOF_OPCODE);
				p[0] = 0xe0 /* rli8 */;
				p[1] = (reg1 << 4);
				break;
			}

			opend++;

			while (ISSPACE (*opend))
				opend++;

			opend = parse_exp_save_ilp (opend, &arg);

			if (relax) {
				// frag_var() starts a new fragS preserving
				// the value of frag_now->fr_subtype.
				p = frag_var (rs_machine_dependent,
					SIZEOF_OPCODE + sizeof(uint32_t) /* Max needed */,
					0 /* fr_var */,
					PU32_FR_SUBTYPE_PCREL,
					arg.X_add_symbol,
					arg.X_add_number,
					0);
			} else {
				p = frag_more (SIZEOF_OPCODE);
				where = frag_more (sizeof(uint32_t));
				fix_new_exp (frag_now,
					(where - frag_now->fr_literal),
					sizeof(uint32_t),
					&arg,
					TRUE,
					BFD_RELOC_32_PCREL)->fx_frag->fr_subtype =
						PU32_FR_SUBTYPE_PCREL;
				// Start a new fragS to preserve
				// the value of frag_now->fr_subtype.
				frag_wane (frag_now);
				frag_new (0);
			}

			p[0] = opcode;
			p[1] = (reg1 << 4);

			break;

		default:

			abort();
	}

	while (ISSPACE (*opend))
		opend++;

	error:;
}

// This function is called just before doing relaxation.
// It returns an initial estimate of a frag before relaxing.
int md_estimate_size_before_relax (
	fragS *fragP ATTRIBUTE_UNUSED, segT segment ATTRIBUTE_UNUSED) {
	return 0;
}

#define PU32_8BITS_OUT_OF_RANGE(VAL) \
	((VAL < -(1<<7)) || (VAL > ((1<<7)-1)))

#define PU32_16BITS_OUT_OF_RANGE(VAL) \
	((VAL < -(1<<15)) || (VAL > ((1<<15)-1)))

// Relax a frag; returns the amount by which
// the current size of the frag should change.
long pu32_relax_frag (
	segT segment, fragS *fragP,
	long stretch ATTRIBUTE_UNUSED) {

	offsetT old_fr_var = fragP->fr_var;

	symbolS *symbolP = fragP->fr_symbol;

	int32_t val;

	if (symbolP) {
		if (S_IS_DEFINED (symbolP) &&
			!S_IS_WEAK (symbolP) &&
			(segment == S_GET_SEGMENT (symbolP))) {
			addressT target = (S_GET_VALUE (symbolP) + fragP->fr_offset);
			addressT address = ((fragP->fr_subtype & PU32_FR_SUBTYPE_PCREL) ?
				(fragP->fr_address + fragP->fr_fix) : 0);
			val = (target - address);
		} else
			val = 0x7fffffff /* ((1<<31)-1) */;
	} else
		val = fragP->fr_offset;

	if (fragP->fr_subtype & PU32_FR_SUBTYPE_NEGATE)
		val = -val;

	offsetT new_fr_var;

	if PU32_8BITS_OUT_OF_RANGE(val)
		if PU32_16BITS_OUT_OF_RANGE(val)
			new_fr_var = (SIZEOF_OPCODE + sizeof(uint32_t));
		else
			new_fr_var = (SIZEOF_OPCODE + sizeof(uint16_t));
	else
		new_fr_var = SIZEOF_OPCODE;

	// To prevent infinite loop, fragS are not allowed to shrink.
	if (new_fr_var <= old_fr_var)
		return 0;

	offsetT growth = ((fragP->fr_var = new_fr_var) - old_fr_var);

	fragP->fr_fix += growth;

	return growth;
}

// This function is called after relaxation
// is finished to create fixSs from fragSs.
void md_convert_frag (
	bfd *abfd ATTRIBUTE_UNUSED,
	segT sec ATTRIBUTE_UNUSED,
	fragS *fragP) {

	unsigned pcrel = ((fragP->fr_subtype & PU32_FR_SUBTYPE_PCREL) ? TRUE : FALSE);

	offsetT fr_var = fragP->fr_var;

	unsigned char *fr_opcode =
		((unsigned char *)fragP->fr_literal + fragP->fr_fix) - fr_var;

	fixS *fixP;

	switch (fr_var) {

		case (SIZEOF_OPCODE + sizeof(uint32_t)):

			switch (*fr_opcode) {
				case 0xa2 /* inc32 */:
					break;
				case 0xaa /* li32 */:
					break;
				case 0xae /* rli32 */:
					break;
				default:
					as_bad_where (fragP->fr_file, fragP->fr_line,
						_("%s: unexpected relax32"), __FUNCTION__);
					exit(1);
			}

			fixP = fix_new (
				fragP,
				fragP->fr_fix - sizeof(uint32_t),
				sizeof(uint32_t),
				fragP->fr_symbol,
				fragP->fr_offset,
				pcrel,
				(pcrel == TRUE) ? BFD_RELOC_32_PCREL : BFD_RELOC_32);

			break;

		case (SIZEOF_OPCODE + sizeof(uint16_t)):

			switch (*fr_opcode) {
				case 0xa2 /* inc32 */:
					*fr_opcode = 0xa1 /* inc16 */;
					break;
				case 0xaa /* li32 */:
					*fr_opcode = 0xa9 /* li16 */;
					break;
				case 0xae /* rli32 */:
					*fr_opcode = 0xad /* rli16 */;
					break;
				default:
					as_bad_where (fragP->fr_file, fragP->fr_line,
						_("%s: unexpected relax16"), __FUNCTION__);
					exit(1);
			}

			fixP = fix_new (
				fragP,
				fragP->fr_fix - sizeof(uint16_t),
				sizeof(uint16_t),
				fragP->fr_symbol,
				fragP->fr_offset,
				pcrel,
				(pcrel == TRUE) ? BFD_RELOC_16_PCREL : BFD_RELOC_16);

			break;

		case SIZEOF_OPCODE:

			switch (*fr_opcode) {
				case 0xa2 /* inc32 */:
					*fr_opcode = 0x90 /* inc8 */;
					break;
				case 0xaa /* li32 */:
					*fr_opcode = 0x80 /* li8 */;
					break;
				case 0xae /* rli32 */:
					*fr_opcode = 0xe0 /* rli8 */;
					break;
				default:
					as_bad_where (fragP->fr_file, fragP->fr_line,
						_("%s: unexpected relax8"), __FUNCTION__);
					exit(1);
			}

			fixP = fix_new (
				fragP,
				fragP->fr_fix - SIZEOF_OPCODE,
				SIZEOF_OPCODE,
				fragP->fr_symbol,
				fragP->fr_offset,
				pcrel,
				(pcrel == TRUE) ? BFD_RELOC_8_PCREL : BFD_RELOC_8);

			break;

		default:
			as_bad_where (fragP->fr_file, fragP->fr_line,
				_("%s: unexpected relax"), __FUNCTION__);
			exit(1);
	}

	fixP->fx_file = fragP->fr_file;
	fixP->fx_line = fragP->fr_line;
}

// Apply a fixup to the object file.
void md_apply_fix (fixS *fixP, valueT *valP, segT seg ATTRIBUTE_UNUSED) {

	fragS *fragP = fixP->fx_frag;

	char *buf = (char *)fragP->fr_literal + fixP->fx_where;

	int32_t val = *valP;

	// Check whether it was signaled that
	// the value should be negated.
	// ###: Note that this signalling is used only
	// ###: if gnu-gas is doing the relocation itself
	// ###: instead of gnu-ld.
	if (fragP->fr_subtype & PU32_FR_SUBTYPE_NEGATE)
		val = -val;

	switch (fixP->fx_r_type) {

		case BFD_RELOC_32:
		case BFD_RELOC_32_PCREL:

			buf[0] = val;
			buf[1] = val >> 8;
			buf[2] = val >> 16;
			buf[3] = val >> 24;

			break;

		case BFD_RELOC_16:
		case BFD_RELOC_16_PCREL:

			if PU32_16BITS_OUT_OF_RANGE(val) {
				as_bad_where (fixP->fx_file, fixP->fx_line,
					_("immediate out of 16bits range: %d"), val);
				exit(1);
			}

			buf[0] = val;
			buf[1] = val >> 8;

			break;

		case BFD_RELOC_8:
		case BFD_RELOC_8_PCREL:

			if PU32_8BITS_OUT_OF_RANGE(val) {
				as_bad_where (fixP->fx_file, fixP->fx_line,
					_("immediate out of 8bits range: %d"), val);
				exit(1);
			}

			buf[0] = ((buf[0]&0xf0) | ((val>>4)&0x0f));
			buf[1] = ((buf[1]&0xf0) | (val&0x0f));

			break;

		default:
			as_bad_where (fixP->fx_file, fixP->fx_line,
				_("unsupported relocation type"));
			exit(1);
	}

	if (fixP->fx_addsy == NULL && fixP->fx_pcrel == 0)
		fixP->fx_done = 1;
}

// Decide from what point a pc-relative relocation
// is relative to, relative to the pc-relative fixup.
long md_pcrel_from (fixS *fixP) {
	return fixP->fx_frag->fr_address + fixP->fx_where + fixP->fx_size;
}

// Translate internal representation of
// relocation info to BFD target format.
// This function generates relocation
// to be used by the bfd relocation howto.
arelent *tc_gen_reloc (asection *section ATTRIBUTE_UNUSED, fixS *fixP) {

	arelent *rel = xmalloc(sizeof(arelent));

	rel->sym_ptr_ptr = xmalloc(sizeof(asymbol *));
	*rel->sym_ptr_ptr = symbol_get_bfdsym(fixP->fx_addsy);

	rel->address = fixP->fx_frag->fr_address + fixP->fx_where;
	rel->addend = fixP->fx_offset;

	bfd_reloc_code_real_type r_type = fixP->fx_r_type;
	rel->howto = bfd_reloc_type_lookup (stdoutput, r_type);

	if (!rel->howto) {
		as_bad_where(fixP->fx_file, fixP->fx_line,
			_("cannot represent relocation type %s"),
			bfd_get_reloc_code_name(r_type));
		exit(1);
	}

	return rel;
}
