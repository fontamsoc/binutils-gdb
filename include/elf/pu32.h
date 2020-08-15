// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#ifndef _ELF_PU32_H
#define _ELF_PU32_H

#include "elf/reloc-macros.h"

// Relocation types.
START_RELOC_NUMBERS (elf_pu32_reloc_type)
	RELOC_NUMBER (R_PU32_NONE,     0)
	RELOC_NUMBER (R_PU32_8,        1)
	RELOC_NUMBER (R_PU32_16,       2)
	RELOC_NUMBER (R_PU32_32,       3)
	RELOC_NUMBER (R_PU32_8_PCREL,  4)
	RELOC_NUMBER (R_PU32_16_PCREL, 5)
	RELOC_NUMBER (R_PU32_32_PCREL, 6)
END_RELOC_NUMBERS (R_PU32_max)

#endif /* _ELF_PU32_H */
