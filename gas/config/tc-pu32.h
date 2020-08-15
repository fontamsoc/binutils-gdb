// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#define TC_PU32 1
#ifndef TARGET_BYTES_BIG_ENDIAN
#define TARGET_BYTES_BIG_ENDIAN 0
#endif

#define WORKING_DOT_WORD

#define TARGET_FORMAT "elf32-pu32"

#define TARGET_ARCH bfd_arch_pu32

#define md_undefined_symbol(NAME)           0

extern int md_estimate_size_before_relax (fragS *, segT);
extern void md_convert_frag (bfd *, segT, fragS *);
#define md_relax_frag pu32_relax_frag
extern long pu32_relax_frag (segT, fragS *, long);

#define MD_PCREL_FROM_SECTION(FIX, SEC) md_pcrel_from (FIX)
extern long md_pcrel_from (struct fix *);

#define md_section_align(SEGMENT, SIZE)     (SIZE)
