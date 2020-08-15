// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"

const bfd_arch_info_type bfd_pu32_arch = {
	32,               // 32 bits in a word.
	32,               // 32 bits in an address.
	8,                //  8 bits in a byte.
	bfd_arch_pu32,    // enum bfd_architecture arch.
	bfd_mach_pu32,
	"PU32",           // Arch name.
	"PU32",           // Printable name.
	2,                // Unsigned int section alignment power.
	true,             // The default and only machine for the architecture.
	bfd_default_compatible,
	bfd_default_scan,
	bfd_arch_default_fill,
	NULL,
	0,
};
