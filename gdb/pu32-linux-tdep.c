// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#include "defs.h"
#include "linux-tdep.h"
#include "osabi.h"
#include "solib-svr4.h"
#include "regset.h"
#include "pu32-tdep.h"
#include "gdbarch.h"

static void pu32_linux_init_osabi (struct gdbarch_info info, struct gdbarch *gdbarch) {

	linux_init_abi (info, gdbarch, 0);

	set_gdbarch_fetch_tls_load_module_address (gdbarch, svr4_fetch_objfile_link_map);
	set_gdbarch_skip_trampoline_code (gdbarch, find_solib_trampoline_target);

	set_solib_svr4_fetch_link_map_offsets (gdbarch, svr4_ilp32_fetch_link_map_offsets);
}

void _initialize_pu32_linux_tdep ();
// Register this machine's init routine.
// The regex within Makefile.in used to generate init.c
// require an _initialize_ function name to be at
// the begining of the line, otherwise it will not match.
void
_initialize_pu32_linux_tdep ()
{
	gdbarch_register_osabi (bfd_arch_pu32, 0, GDB_OSABI_LINUX, pu32_linux_init_osabi);
}
