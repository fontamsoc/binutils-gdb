// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#ifndef PU32_TDEP_H
#define PU32_TDEP_H

enum pu32_regnum {
	PU32_SP_REGNUM = 0,
	PU32_FP_REGNUM = 14,
	PU32_RP_REGNUM = 15,
	PU32_PC_REGNUM = 16,
	PU32_RETVAL_REGNUM = 1,
};

#define PU32_NUM_REGS 17

#endif /* PU32_TDEP_H */
