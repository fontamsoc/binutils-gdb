// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#ifndef SIM_MAIN_H
#define SIM_MAIN_H

#define WITH_SMP 8

#define SIM_CPU_EXCEPTION_SUSPEND(SD,CPU,EXC) \
	pu32_cpu_exception_suspend(SD,STATE_CPU(SD, 0),EXC)
#define SIM_CPU_EXCEPTION_RESUME(SD,CPU,EXC) \
	pu32_cpu_exception_resume(SD,STATE_CPU(SD, 0),EXC)

#include "sim-basics.h"
#include "sim-base.h"

void pu32_cpu_exception_suspend (SIM_DESC, SIM_CPU *, int);
void pu32_cpu_exception_resume (SIM_DESC, SIM_CPU *, int);

#endif
