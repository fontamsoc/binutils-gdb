// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

#ifndef PU32_SIM_H
#define PU32_SIM_H

#define _stringify(x) #x
#define stringify(x) _stringify(x)

#include <stdint.h>

#define PU32_REG_SR	13
#define PU32_REG_PC	16
#define PU32_GPRCNT	17
#define PU32_TLBSZ	64
#define PU32_ICACHESETCOUNT	0
#define PU32_DCACHESETCOUNT	0

#define PU32_REG_ASID (PU32_GPRCNT * (1+1)) /* kernelmode+usermode GPRs */
#define PU32_REG_TIMER (PU32_REG_ASID + 1)
#define PU32_REG_FLAGS (PU32_REG_TIMER + 1)
#define PU32_REG_SYSOPCODE (PU32_REG_FLAGS + 1)
#define PU32_REG_FAULTADDR (PU32_REG_SYSOPCODE + 1)
#define PU32_REG_FAULTREASON (PU32_REG_FAULTADDR + 1)
#define PU32_REG_KSL (PU32_REG_FAULTREASON + 1)
#define PU32_REGCNT (PU32_REG_KSL + 1)

#define PU32_OP_NOTAVAIL 0x40

#define PU32_FLAGS_setasid		0x1
#define PU32_FLAGS_settimer		0x2
#define PU32_FLAGS_settlb		0x4
#define PU32_FLAGS_clrtlb		0x8
#define PU32_FLAGS_getclkcyclecnt	0x10
#define PU32_FLAGS_getclkfreq		0x20
#define PU32_FLAGS_gettlbsize		0x40
#define PU32_FLAGS_getcachesize		0x80
#define PU32_FLAGS_getcoreid		0x100
#define PU32_FLAGS_cacherst		0x200
#define PU32_FLAGS_gettlb		0x400
#define PU32_FLAGS_setflags		0x800
#define PU32_FLAGS_disExtIntr		0x1000
#define PU32_FLAGS_disTimerIntr		0x2000
#define PU32_FLAGS_disPreemptIntr	0x4000
#define PU32_FLAGS_halt			0x8000

#define PU32_CAP_mmu	0x1
#define PU32_CAP_hptw	0x2
#define PU32_CAP	(PU32_CAP_mmu | PU32_CAP_hptw)

#define PU32_VER	(((1)<<8) | (0))

typedef enum {
	pu32ReadFaultIntr,
	pu32WriteFaultIntr,
	pu32ExecFaultIntr,
	pu32AlignFaultIntr,
	pu32ExtIntr,
	pu32SysOpIntr,
	pu32TimerIntr,
	pu32PreemptIntr,
} pu32FaultReason;

typedef struct {
	union {
		struct {
			uint32_t executable:1;
			uint32_t writable:1;
			uint32_t readable:1;
			uint32_t cached:1;
			uint32_t user: 1;
			uint32_t xxx:7;
			uint32_t ppn:20;
		};
		uint32_t d1;
	};
	union {
		struct {
			uint32_t asid:12;
			uint32_t vpn:20;
		};
		uint32_t d2;
	};
} pu32tlbentry;

typedef struct {
	uint32_t regs[PU32_REGCNT];
	pu32tlbentry itlb[PU32_TLBSZ];
	pu32tlbentry dtlb[PU32_TLBSZ];
	unsigned curctx;
	unsigned skipintrhandling;
	uint32_t resettimer;
	volatile unsigned dohalt;
	uint64_t clkperiod;
	struct timespec stime;
} pu32state;

struct pu32_sim_cpu {
	unsigned coreid;
	pu32state *state;
};

#define PU32_SIM_CPU(cpu) ((struct pu32_sim_cpu *)CPU_ARCH_DATA(cpu))

// RoundDown to power of two.
#define ROUNDDOWNTOPOWEROFTWO(VALUE,POWEROFTWO) \
	((VALUE) & -(POWEROFTWO))
// RoundUp to power of two.
#define ROUNDUPTOPOWEROFTWO(VALUE,POWEROFTWO) \
	ROUNDDOWNTOPOWEROFTWO(((VALUE) + ((POWEROFTWO)-1)), POWEROFTWO)
#define PU32_KERNELSPACE_START	0x1000
#define PU32_USERSPACE_START	0x50000000 /* Binutils.TEXT_START_ADDR */

#define PU32_MEM_START	PU32_KERNELSPACE_START
#define PU32_MEM_END	(PU32_USERSPACE_START + 0x28000000)
#define PU32_MEM_SIZE	(PU32_MEM_END - PU32_MEM_START)

#define PU32_ARG_REGION_SIZE		0x1000
#define PU32_ARG_REGION_ADDR		(PU32_MEM_END - PU32_ARG_REGION_SIZE)
#define PU32_INITIAL_STACK_SIZE		0x8000
#define PU32_INITIAL_STACK_BOTTOM	PU32_ARG_REGION_ADDR
#define PU32_INITIAL_STACK_TOP		(PU32_INITIAL_STACK_BOTTOM - PU32_INITIAL_STACK_SIZE)
#define PU32_INITIAL_HEAP_SIZE		0x10000
#define PU32_INTRCHECK_STACK_SIZE	PAGE_SIZE
#define PU32_CORETHREAD_STACK_SIZE	PAGE_SIZE

#define KERNELADDR         0x8000
#define PARKPUSZ           24
#define PARKPU_ADDR        (KERNELADDR - PARKPUSZ)
#define PARKPU_RESUME_ADDR (PARKPU_ADDR +  10)

/* Number of reserved file-descriptors
   provided by the sim starting from 0:
   0: stdin.
   1: stdout.
   2: stderr.
   3: dup()ed stdin.
   4: stdin (non-blocking).
   5: storage device (non-blocking).
   6: network device (non-blocking).
   7: interrupt controller. */
#define PU32_RESERVED_FDS 8 /* must match _initialize_pu32_tdep() */

#define PU32_BIOS_FD_STDIN             4
#define PU32_BIOS_FD_STDOUT            1
#define PU32_BIOS_FD_STDERR            2
#define PU32_BIOS_FD_STORAGEDEV        5
#define PU32_BIOS_FD_NETWORKDEV        6
#define PU32_BIOS_FD_INTCTRLDEV        7

// PU32_BIOS_FD_STORAGEDEV block size in bytes.
#define BLKSZ 512

// IRQ ids when running in a VM.
#define PU32_VM_IRQ_TTYS0 0

#define PAGE_SHIFT	12
#define PAGE_SIZE	(1 << PAGE_SHIFT)
#define PAGE_MASK	(~(PAGE_SIZE-1))

// Must match linux/include/uapi/asm-generic/unistd.h .
#define __NR_arch_specific_syscall 244
#define __NR_lseek  (__NR_arch_specific_syscall+0)
#define __NR_settls (__NR_arch_specific_syscall+1)
#define __NR_gettls (__NR_arch_specific_syscall+2)
#define __NR_exit		93
#define __NR_exit_group		94
#define __NR_openat		56
#define __NR_close		57
#define __NR_read		63
#define __NR_write		64
#define __NR_writev		66
#define __NR_unlinkat		35
#define __NR_linkat		37
#define __NR_readlinkat		78
#define __NR_fstat64		80
#define __NR_getuid		174
#define __NR_geteuid		175
#define __NR_getgid		176
#define __NR_getegid		177
#define __NR_getpid		172
#define __NR_kill		129
#define __NR_brk		214
#define __NR_mmap2		222
#define __NR_chdir		49
#define __NR_fchmodat 		53
#define __NR_ioctl		29

#endif
