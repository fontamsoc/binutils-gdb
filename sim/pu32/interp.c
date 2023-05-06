// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

// This must come before any other includes.
#include "defs.h"
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <termios.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <utime.h>
#include <time.h>
#include <sys/param.h>
#include <unistd.h>
#include <errno.h>
#include "bfd.h"
#include "elf-bfd.h"
#include "libiberty.h"
#include "sim/sim.h"

#include <sys/mman.h>
#ifndef MAP_UNINITIALIZED
#define MAP_UNINITIALIZED 0x4000000
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sched.h>

#include <time.h>
#include <sys/timerfd.h>

#include "sim-main.h"
#include "sim-base.h"
#include "sim-options.h"
#include "sim-signal.h"

// Uncomment to generate debug outputs.
//#define PU32_DEBUG

static volatile SIM_DESC sd = 0;

static void dumpregs (sim_cpu *scpu) {
	SIM_DESC sd = CPU_STATE(scpu);
	pu32state *scpustate = scpu->state;
	uint32_t *regs = scpustate->regs;
	unsigned long o = (scpustate->curctx*PU32_GPRCNT);
	sim_io_eprintf(sd,
		"pc(0x%x) rp(0x%x)\n",
		regs[PU32_REG_PC+o], regs[15+o]);
	sim_io_eprintf(sd,
		"sp(0x%x) r1(0x%x) r2(0x%x) r3(0x%x) r4(0x%x) r5(0x%x) r6(0x%x) r7(0x%x)\n",
		regs[0+o], regs[1+o], regs[2+o], regs[3+o], regs[4+o], regs[5+o], regs[6+o], regs[7+o]);
	sim_io_eprintf(sd,
		"r8(0x%x) r9(0x%x) tp(0x%x) r11(0x%x) r12(0x%x) sr(0x%x) fp(0x%x)\n",
		regs[8+o], regs[9+o], regs[10+o], regs[11+o], regs[12+o], regs[13+o], regs[14+o]);
}

// Copied from common/sim-core.c and modified.
static sim_core_mapping *sim_core_find_mapping (
	sim_cpu *scpu,
	unsigned map,
	address_word addr,
	unsigned nr_bytes,
	transfer_type transfer,
	int abort) {
	sim_core_mapping *mapping = (&CPU_CORE(scpu)->common)->map[map].first;
	//ASSERT ((addr & (nr_bytes - 1)) == 0); /* must be aligned */
	ASSERT ((addr + (nr_bytes - 1)) >= addr); /* must not wrap */
	while (mapping != NULL) {
		if (addr >= mapping->base &&
			(addr + (nr_bytes - 1)) <= mapping->bound)
			return mapping;
		mapping = mapping->next;
	}
	if (abort) {
		SIM_DESC sd = CPU_STATE(scpu);
		sim_cia cia = CPU_PC_GET(scpu);
		sim_io_eprintf(sd,
			"pu32-sim: core%u: %u byte%s %s unmapped address 0x%lx at 0x%lx\n",
			scpu->coreid, nr_bytes,
			(nr_bytes > 1) ? "s" : "",
			(transfer == read_transfer) ? "read from" : "write to",
			(unsigned long)addr,
			(unsigned long)CIA_ADDR(cia));
		dumpregs(scpu);
		sim_engine_halt(
			sd, scpu, scpu, cia,
			sim_stopped, SIM_SIGSEGV);
	}
	return NULL;
}

// Created from sim_core_find_mapping().
static address_word sim_core_map_memory (
	sim_cpu *scpu,
	address_word addr,
	unsigned nr_bytes,
	int fd, off_t pgoffset) {
	if (!addr)
		addr = PU32_MEM_END;
	SIM_DESC sd = CPU_STATE(scpu);
	if (addr & (PAGE_SIZE-1)) {
		sim_io_eprintf (sd, "pu32-sim: core%u: %s: addr pagesize unaligned: addr == 0x%x\n",
			scpu->coreid, __FUNCTION__, addr);
		pu32state *scpustate = scpu->state;
		dumpregs(scpu);
		sim_engine_halt (
			sd, scpu, scpu, scpustate->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
			sim_stopped, SIM_SIGABRT);
	}
	sim_core_mapping *mapping = (&CPU_CORE(scpu)->common)->map[write_map].first;
	ASSERT ((addr + (nr_bytes - 1)) >= addr); /* must not wrap */
	while (mapping != NULL) {
		if ((addr + nr_bytes) <= mapping->base)
			break;
		addr = (mapping->bound + 1);
		mapping = mapping->next;
	}
	if ((addr + (nr_bytes - 1)) < addr) {
		sim_io_eprintf (sd, "pu32-sim: core%u: %s: (addr + nr_bytes) >= addr: addr == 0x%x, nr_bytes == %u\n",
			scpu->coreid, __FUNCTION__, addr, nr_bytes);
		pu32state *scpustate = scpu->state;
		dumpregs(scpu);
		sim_engine_halt (
			sd, scpu, scpu, scpustate->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
			sim_stopped, SIM_SIGABRT);
	}
	void *mmap_buffer = mmap (
		0, nr_bytes,
		PROT_READ|PROT_WRITE,
		MAP_SHARED|((fd == -1) ? MAP_ANONYMOUS : 0),
		fd, pgoffset*PAGE_SIZE);
	if (mmap_buffer == 0 || mmap_buffer == (void*)-1) /* MAP_FAILED */ {
		sim_io_eprintf (sd, "pu32-sim: core%u: mmap() failed\n", scpu->coreid);
		pu32state *scpustate = scpu->state;
		dumpregs(scpu);
		sim_engine_halt (
			sd, scpu, scpu, scpustate->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
			sim_stopped, SIM_SIGABRT);
	}
	sim_core_attach (sd, NULL,
		0, access_read_write_exec, 0,
		addr, nr_bytes, 0, NULL, mmap_buffer);
	return addr;
}

// Copied from common/sim-core.c
static INLINE void *sim_core_translate (
	sim_core_mapping *mapping,
	address_word addr) {
	return
		(void *)((uint8_t *)mapping->buffer +
		((addr - mapping->base) & mapping->mask));
}

static SIM_OPEN_KIND sim_open_kind;

static uint32_t pgds[PU32_CPUCNT];

static struct termios ttyconfig, savedttyconfig;

// Pipe file descriptors used to buffer the id of interrupts.
static volatile int intctrlpipe[PU32_CPUCNT][2];

// Pipe file descriptors used for buffering data from STDIN.
static volatile int stdinpipe[2];

// Pipe file descriptors used to synchronize with intrthread().
static volatile int intrsyncpipe[PU32_CPUCNT][2];

// Pipe file descriptors used to synchronize with intrthread() when halting.
static volatile int haltsyncpipe[PU32_CPUCNT][2];

// File descriptors for each context %timer.
static volatile int timerfd[PU32_CPUCNT];

// intrthread() thread IDs.
static int intrthreadid[PU32_CPUCNT];
// corethread() thread IDs.
static int corethreadid[PU32_CPUCNT];

// intrthread() stacks.
static void *intrthread_stack[PU32_CPUCNT];
// corethread() stacks.
static void *corethread_stack[PU32_CPUCNT];

// File descriptor nbr to be used by poll()
// and dup()ed from STDIN_FILENO.
// It is used because file descriptor 0 (STDIN_FILENO)
// cannot be negated in order to disable polling.
#define STDIN_DUP_FILENO 3

// Total nbr of file descriptors per core to poll.
#define POLL_NFDS (             \
	1/*intrsyncpipe*/ +     \
	1/*timerfd[]*/ + \
	1/*STDIN_DUP_FILENO*/)
#define INTRSYNC_POLL_IDX 0 /* Used to restart poll() */
#define TIMER_POLL_IDX (INTRSYNC_POLL_IDX+1)
#define STDIN_POLL_IDX (TIMER_POLL_IDX+1) /* last in intrfds[][] so to be easily ignored */
#define INTRCTRL_PENDING_IDX (STDIN_POLL_IDX+1)

static volatile unsigned intrpending[PU32_CPUCNT][POLL_NFDS+1/*INTRCTRL_PENDING_IDX*/];
static volatile struct pollfd intrfds[PU32_CPUCNT][POLL_NFDS];

static volatile unsigned haltedcore[PU32_CPUCNT];

#define POLL_EVENTS_FLAGS (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND)

// An intrthread() is spawned per core.
static void intrthread (unsigned coreid) {
	sim_cpu *scpu = STATE_CPU(sd, coreid);
	pu32state *scpustate = scpu->state;
	volatile uint32_t *scpustateregs = scpustate->regs;
	intrfds[coreid][INTRSYNC_POLL_IDX].fd = intrsyncpipe[coreid][0];
	intrfds[coreid][INTRSYNC_POLL_IDX].events = POLL_EVENTS_FLAGS;
	intrfds[coreid][TIMER_POLL_IDX].fd = timerfd[coreid];
	intrfds[coreid][TIMER_POLL_IDX].events = POLL_EVENTS_FLAGS;
	if (coreid == 0) { // Only core0 handles stdin interrupts.
		intrfds[coreid][STDIN_POLL_IDX].fd =
			((sim_open_kind == SIM_OPEN_DEBUG) ?
				// When running within GDB, initially
				// disable stdin as part of intrfds[];
				-STDIN_DUP_FILENO : STDIN_DUP_FILENO);
		intrfds[coreid][STDIN_POLL_IDX].events = POLL_EVENTS_FLAGS;
	}
	intrpending[coreid][0] = 0; // intrpending[coreid][0] is used during startup to signal that intrthread() has initialized.
	while (1) {
		while (poll ((struct pollfd *)intrfds[coreid], (POLL_NFDS - (coreid != 0)), -1) == -1) {
			if (errno == EINTR)
				continue;
			perror("poll()");
			sim_io_eprintf (sd, "pu32-sim: %s: poll(intrfds[%u]) failed\n", __FUNCTION__, coreid);
			sim_engine_halt (
				sd, scpu, scpu,
				scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
				sim_stopped, SIM_SIGABRT);
		}
		if (intrfds[coreid][INTRSYNC_POLL_IDX].revents&POLL_EVENTS_FLAGS) {
			signed char intrid;
			while (read (intrfds[coreid][INTRSYNC_POLL_IDX].fd, &intrid, 1) == -1) {
				if (errno == EINTR)
					continue;
				perror("read()");
				sim_io_eprintf (sd, "pu32-sim: %s: read(intrfds[%u][INTRSYNC_POLL_IDX].fd) failed\n",
					__FUNCTION__, coreid);
				sim_engine_halt (
					sd, scpu, scpu,
					scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
					sim_stopped, SIM_SIGABRT);
			}
			unsigned en;
			if (intrid < 0) {
				intrid = -intrid;
				en = 0;
			} else
				en = 1;
			switch (intrid) {
				case STDIN_POLL_IDX:
					//intrpending[coreid][STDIN_POLL_IDX] = 0; commented otherwise keypresses can sporadically lag.
					goto set_intrfds;
				case TIMER_POLL_IDX:
					intrpending[coreid][TIMER_POLL_IDX] = 0;
					set_intrfds:;	// From here, intrid is used because it runs
							// for STDIN_POLL_IDX and TIMER_POLL_IDX.
					int fd = intrfds[coreid][intrid].fd;
					if (en) {
						if (fd < 0)
							intrfds[coreid][intrid].fd = -fd;
					} else {
						if (fd > 0)
							intrfds[coreid][intrid].fd = -fd;
					}
					break;
				default:
					sim_io_eprintf (sd, "pu32-sim: %s: invalid intrid %d\n", __FUNCTION__, intrid);
					sim_engine_halt (
						sd, scpu, scpu,
						scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
						sim_stopped, SIM_SIGABRT);
					break;
			}
			// Write to haltsyncpipe to resume restart_intrfds_poll().
			while (write (haltsyncpipe[coreid][1], &((char){0}), 1) == -1) {
				if (errno == EINTR)
					continue;
				perror("write()");
				sim_io_eprintf (sd, "pu32-sim: write(haltsyncpipe[%u][1]) failed\n", coreid);
				sim_engine_halt (
					sd, scpu, scpu,
					scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
					sim_stopped, SIM_SIGABRT);
			}
			continue;
		}
		int fd = intrfds[coreid][TIMER_POLL_IDX].fd;
		if (fd > 0 && intrfds[coreid][TIMER_POLL_IDX].revents&POLL_EVENTS_FLAGS) {
			while (read (fd, &((uint64_t){0}), sizeof(uint64_t)) == -1) {
				if (errno == EINTR)
					continue;
				perror("read()");
				sim_io_eprintf (sd, "pu32-sim: %s: read(intrfds[%u][TIMER_POLL_IDX].fd) failed\n", __FUNCTION__, coreid);
				sim_engine_halt (
					sd, scpu, scpu,
					scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
					sim_stopped, SIM_SIGABRT);
			}
			intrfds[coreid][TIMER_POLL_IDX].fd = -fd; // Negate to disable it as part of intrfds[].
			intrpending[coreid][TIMER_POLL_IDX] = 1;
			scpustate->dohalt = (scpustate->dohalt && !!(scpustateregs[PU32_REG_FLAGS] & PU32_FLAGS_disTimerIntr));
		}
		if (coreid == 0 && intrfds[coreid][STDIN_POLL_IDX].revents&POLL_EVENTS_FLAGS) {
			// Only core0 handles stdin interrupts.
			int stdinflags = fcntl(STDIN_FILENO, F_GETFL);
			while (fcntl(STDIN_FILENO, F_SETFL, stdinflags | O_NONBLOCK) == -1) {
				if (errno == EINTR)
					continue;
				perror("fcntl()");
				sim_io_eprintf (sd, "pu32-sim: fcntl(STDIN_FILENO) failed\n");
				sim_engine_halt (
					sd, scpu, scpu,
					scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
					sim_stopped, SIM_SIGABRT);
			}
			ssize_t splice_ret;
			do splice_ret = splice(STDIN_FILENO, 0, stdinpipe[1], 0, PIPE_BUF, SPLICE_F_NONBLOCK);
				while ((splice_ret == -1 && errno == EINTR) || splice_ret == PIPE_BUF);
			while (fcntl(STDIN_FILENO, F_SETFL, stdinflags) == -1) {
				if (errno == EINTR)
					continue;
				perror("fcntl()");
				sim_io_eprintf (sd, "pu32-sim: fcntl(STDIN_FILENO) failed\n");
				sim_engine_halt (
					sd, scpu, scpu,
					scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
					sim_stopped, SIM_SIGABRT);
			}
			intrpending[coreid][STDIN_POLL_IDX] = 1;
			scpustate->dohalt = (scpustate->dohalt && !!(scpustateregs[PU32_REG_FLAGS] & PU32_FLAGS_disExtIntr));
		}
		if (haltedcore[coreid] && !scpustate->dohalt) {
			while (write (haltsyncpipe[coreid][1], &((char){0}), 1) == -1) {
				if (errno == EINTR)
					continue;
				perror("write()");
				sim_io_eprintf (sd, "pu32-sim: write(haltsyncpipe[%u][1]) failed\n", coreid);
				sim_engine_halt (
					sd, scpu, scpu,
					scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
					sim_stopped, SIM_SIGABRT);
			}
			while (haltedcore[coreid]);
			while (write (haltsyncpipe[coreid][1], &((char){0}), 1) == -1) {
				if (errno == EINTR)
					continue;
				perror("write()");
				sim_io_eprintf (sd, "pu32-sim: write(haltsyncpipe[%u][1]) failed\n", coreid);
				sim_engine_halt (
					sd, scpu, scpu,
					scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
					sim_stopped, SIM_SIGABRT);
			}
		}
	}
}

static uint64_t getclkperiod (unsigned coreid) {
	// Return nanoseconds/clockcycle.
	struct timespec t;
	while (clock_getres(CLOCK_BOOTTIME, &t) == -1) {
		if (errno == EINTR)
			continue;
		perror("clock_getres()");
		sim_io_eprintf (sd, "pu32-sim: clock_getres() failed\n");
		sim_cpu *scpu = STATE_CPU(sd, coreid);
		pu32state *scpustate = scpu->state;
		sim_engine_halt (
			sd, scpu, scpu, scpustate->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
			sim_stopped, SIM_SIGABRT);
	}
	return (uint64_t)t.tv_nsec + ((uint64_t)t.tv_sec*1000000000);
}

static void restart_intrfds_poll (unsigned coreid, char intrid) {
	while (write (intrsyncpipe[coreid][1], &intrid, 1) == -1) {
		if (errno == EINTR)
			continue;
		perror("write()");
		sim_io_eprintf (sd, "pu32-sim: %s: write(intrsyncpipe[%u][1]) failed\n",
			__FUNCTION__, coreid);
		sim_cpu *scpu = STATE_CPU(sd, coreid);
		pu32state *scpustate = scpu->state;
		sim_engine_halt (
			sd, scpu, scpu, scpustate->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
			sim_stopped, SIM_SIGABRT);
	}
	// Wait for intrthread() to complete.
	while (read (haltsyncpipe[coreid][0], &((char){0}), 1) == -1) {
		if (errno == EINTR)
			continue;
		perror("read()");
		sim_io_eprintf (sd, "pu32-sim: %s: read(haltsyncpipe[%u][0]) failed\n",
			__FUNCTION__, coreid);
		sim_cpu *scpu = STATE_CPU(sd, coreid);
		pu32state *scpustate = scpu->state;
		sim_engine_halt (
			sd, scpu, scpu,
			scpu->state->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
			sim_stopped, SIM_SIGABRT);
	}
}

void pu32_cpu_exception_suspend (
	SIM_DESC _ /* ignore */,
	SIM_CPU *scpu, int exc) {
	scpu->state->skipintrhandling = (exc == SIGTRAP);
	restart_intrfds_poll(scpu->coreid, -STDIN_POLL_IDX);
	tcsetattr(STDOUT_FILENO, TCSADRAIN, &savedttyconfig);
}

void pu32_cpu_exception_resume (
	SIM_DESC _ /* ignore */,
	SIM_CPU *scpu, int exc) {
	tcsetattr(STDOUT_FILENO, TCSADRAIN, &ttyconfig);
	restart_intrfds_poll(scpu->coreid, STDIN_POLL_IDX);
}

// Bitfield used to keep track of whether
// an address needs to be translated.
static union {
	struct {
		uint32_t st8at :1;
		uint32_t st16at :1;
		uint32_t st32at :1;
		uint32_t ld8at :1;
		uint32_t ld16at :1;
		uint32_t ld32at :1;
		uint32_t ldst8at :1;
		uint32_t ldst16at :1;
		uint32_t ldst32at :1;
		uint32_t cldst8at :1;
		uint32_t cldst16at :1;
		uint32_t cldst32at :1;
		uint32_t ldinst :1;
	};
	uint32_t _;
} clraddrtranslcache[PU32_CPUCNT];

#include "p.interp.c"

static volatile int brkcoreid;

static unsigned long corecnt = 1;

void sim_engine_run (
	SIM_DESC _ /* ignore */,
	int coreid,
	int nr_cpus /* ignore */,
	int siggnal /* ignore */) {

	sim_cpu *scpu = STATE_CPU(sd, coreid);
	pu32state *scpustate = scpu->state;
	volatile uint32_t *scpustateregs = scpustate->regs;
	pu32tlbentry *scpustateitlb = scpustate->itlb;
	pu32tlbentry *scpustatedtlb = scpustate->dtlb;

	struct timespec clockcyclestotimespec (uint32_t clockcycles) {
		struct timespec t;
		uint64_t nanosecs = ((uint64_t)1 * clockcycles * scpustate->clkperiod);
		t.tv_nsec = (nanosecs % 1000000000);
		t.tv_sec = (nanosecs / 1000000000);
		return t;
	}

	void do_resettimer (void) {

		uint32_t timerval = scpustateregs[PU32_REG_TIMER];
		int fd = intrfds[coreid][TIMER_POLL_IDX].fd;

		if (fd > 0) {
			// Disable polling of corresponding file descriptor
			// so not to miss an interrupt triggering before
			// calling restart_intrfds_poll(coreid, TIMER_POLL_IDX),
			// due to timerval being very small.
			restart_intrfds_poll(coreid, -TIMER_POLL_IDX);
		} else
			fd = -fd;

		if (timerval == -1)
			return;

		struct itimerspec itsval;
		itsval.it_value = clockcyclestotimespec(timerval);
		itsval.it_interval.tv_nsec = 0;
		itsval.it_interval.tv_sec = 0;
		while (timerfd_settime (fd, 0, &itsval, 0) == -1) {
			if (errno == EINTR)
				continue;
			perror("timerfd_settime()");
			sim_io_eprintf (sd, "pu32-sim: timerfd_settime(%u) failed\n", fd);
			sim_engine_halt (
				sd, scpu, scpu, scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
				sim_stopped, SIM_SIGABRT);
		}

		restart_intrfds_poll(coreid, TIMER_POLL_IDX);
	}

	while (1) {

		__label__ sim_engine_run_loopbottom;

		// Used within "m.interp.c" .
		void dopfault (pu32FaultReason r, uint32_t a) {
			scpustateregs[PU32_REG_FAULTREASON] = r;
			scpustateregs[PU32_REG_SYSOPCODE] = PU32_OP_NOTAVAIL;
			scpustateregs[PU32_REG_FAULTADDR] = a;
			scpustate->curctx = 0;
			clraddrtranslcache[coreid]._ = -1;
			goto sim_engine_run_loopbottom;
		}

		#include "m.interp.c"

		if (scpustate->curctx && !scpustate->skipintrhandling) {

			if (scpustate->dohalt && (haltedcore[coreid] =
				(!intrpending[coreid][TIMER_POLL_IDX] && !intrpending[coreid][INTRCTRL_PENDING_IDX] &&
				((coreid != 0) || !intrpending[coreid][STDIN_POLL_IDX])))) {

				while (read (haltsyncpipe[coreid][0], &((char){0}), 1) == -1) {
					if (errno == EINTR)
						continue;
					perror("read()");
					sim_io_eprintf (sd, "pu32-sim: %s: read(haltsyncpipe[%u][0]) failed\n",
						__FUNCTION__, coreid);
					sim_engine_halt (
						sd, scpu, scpu,
						scpu->state->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
						sim_stopped, SIM_SIGABRT);
				}
				haltedcore[coreid] = 0;
				while (read (haltsyncpipe[coreid][0], &((char){0}), 1) == -1) {
					if (errno == EINTR)
						continue;
					perror("read()");
					sim_io_eprintf (sd, "pu32-sim: %s: read(haltsyncpipe[%u][0]) failed\n",
						__FUNCTION__, coreid);
					sim_engine_halt (
						sd, scpu, scpu,
						scpu->state->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
						sim_stopped, SIM_SIGABRT);
				}

				scpustate->dohalt = 0;
				clraddrtranslcache[coreid]._ = -1;
			}

			if (!(scpustateregs[PU32_REG_FLAGS] & PU32_FLAGS_disTimerIntr) &&
				intrpending[coreid][TIMER_POLL_IDX]) {

				intrpending[coreid][TIMER_POLL_IDX] = 0;

				scpustateregs[PU32_REG_FAULTREASON] = pu32TimerIntr;
				scpustateregs[PU32_REG_SYSOPCODE] = PU32_OP_NOTAVAIL;
				scpustate->curctx = 0;
				clraddrtranslcache[coreid]._ = -1;

			} else if (!(scpustateregs[PU32_REG_FLAGS] & PU32_FLAGS_disExtIntr) &&
				intrpending[coreid][INTRCTRL_PENDING_IDX]) {

				while (write (intctrlpipe[coreid][1], &((uint32_t){-1}), sizeof(uint32_t)) == -1) {
					if (errno == EINTR)
						continue;
					perror("write()");
					sim_io_eprintf (sd, "pu32-sim: %s: write(intctrlpipe[%u][1]) failed\n",
						__FUNCTION__, coreid);
					sim_engine_halt (
						sd, scpu, scpu,
						scpu->state->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
						sim_stopped, SIM_SIGABRT);
				}

				intrpending[coreid][INTRCTRL_PENDING_IDX] = 0;

				scpustateregs[PU32_REG_FAULTREASON] = pu32ExtIntr;
				scpustateregs[PU32_REG_SYSOPCODE] = PU32_OP_NOTAVAIL;
				scpustate->curctx = 0;
				clraddrtranslcache[coreid]._ = -1;

			} else if (!(scpustateregs[PU32_REG_FLAGS] & PU32_FLAGS_disExtIntr) &&
				intrpending[coreid][STDIN_POLL_IDX]) {

				while (write (intctrlpipe[coreid][1], &((uint32_t){PU32_VM_IRQ_TTYS0}), sizeof(uint32_t)) == -1) {
					if (errno == EINTR)
						continue;
					perror("write()");
					sim_io_eprintf (sd, "pu32-sim: %s: write(intctrlpipe[%u][1]) failed\n",
						__FUNCTION__, coreid);
					sim_engine_halt (
						sd, scpu, scpu,
						scpu->state->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
						sim_stopped, SIM_SIGABRT);
				}

				intrpending[coreid][STDIN_POLL_IDX] = 0;

				scpustateregs[PU32_REG_FAULTREASON] = pu32ExtIntr;
				scpustateregs[PU32_REG_SYSOPCODE] = PU32_OP_NOTAVAIL;
				scpustate->curctx = 0;
				clraddrtranslcache[coreid]._ = -1;
			}
		}

		unsigned curctxgproffset = (scpustate->curctx*PU32_GPRCNT);

		uint16_t inst = ldinst (scpustateregs[PU32_REG_PC+curctxgproffset]);

		uint8_t inst0 = inst;
		uint8_t inst1 = (inst >> 8);

		switch (inst0) {

			case 0xb8: {
				// Specification from the
				// instruction set manual:
				// add %gpr1, %gpr2 |23|000|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] += scpustateregs[gpr2+curctxgproffset];

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xb9: {
				// Specification from the
				// instruction set manual:
				// sub %gpr1, %gpr2 |23|001|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] -= scpustateregs[gpr2+curctxgproffset];

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xca: {
				// Specification from the
				// instruction set manual:
				// mul %gpr1, %gpr2 |25|010|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((int32_t)scpustateregs[gpr1+curctxgproffset] *
						(int32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xcb: {
				// Specification from the
				// instruction set manual:
				// mulh %gpr1, %gpr2 |25|011|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					(((((int64_t)1 * (int32_t)scpustateregs[gpr1+curctxgproffset]) *
						(int32_t)scpustateregs[gpr2+curctxgproffset])) >> 32);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xce: {
				// Specification from the
				// instruction set manual:
				// div %gpr1, %gpr2 |25|110|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((int32_t)scpustateregs[gpr1+curctxgproffset] /
						(int32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xcf: {
				// Specification from the
				// instruction set manual:
				// mod %gpr1, %gpr2 |25|111|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((int32_t)scpustateregs[gpr1+curctxgproffset] %
						(int32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xc8: {
				// Specification from the
				// instruction set manual:
				// mulu %gpr1, %gpr2 |25|000|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((uint32_t)scpustateregs[gpr1+curctxgproffset] *
						(uint32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xc9: {
				// Specification from the
				// instruction set manual:
				// mulhu %gpr1, %gpr2 |25|001|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					(((((uint64_t)1 * (uint32_t)scpustateregs[gpr1+curctxgproffset]) *
						(uint32_t)scpustateregs[gpr2+curctxgproffset])) >> 32);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xcc: {
				// Specification from the
				// instruction set manual:
				// divu %gpr1, %gpr2 |25|100|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((uint32_t)scpustateregs[gpr1+curctxgproffset] /
						(uint32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xcd: {
				// Specification from the
				// instruction set manual:
				// modu %gpr1, %gpr2 |25|101|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((uint32_t)scpustateregs[gpr1+curctxgproffset] %
						(uint32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			union {
				uint32_t i;
				float f;
			} farg1, farg2, frslt;

			case 0xd8: {
				// Specification from the
				// instruction set manual:
				// fadd %gpr1, %gpr2 |22|100|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				farg1.i = scpustateregs[gpr1+curctxgproffset];
				farg2.i = scpustateregs[gpr2+curctxgproffset];
				frslt.f = (farg1.f + farg2.f);
				scpustateregs[gpr1+curctxgproffset] = frslt.i;

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xd9: {
				// Specification from the
				// instruction set manual:
				// fsub %gpr1, %gpr2 |22|101|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				farg1.i = scpustateregs[gpr1+curctxgproffset];
				farg2.i = scpustateregs[gpr2+curctxgproffset];
				frslt.f = (farg1.f - farg2.f);
				scpustateregs[gpr1+curctxgproffset] = frslt.i;

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xda: {
				// Specification from the
				// instruction set manual:
				// fmul %gpr1, %gpr2 |22|110|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				farg1.i = scpustateregs[gpr1+curctxgproffset];
				farg2.i = scpustateregs[gpr2+curctxgproffset];
				frslt.f = (farg1.f * farg2.f);
				scpustateregs[gpr1+curctxgproffset] = frslt.i;

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xdb: {
				// Specification from the
				// instruction set manual:
				// fdiv %gpr1, %gpr2 |22|111|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				farg1.i = scpustateregs[gpr1+curctxgproffset];
				farg2.i = scpustateregs[gpr2+curctxgproffset];
				frslt.f = (farg1.f / farg2.f);
				scpustateregs[gpr1+curctxgproffset] = frslt.i;

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xc3: {
				// Specification from the
				// instruction set manual:
				// and %gpr1, %gpr2 |24|011|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] &= scpustateregs[gpr2+curctxgproffset];

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xc4: {
				// Specification from the
				// instruction set manual:
				// or %gpr1, %gpr2 |24|100|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] |= scpustateregs[gpr2+curctxgproffset];

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xc5: {
				// Specification from the
				// instruction set manual:
				// xor %gpr1, %gpr2 |24|101|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] ^= scpustateregs[gpr2+curctxgproffset];

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xc6: {
				// Specification from the
				// instruction set manual:
				// not %gpr1, %gpr2 |24|110|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] = ~scpustateregs[gpr2+curctxgproffset];

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xc7: {
				// Specification from the
				// instruction set manual:
				// cpy %gpr1, %gpr2 |24|111|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] = scpustateregs[gpr2+curctxgproffset];

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xc0: {
				// Specification from the
				// instruction set manual:
				// sll %gpr1, %gpr2 |24|000|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] <<= scpustateregs[gpr2+curctxgproffset];

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xc1: {
				// Specification from the
				// instruction set manual:
				// srl %gpr1, %gpr2 |24|001|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((uint32_t)scpustateregs[gpr1+curctxgproffset] >>
						(uint32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xc2: {
				// Specification from the
				// instruction set manual:
				// sra %gpr1, %gpr2 |24|010|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((int32_t)scpustateregs[gpr1+curctxgproffset] >>
						(int32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xba: {
				// Specification from the
				// instruction set manual:
				// seq %gpr1, %gpr2 |23|010|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					(scpustateregs[gpr1+curctxgproffset] ==
						scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xbb: {
				// Specification from the
				// instruction set manual:
				// sne %gpr1, %gpr2 |23|011|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					(scpustateregs[gpr1+curctxgproffset] !=
						scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xbc: {
				// Specification from the
				// instruction set manual:
				// slt %gpr1, %gpr2 |23|100|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((int32_t)scpustateregs[gpr1+curctxgproffset] <
						(int32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xbd: {
				// Specification from the
				// instruction set manual:
				// slte %gpr1, %gpr2 |23|101|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((int32_t)scpustateregs[gpr1+curctxgproffset] <=
						(int32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xbe: {
				// Specification from the
				// instruction set manual:
				// sltu %gpr1, %gpr2 |23|110|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((uint32_t)scpustateregs[gpr1+curctxgproffset] <
						(uint32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xbf: {
				// Specification from the
				// instruction set manual:
				// slteu %gpr1, %gpr2 |23|111|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((uint32_t)scpustateregs[gpr1+curctxgproffset] <=
						(uint32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xb0: {
				// Specification from the
				// instruction set manual:
				// sgt %gpr1, %gpr2 |19|000|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((int32_t)scpustateregs[gpr1+curctxgproffset] >
						(int32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xb1: {
				// Specification from the
				// instruction set manual:
				// sgte %gpr1, %gpr2 |19|001|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((int32_t)scpustateregs[gpr1+curctxgproffset] >=
						(int32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xb2: {
				// Specification from the
				// instruction set manual:
				// sgtu %gpr1, %gpr2 |19|010|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((uint32_t)scpustateregs[gpr1+curctxgproffset] >
						(uint32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xb3: {
				// Specification from the
				// instruction set manual:
				// sgteu %gpr1, %gpr2 |19|011|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					((uint32_t)scpustateregs[gpr1+curctxgproffset] >=
						(uint32_t)scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xd0: {
				// Specification from the
				// instruction set manual:
				// jz %gpr1 %gpr2 |26|000|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				if (!scpustateregs[gpr1+curctxgproffset])
					scpustateregs[PU32_REG_PC+curctxgproffset] =
						(scpustateregs[gpr2+curctxgproffset] & ~(uint32_t)1);
				else
					scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xd1: {
				// Specification from the
				// instruction set manual:
				// jnz %gpr1 %gpr2 |26|001|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				if (scpustateregs[gpr1+curctxgproffset])
					scpustateregs[PU32_REG_PC+curctxgproffset] =
						(scpustateregs[gpr2+curctxgproffset] & ~(uint32_t)1);
				else
					scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xd2: {
				// Specification from the
				// instruction set manual:
				// jl %gpr1 %gpr2 |26|010|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] = (scpustateregs[PU32_REG_PC+curctxgproffset] + 2);
				scpustateregs[PU32_REG_PC+curctxgproffset] =
					(scpustateregs[gpr2+curctxgproffset] & ~(uint32_t)1);

				break;
			}

			case 0xad: {
				// Specification from the
				// instruction set manual:
				// rli16 %gpr, imm |21|101|rrrr|0000|
				//                 |iiiiiiiiiiiiiiii|

				unsigned gpr = (inst1 >> 4);

				int32_t imm = ldinst (scpustateregs[PU32_REG_PC+curctxgproffset] + 2);

				// Sign extend the immediate value.
				imm <<= ((sizeof(imm)*8)-16);
				imm >>= ((sizeof(imm)*8)-16);

				scpustateregs[PU32_REG_PC+curctxgproffset] += (2 + 2);

				scpustateregs[gpr+curctxgproffset] =
					(scpustateregs[PU32_REG_PC+curctxgproffset] + imm);

				break;
			}

			case 0xae: {
				// Specification from the
				// instruction set manual:
				// rli32 %gpr, imm |21|110|rrrr|0000|
				//                 |iiiiiiiiiiiiiiii| 16 msb.
				//                 |iiiiiiiiiiiiiiii| 16 lsb.

				unsigned gpr = (inst1 >> 4);

				uint32_t uip = scpustateregs[PU32_REG_PC+curctxgproffset];

				uint16_t imm0 = ldinst (uip + 2);
				uint16_t imm1 = ldinst (uip + 4);
				uint32_t imm = (imm0 | (imm1 << 16));

				scpustateregs[PU32_REG_PC+curctxgproffset] += (2 + 2 + 2);

				scpustateregs[gpr+curctxgproffset] =
					(scpustateregs[PU32_REG_PC+curctxgproffset] + imm);

				break;
			}

			case 0xac: {
				// Specification from the
				// instruction set manual:
				// drli %gpr, imm |21|000|rrrr|0000|
				//                |iiiiiiiiiiiiiiii| 16 msb.
				//                |iiiiiiiiiiiiiiii| 16 lsb.

				unsigned gpr = (inst1 >> 4);

				uint32_t uip = scpustateregs[PU32_REG_PC+curctxgproffset];

				uint16_t imm0 = ldinst (uip + 2);
				uint16_t imm1 = ldinst (uip + 4);
				uint32_t imm = (imm0 | (imm1 << 16));

				scpustateregs[PU32_REG_PC+curctxgproffset] += (2 + 2 + 2);

				scpustateregs[gpr+curctxgproffset] =
					ld32at (scpustateregs[PU32_REG_PC+curctxgproffset] + imm);

				break;
			}

			case 0xa1: {
				// Specification from the
				// instruction set manual:
				// inc16 %gpr1, %gpr2, imm |20|001|rrrr|rrrr|
				//                         |iiiiiiiiiiiiiiii|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				int32_t imm = ldinst (scpustateregs[PU32_REG_PC+curctxgproffset] + 2);

				// Sign extend the immediate value.
				imm <<= ((sizeof(imm)*8)-16);
				imm >>= ((sizeof(imm)*8)-16);

				scpustateregs[gpr1+curctxgproffset] =
					(scpustateregs[gpr2+curctxgproffset] + imm);

				scpustateregs[PU32_REG_PC+curctxgproffset] += (2 + 2);

				break;
			}

			case 0xa2: {
				// Specification from the
				// instruction set manual:
				// inc32 %gpr1, %gpr2, imm |20|010|rrrr|rrrr|
				//                         |iiiiiiiiiiiiiiii| 16 msb.
				//                         |iiiiiiiiiiiiiiii| 16 lsb.

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				uint32_t uip = scpustateregs[PU32_REG_PC+curctxgproffset];

				uint16_t imm0 = ldinst (uip + 2);
				uint16_t imm1 = ldinst (uip + 4);
				uint32_t imm = (imm0 | (imm1 << 16));

				scpustateregs[gpr1+curctxgproffset] =
					(scpustateregs[gpr2+curctxgproffset] + imm);

				scpustateregs[PU32_REG_PC+curctxgproffset] += (2 + 2 + 2);

				break;
			}

			case 0xa9: {
				// Specification from the
				// instruction set manual:
				// li16 %gpr, imm |21|001|rrrr|0000|
				//                |iiiiiiiiiiiiiiii|

				unsigned gpr = (inst1 >> 4);

				int32_t imm = ldinst (scpustateregs[PU32_REG_PC+curctxgproffset] + 2);

				// Sign extend the immediate value.
				imm <<= ((sizeof(imm)*8)-16);
				imm >>= ((sizeof(imm)*8)-16);

				scpustateregs[gpr+curctxgproffset] = imm;

				scpustateregs[PU32_REG_PC+curctxgproffset] += (2 + 2);

				break;
			}

			case 0xaa: {
				// Specification from the
				// instruction set manual:
				// li32 %gpr, imm |21|010|rrrr|0000|
				//                |iiiiiiiiiiiiiiii| 16 msb.
				//                |iiiiiiiiiiiiiiii| 16 lsb.

				unsigned gpr = (inst1 >> 4);

				uint32_t uip = scpustateregs[PU32_REG_PC+curctxgproffset];

				uint16_t imm0 = ldinst (uip + 2);
				uint16_t imm1 = ldinst (uip + 4);
				uint32_t imm = (imm0 | (imm1 << 16));

				scpustateregs[gpr+curctxgproffset] = imm;

				scpustateregs[PU32_REG_PC+curctxgproffset] += (2 + 2 + 2);

				break;
			}

			case 0x74:
			case 0xf4: {
				// Specification from the
				// instruction set manual:
				// ld8v %gpr1, %gpr2 |14|100|rrrr|rrrr|
				// ld8  %gpr1, %gpr2 |30|100|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					ld8at (scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0x75:
			case 0xf5: {
				// Specification from the
				// instruction set manual:
				// ld16v %gpr1, %gpr2 |14|101|rrrr|rrrr|
				// ld16  %gpr1, %gpr2 |30|101|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					ld16at (scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0x76:
			case 0xf6: {
				// Specification from the
				// instruction set manual:
				// ld32v %gpr1, %gpr2 |14|110|rrrr|rrrr|
				// ld32  %gpr1, %gpr2 |30|110|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					ld32at (scpustateregs[gpr2+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0x70:
			case 0xf0: {
				// Specification from the
				// instruction set manual:
				// st8v %gpr1, %gpr2 |14|000|rrrr|rrrr|
				// st8  %gpr1, %gpr2 |30|000|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				st8at (
					scpustateregs[gpr2+curctxgproffset],
					scpustateregs[gpr1+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0x71:
			case 0xf1: {
				// Specification from the
				// instruction set manual:
				// st16v %gpr1, %gpr2 |14|001|rrrr|rrrr|
				// st16  %gpr1, %gpr2 |30|001|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				st16at (
					scpustateregs[gpr2+curctxgproffset],
					scpustateregs[gpr1+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0x72:
			case 0xf2: {
				// Specification from the
				// instruction set manual:
				// st32v %gpr1, %gpr2 |14|010|rrrr|rrrr|
				// st32  %gpr1, %gpr2 |30|010|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				st32at (
					scpustateregs[gpr2+curctxgproffset],
					scpustateregs[gpr1+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xf8: {
				// Specification from the
				// instruction set manual:
				// ldst8 %gpr1, %gpr2 |31|000|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					ldst8at (
						scpustateregs[gpr2+curctxgproffset],
						scpustateregs[gpr1+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xf9: {
				// Specification from the
				// instruction set manual:
				// ldst16 %gpr1, %gpr2 |31|001|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					ldst16at (
						scpustateregs[gpr2+curctxgproffset],
						scpustateregs[gpr1+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xfa: {
				// Specification from the
				// instruction set manual:
				// ldst32 %gpr1, %gpr2 |31|010|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					ldst32at (
						scpustateregs[gpr2+curctxgproffset],
						scpustateregs[gpr1+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xfc: {
				// Specification from the
				// instruction set manual:
				// cldst8 %gpr1, %gpr2 |31|100|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					cldst8at (
						scpustateregs[gpr2+curctxgproffset],
						scpustateregs[gpr1+curctxgproffset],
						scpustateregs[PU32_REG_SR+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xfd: {
				// Specification from the
				// instruction set manual:
				// cldst16 %gpr1, %gpr2 |31|101|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					cldst16at (
						scpustateregs[gpr2+curctxgproffset],
						scpustateregs[gpr1+curctxgproffset],
						scpustateregs[PU32_REG_SR+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			case 0xfe: {
				// Specification from the
				// instruction set manual:
				// cldst32 %gpr1, %gpr2 |31|110|rrrr|rrrr|

				unsigned gpr1 = (inst1 >> 4);
				unsigned gpr2 = (inst1 & 0xf);

				scpustateregs[gpr1+curctxgproffset] =
					cldst32at (
						scpustateregs[gpr2+curctxgproffset],
						scpustateregs[gpr1+curctxgproffset],
						scpustateregs[PU32_REG_SR+curctxgproffset]);

				scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

				break;
			}

			default: {

				uint notinflags (void) {

					uint32_t flags = scpustateregs[PU32_REG_FLAGS];

					switch (inst0) {

						case 0x02:
							// Allow GDB to catch breakpoints
							// even when the pu is in usermode.
							if (sim_open_kind == SIM_OPEN_DEBUG)
								return 0;
							else
								return 1;

						case 0x03:
							if (flags & PU32_FLAGS_halt)
								return 0;
							else
								return 1;

						case 0x04:
						case 0x05:
							if (flags & PU32_FLAGS_cacherst)
								return 0;
							else
								return 1;

						case 0x3c:
							if (flags & PU32_FLAGS_setasid)
								return 0;
							else
								return 1;

						case 0x3e:
							if (flags & PU32_FLAGS_setflags)
								return 0;
							else
								return 1;

						case 0x3f:
							if (flags & PU32_FLAGS_settimer)
								return 0;
							else
								return 1;

						case 0x3a:
							if (flags & PU32_FLAGS_settlb)
								return 0;
							else
								return 1;

						case 0x3b:
							if (flags & PU32_FLAGS_clrtlb)
								return 0;
							else
								return 1;

						case 0x2c:
						case 0x2d:
							if (flags & PU32_FLAGS_getclkcyclecnt)
								return 0;
							else
								return 1;

						case 0x2e:
							if (flags & PU32_FLAGS_gettlbsize)
								return 0;
							else
								return 1;

						case 0x2f:
						case 0x12:
							if (flags & PU32_FLAGS_getcachesize)
								return 0;
							else
								return 1;

						case 0x10:
							if (flags & PU32_FLAGS_getcoreid)
								return 0;
							else
								return 1;

						case 0x11:
						case 0x14:
						case 0x15:
							if (flags & PU32_FLAGS_getclkfreq)
								return 0;
							else
								return 1;

						case 0x13:
							if (flags & PU32_FLAGS_gettlb)
								return 0;
							else
								return 1;
					}

					return 1;
				}

				unsigned x = (inst0 >> 4);

				if (x == 0x8 || x == 0x9 || x == 0xe) {
					// Specification from the
					// instruction set manual:
					// li8 %gpr, imm |1000|iiii|rrrr|iiii|

					// Specification from the
					// instruction set manual:
					// inc8 %gpr, imm |1001|iiii|rrrr|iiii|

					// Specification from the
					// instruction set manual:
					// rli8 %gpr, imm |1110|iiii|rrrr|iiii|

					scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

					if (inst == 0x0090) { // preemptctx: inc8 %0, 0;

						if (scpustate->curctx && !scpustate->skipintrhandling
							&& !(scpustateregs[PU32_REG_FLAGS] & PU32_FLAGS_disPreemptIntr)) {
							scpustateregs[PU32_REG_FAULTREASON] = pu32PreemptIntr;
							scpustateregs[PU32_REG_SYSOPCODE] = PU32_OP_NOTAVAIL;
							scpustate->curctx = 0;
							clraddrtranslcache[coreid]._ = -1;
						}

					} else {

						unsigned gpr = (inst1 >> 4);

						int32_t imm = ((inst0&0xf)<<4) + (inst1&0xf);

						// Sign extend the immediate value.
						imm <<= ((sizeof(imm)*8)-8);
						imm >>= ((sizeof(imm)*8)-8);

						if (x == 0x8)
							scpustateregs[gpr+curctxgproffset] = imm;
						else if (x == 0x9)
							scpustateregs[gpr+curctxgproffset] += imm;
						else
							scpustateregs[gpr+curctxgproffset] =
								(scpustateregs[PU32_REG_PC+curctxgproffset] + imm);
					}

				} else if (scpustate->curctx && notinflags()) {

					scpustateregs[PU32_REG_FAULTREASON] = pu32SysOpIntr;
					scpustateregs[PU32_REG_SYSOPCODE] = inst;
					scpustate->curctx = 0;
					clraddrtranslcache[coreid]._ = -1;

				} else switch (inst0) {

					// In this block, curctxgproffset is used only with instructions
					// which can be enabled in usermode through setflags.

					case 0x00: {
						// Specification from the
						// instruction set manual:
						// sysret |0|000|0000|0000|

						scpustate->curctx = 1;
						clraddrtranslcache[coreid]._ = -1;

						scpustateregs[PU32_REG_PC] += 2;

						if (scpustate->resettimer) {
							scpustate->resettimer = 0;
							do_resettimer();
						}

						break;
					}

					case 0x01: { // syscall pseudo-instruction.
						// Specification from the
						// instruction set manual:
						// syscall |0|001|0000|0000|

						// Here are handled syscalls issued
						// while in kernelmode; the correct
						// naming would be hypercalls.

						switch (scpustateregs[PU32_REG_SR]) {

							case __NR_exit:
							case __NR_exit_group: {

								restart_intrfds_poll(coreid, -STDIN_POLL_IDX);

								tcsetattr(STDOUT_FILENO, TCSAFLUSH, &savedttyconfig);

								sim_engine_halt (
									sd, scpu, scpu, scpustateregs[PU32_REG_PC],
									sim_exited, scpustateregs[1]);

								break;
							}

							void *get_host_addr (
								address_word vm_addr,
								unsigned nr_bytes,
								unsigned map,
								transfer_type transfer) {
								sim_core_mapping *mapping =
									sim_core_find_mapping (
										scpu, map, vm_addr, nr_bytes, transfer,
										1 /*abort*/);
								return (void *)sim_core_translate(mapping, vm_addr);
							}

							case __NR_openat: {

								scpustateregs[1] = openat (
									(int)scpustateregs[1],
									(char *)get_host_addr(
										scpustateregs[2],
										PATH_MAX,
										read_map, read_transfer),
									(int)scpustateregs[3],
									(mode_t)scpustateregs[4]);

								break;
							}

							case __NR_close: {

								int fd = scpustateregs[1];

								// Do not allow closing stdin, stdout or stderr,
								// otherwise GDB hang or STANDALONE cannot restore the tty.
								if (fd <= PU32_RESERVED_FDS)
									scpustateregs[1] = 0;
								else
									scpustateregs[1] = close (fd);

								break;
							}

							case __NR_read: {

								int fd = scpustateregs[1];

								void *buf = (void *)get_host_addr (
									scpustateregs[2],
									scpustateregs[3],
									write_map, write_transfer);

								switch (fd) {
									case PU32_BIOS_FD_INTCTRLDEV:
										fd = intctrlpipe[coreid][0];
										break;
								}

								unsigned bsz = ((fd != PU32_BIOS_FD_STORAGEDEV) ? 1 : BLKSZ);

								scpustateregs[1] = (read (fd, buf, ((size_t)scpustateregs[3] * bsz)) / bsz);

								break;
							}

							case __NR_write: {

								int fd = scpustateregs[1];

								void *buf = (void *)get_host_addr (
									scpustateregs[2],
									scpustateregs[3],
									read_map, read_transfer);

								switch (fd) {

									case PU32_BIOS_FD_INTCTRLDEV: {

										uint32_t intrdst = *(uint32_t *)buf;

										if (intrdst >= corecnt)
											intrdst = -1;
										else { // Do work similar to intrthread(intrdst) to interrupt corethread(intrdst).
											intrpending[intrdst][INTRCTRL_PENDING_IDX] = 1;

											sim_cpu *scpu = STATE_CPU(sd, intrdst);
											pu32state *scpustate = scpu->state;

											if (haltedcore[intrdst]) {
												while (write (haltsyncpipe[intrdst][1], &((char){0}), 1) == -1) {
													if (errno == EINTR)
														continue;
													perror("write()");
													sim_io_eprintf (sd, "pu32-sim: write(haltsyncpipe[%u][1]) failed\n", intrdst);
													sim_engine_halt (
														sd, scpu, scpu,
														scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
														sim_stopped, SIM_SIGABRT);
												}
												while (haltedcore[intrdst]);
												while (write (haltsyncpipe[intrdst][1], &((char){0}), 1) == -1) {
													if (errno == EINTR)
														continue;
													perror("write()");
													sim_io_eprintf (sd, "pu32-sim: write(haltsyncpipe[%u][1]) failed\n", intrdst);
													sim_engine_halt (
														sd, scpu, scpu,
														scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)],
														sim_stopped, SIM_SIGABRT);
												}
											}
										}

										while ((scpustateregs[1] = write (intctrlpipe[coreid][1], &intrdst, sizeof(uint32_t))) == -1) {
											if (errno == EINTR)
												continue;
											perror("write()");
											sim_io_eprintf (sd, "pu32-sim: %s: write(intctrlpipe[%u][1]) failed\n",
												__FUNCTION__, coreid);
											sim_engine_halt (
												sd, scpu, scpu, scpustateregs[PU32_REG_PC],
												sim_stopped, SIM_SIGABRT);
										}

										break;
									}

									default: {

										unsigned bsz = ((fd != PU32_BIOS_FD_STORAGEDEV) ? 1 : BLKSZ);

										scpustateregs[1] = (write (fd, buf, ((size_t)scpustateregs[3] * bsz)) / bsz);

										fsync(fd);

										break;
									}
								}

								break;
							}

							case __NR_writev: {

								int iovcnt = scpustateregs[3];

								struct iovec {
									uint32_t *iov_base;
									uint32_t iov_len;
								} *iov = (void *)get_host_addr (
									scpustateregs[2],
									iovcnt*sizeof(struct iovec),
									read_map, read_transfer);

								int fd = scpustateregs[1];

								unsigned bsz = ((fd != PU32_BIOS_FD_STORAGEDEV) ? 1 : BLKSZ);

								ssize_t sz = 0;

								for (unsigned i = 0; i < iovcnt; ++i) {
									size_t iov_len = (iov[i].iov_len * bsz);
									ssize_t ret = (write (fd,
										(void *)get_host_addr (
											(address_word)(unsigned long)iov[i].iov_base,
											iov_len, read_map, read_transfer),
										iov_len) / bsz);
									if (ret == -1) {
										sz = ret;
										break;
									} else
										sz += ret;
								}

								scpustateregs[1] = sz;

								fsync(fd);

								break;
							}

							case __NR_lseek: {

								int fd = scpustateregs[1];

								unsigned bsz = ((fd != PU32_BIOS_FD_STORAGEDEV) ? 1 : BLKSZ);

								scpustateregs[1] = (lseek (
									(int)scpustateregs[1],
									((off_t)scpustateregs[2] * bsz),
									(int)scpustateregs[3]) / bsz);

								break;
							}

							case __NR_unlinkat: {

								scpustateregs[1] = unlinkat (
									(int)scpustateregs[1],
									(char *)(unsigned long)scpustateregs[2],
									(int)scpustateregs[3]);

								break;
							}

							case __NR_linkat: {

								scpustateregs[1] = linkat (
									(int)scpustateregs[1],
									(char *)(unsigned long)scpustateregs[2],
									(int)scpustateregs[3],
									(char *)(unsigned long)scpustateregs[4],
									(int)scpustateregs[5]);

								break;
							}

							case __NR_readlinkat: {

								scpustateregs[1] = readlinkat (
									(int)scpustateregs[1],
									(char *)(unsigned long)scpustateregs[2],
									(char *)(unsigned long)scpustateregs[3],
									(size_t)scpustateregs[4]);

								break;
							}

							case __NR_fstat64: {
								scpustateregs[1] = -1;
								break;
							}

							case __NR_getuid:
							case __NR_geteuid:
							case __NR_getgid:
							case __NR_getegid: {
								scpustateregs[1] = 1000;
								break;
							}

							case __NR_getpid: {
								scpustateregs[1] = coreid;
								break;
							}

							case __NR_kill: {
								// Do nothing, but in the future
								// could be used to shutdown a core.
								scpustateregs[1] = 0;
								break;
							}

							case __NR_brk: {

								static unsigned brkaddr = (PU32_INITIAL_STACK_TOP - PU32_INITIAL_HEAP_SIZE);

								if (!scpustateregs[1])
									scpustateregs[1] = brkaddr;
								else if (scpustateregs[1] > scpustateregs[0])
									scpustateregs[1] = 0;
								else {
									unsigned oldbrkaddr = brkaddr;
									brkaddr = scpustateregs[1];
									if (oldbrkaddr < brkaddr) {
										unsigned brksz = (brkaddr - oldbrkaddr);
										// GLIBC expects zeroed memory.
										memset (
											(void *)get_host_addr(
												oldbrkaddr, brksz,
												write_map, read_transfer),
											0,
											brksz);
									}
								}

								break;
							}

							case __NR_mmap2: {

								scpustateregs[1] = sim_core_map_memory (
									scpu,
									scpustateregs[1],
									scpustateregs[2],
									scpustateregs[5],
									scpustateregs[6]);

								break;
							}

							case __NR_chdir: {

								scpustateregs[1] = chdir (
									(char *)(unsigned long)scpustateregs[1]);

								break;
							}

							case __NR_fchmodat: {

								scpustateregs[1] = fchmodat (
									(int)scpustateregs[1],
									(char *)(unsigned long)scpustateregs[2],
									(mode_t)scpustateregs[3],
									(int)scpustateregs[4]);

								break;
							}

							case __NR_ioctl: {

								scpustateregs[1] = ioctl (
									(int)scpustateregs[1],
									scpustateregs[2],
									scpustateregs[3]);

								break;
							}

							static uint32_t tls = 0;

							case __NR_settls: {
								tls = scpustateregs[1];
								break;
							}

							case __NR_gettls: {
								scpustateregs[1] = tls;
								break;
							}

							default: {

								sim_io_eprintf (sd,
									"pu32-sim: unsupported syscall number: %u\n",
									scpustateregs[PU32_REG_SR]);

								sim_engine_halt (
									sd, scpu, scpu, scpustateregs[PU32_REG_PC],
									sim_stopped, SIM_SIGABRT);

								break;
							}
						}

						scpustateregs[PU32_REG_PC] += 2;

						break;
					}

					case 0x02: {
						// Specification from the
						// instruction set manual:
						// brk |0|010|0000|0000|
						// Software breakpoint instruction.

						if (coreid == 0) /* only core0 does this */
							sim_engine_halt (
								sd, scpu, scpu, scpustateregs[PU32_REG_PC+curctxgproffset],
								sim_stopped, SIM_SIGTRAP);
						else {
							brkcoreid = coreid;
							while (brkcoreid); // spinloop until core0 set it null.
						}

						break;
					}

					case 0x03: {
						// Specification from the
						// instruction set manual:
						// halt |0|011|0000|0000|

						scpustate->dohalt = (coreid != 0 /* only core0 is prevented */ || sim_open_kind == SIM_OPEN_STANDALONE);

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x04: {
						// Specification from the
						// instruction set manual:
						// icacherst |0|100|0000|0000|

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x05: {
						// Specification from the
						// instruction set manual:
						// dcacherst |0|101|0000|0000|

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x39: {
						// Specification from the
						// instruction set manual:
						// setksl %gpr |7|001|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[PU32_REG_KSL] = scpustateregs[gpr];

						scpustateregs[PU32_REG_PC] += 2;

						break;
					}

					case 0x3c: {
						// Specification from the
						// instruction set manual:
						// setasid %gpr |7|100|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[PU32_REG_ASID] = scpustateregs[gpr+curctxgproffset];

						pgds[coreid] = scpustateregs[PU32_REG_SR+curctxgproffset];

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x3d: {
						// Specification from the
						// instruction set manual:
						// setuip %gpr |7|101|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[PU32_REG_PC+PU32_GPRCNT] =
							(scpustateregs[gpr] & ~(uint32_t)1);

						scpustateregs[PU32_REG_PC] += 2;

						break;
					}

					case 0x3e: {
						// Specification from the
						// instruction set manual:
						// setflags %gpr |7|110|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[PU32_REG_FLAGS] =
							scpustateregs[gpr+curctxgproffset];

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x3f: {
						// Specification from the
						// instruction set manual:
						// settimer %gpr |7|111|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[PU32_REG_TIMER] = scpustateregs[gpr+curctxgproffset];

						if (scpustateregs[PU32_REG_TIMER] != (uint32_t)-1) {
							if (scpustate->curctx)
								// Must be done after setting scpustateregs[PU32_REG_TIMER].
								do_resettimer();
							else
								scpustate->resettimer = 1;
						}

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x3a: {
						// Specification from the
						// instruction set manual:
						// settlb %gpr1, %gpr2 |7|010|rrrr|rrrr|

						unsigned gpr1 = (inst1 >> 4);
						unsigned gpr2 = (inst1 & 0xf);

						uint32_t d1 = scpustateregs[gpr1+curctxgproffset];
						uint32_t d2 = scpustateregs[gpr2+curctxgproffset];

						if (d1 & 1)
							scpustateitlb[(d2 >> PAGE_SHIFT) & (PU32_TLBSZ - 1)] =
								((pu32tlbentry){.d1 = d1, .d2 = d2});

						if (d1 & 0b110)
							scpustatedtlb[(d2 >> PAGE_SHIFT) & (PU32_TLBSZ - 1)] =
								((pu32tlbentry){.d1 = d1, .d2 = d2});

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x3b: {
						// Specification from the
						// instruction set manual:
						// clrtlb %gpr1, %gpr2 |7|011|rrrr|rrrr|

						unsigned gpr1 = (inst1 >> 4);
						unsigned gpr2 = (inst1 & 0xf);

						uint32_t scpustateregsgpr1 = scpustateregs[gpr1+curctxgproffset];
						uint32_t scpustateregsgpr2 = scpustateregs[gpr2+curctxgproffset];

						uint32_t vpn = (scpustateregsgpr2 >> PAGE_SHIFT);

						pu32tlbentry *itlbentry = &scpustateitlb[vpn & (PU32_TLBSZ - 1)];
						if (!((itlbentry->d2 ^ scpustateregsgpr2) & scpustateregsgpr1))
							*itlbentry = ((pu32tlbentry){.d1 = 0, .d2 = 0});

						pu32tlbentry *dtlbentry = &scpustatedtlb[vpn & (PU32_TLBSZ - 1)];
						if (!((dtlbentry->d2 ^ scpustateregsgpr2) & scpustateregsgpr1))
							*dtlbentry = ((pu32tlbentry){.d1 = 0, .d2 = 0});

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x79: {
						// Specification from the
						// instruction set manual:
						// setkgpr %gpr1 %gpr2 |15|001|rrrr|rrrr|

						unsigned gpr1 = (inst1 >> 4);
						unsigned gpr2 = (inst1 & 0xf);

						scpustateregs[gpr1] = scpustateregs[gpr2+PU32_GPRCNT];

						scpustateregs[PU32_REG_PC] += 2;

						break;
					}

					case 0x7a: {
						// Specification from the
						// instruction set manual:
						// setugpr %gpr1 %gpr2 |15|010|rrrr|rrrr|

						unsigned gpr1 = (inst1 >> 4);
						unsigned gpr2 = (inst1 & 0xf);

						scpustateregs[gpr1+PU32_GPRCNT] = scpustateregs[gpr2];

						scpustateregs[PU32_REG_PC] += 2;

						break;
					}

					case 0x7b: {
						// Specification from the
						// instruction set manual:
						// setgpr %gpr1 %gpr2 |15|011|rrrr|rrrr|

						unsigned gpr1 = (inst1 >> 4);
						unsigned gpr2 = (inst1 & 0xf);

						scpustateregs[gpr1+PU32_GPRCNT] = scpustateregs[gpr2+PU32_GPRCNT];

						scpustateregs[PU32_REG_PC] += 2;

						break;
					}

					case 0x28: {
						// Specification from the
						// instruction set manual:
						// getsysopcode %gpr |5|000|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr] = scpustateregs[PU32_REG_SYSOPCODE];

						scpustateregs[PU32_REG_PC] += 2;

						break;
					}

					case 0x29: {
						// Specification from the
						// instruction set manual:
						// getuip %gpr |5|001|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr] = scpustateregs[PU32_REG_PC+PU32_GPRCNT];

						scpustateregs[PU32_REG_PC] += 2;

						break;
					}

					case 0x2a: {
						// Specification from the
						// instruction set manual:
						// getfaultaddr %gpr |5|010|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr] = scpustateregs[PU32_REG_FAULTADDR];

						scpustateregs[PU32_REG_PC] += 2;

						break;
					}

					case 0x2b: {
						// Specification from the
						// instruction set manual:
						// getfaultreason %gpr |5|011|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr] = scpustateregs[PU32_REG_FAULTREASON];

						scpustateregs[PU32_REG_PC] += 2;

						break;
					}

					uint64_t getclkcyclecnt (void) {
						struct timespec t;
						if (clock_gettime(CLOCK_BOOTTIME, &t) == -1) {
							sim_io_eprintf (sd, "pu32-sim: clock_gettime() failed\n");
							sim_engine_halt (
								sd, scpu, scpu, scpustateregs[PU32_REG_PC+curctxgproffset],
								sim_stopped, SIM_SIGABRT);
							return ((uint64_t){0});
						}
						struct timespec timespecsub (struct timespec t1, struct timespec t2) {
								struct timespec r;
								r.tv_sec = (t1.tv_sec - t2.tv_sec);
								r.tv_nsec = (t1.tv_nsec - t2.tv_nsec);
								if (t1.tv_sec < t2.tv_sec)
										r.tv_sec = -r.tv_sec;
								if (t1.tv_nsec < t2.tv_nsec) {
										// Borrow a second.
										--r.tv_sec;
										r.tv_nsec += 1000000000;
								}
								return r;
						}
						t = timespecsub (t, scpustate->stime);
						return (((uint64_t)t.tv_nsec + ((uint64_t)t.tv_sec*1000000000)) / scpustate->clkperiod);
					}

					case 0x2c: {
						// Specification from the
						// instruction set manual:
						// getclkcyclecnt %gpr |5|100|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr+curctxgproffset] = getclkcyclecnt();

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x2d: {
						// Specification from the
						// instruction set manual:
						// getclkcyclecnth %gpr |5|101|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr+curctxgproffset] = (getclkcyclecnt() >> 32);

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x2e: {
						// Specification from the
						// instruction set manual:
						// gettlbsize %gpr |5|110|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr+curctxgproffset] = PU32_TLBSZ;

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x2f: {
						// Specification from the
						// instruction set manual:
						// geticachesize %gpr |5|111|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr+curctxgproffset] = PU32_ICACHESETCOUNT;

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x10: {
						// Specification from the
						// instruction set manual:
						// getcoreid %gpr |2|000|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr+curctxgproffset] = coreid;

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x11: {
						// Specification from the
						// instruction set manual:
						// getclkfreq %gpr |2|001|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustate->clkperiod = getclkperiod(coreid); // Update nanoseconds/clockcycle.

						scpustateregs[gpr+curctxgproffset] = (1000000000 / scpustate->clkperiod);

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x12: {
						// Specification from the
						// instruction set manual:
						// getdcachesize %gpr |2|010|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr+curctxgproffset] = PU32_DCACHESETCOUNT;

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x13: {
						// Specification from the
						// instruction set manual:
						// gettlb %gpr1, %gpr2 |2|011|rrrr|rrrr|

						unsigned gpr1 = (inst1 >> 4);
						unsigned gpr2 = (inst1 & 0xf);

						uint32_t scpustateregsgpr2 = scpustateregs[gpr2+curctxgproffset];

						uint32_t vpn = (scpustateregsgpr2 >> PAGE_SHIFT);
						uint32_t asid = (scpustateregsgpr2 & ~PAGE_MASK);

						pu32tlbentry *itlbentry = &scpustateitlb[vpn & (PU32_TLBSZ - 1)];
						uint32_t id1 =
							((asid == itlbentry->asid) && (vpn == itlbentry->vpn)) ?
								itlbentry->d1 : 0;

						pu32tlbentry *dtlbentry = &scpustatedtlb[vpn & (PU32_TLBSZ - 1)];
						uint32_t dd1 =
							((asid == dtlbentry->asid) && (vpn == dtlbentry->vpn)) ?
								dtlbentry->d1 : 0;

						if (!id1 ^ !dd1)
							scpustateregs[gpr1+curctxgproffset] = (id1 ?: dd1);
						else if ((id1 >> PAGE_SHIFT) == (dd1 >> PAGE_SHIFT))
							scpustateregs[gpr1+curctxgproffset] = (id1 | dd1);
						else
							scpustateregs[gpr1+curctxgproffset] = 0;

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x14: {
						// Specification from the
						// instruction set manual:
						// getcap %gpr |2|100|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr+curctxgproffset] = PU32_CAP;

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					case 0x15: {
						// Specification from the
						// instruction set manual:
						// getver %gpr |2|101|rrrr|0000|

						unsigned gpr = (inst1 >> 4);

						scpustateregs[gpr+curctxgproffset] = PU32_VER;

						scpustateregs[PU32_REG_PC+curctxgproffset] += 2;

						break;
					}

					default: {

						sim_io_eprintf (sd,
							"pu32-sim: unsupported instruction 0x%02x 0x%02x @ 0x%x\n",
								inst0, inst1, scpustateregs[PU32_REG_PC+curctxgproffset]);

						sim_engine_halt (
							sd, scpu, scpu, scpustateregs[PU32_REG_PC+curctxgproffset],
							sim_stopped, SIM_SIGABRT);

						break;
					}
				}
			}
		}

		sim_engine_run_loopbottom:;

		if (coreid == 0 /* only core0 does this */ && sim_open_kind == SIM_OPEN_DEBUG) {
			if (brkcoreid) {
				sim_cpu *scpu = STATE_CPU(sd, brkcoreid);
				pu32state *scpustate = scpu->state;
				volatile uint32_t *scpustateregs = scpustate->regs;
				unsigned curctxgproffset = (scpustate->curctx*PU32_GPRCNT);
				sim_engine_halt (
					sd, scpu, scpu, scpustateregs[PU32_REG_PC+curctxgproffset],
					sim_stopped, SIM_SIGTRAP);
				brkcoreid = 0;
			} else {
				if (sim_events_tick(sd)) {
					pu32_cpu_exception_suspend (sd, scpu, 0);
					sim_events_process(sd);
					pu32_cpu_exception_resume (sd, scpu, 0);
				}
			}
		}
	}
}

static void corethread (unsigned coreid) {
	sim_engine_run (((SIM_DESC){0}), coreid, ((int){0}), ((int){0}));
}

int sim_read (
	SIM_DESC _ /* ignore */,
	SIM_ADDR x,
	unsigned char *buf,
	int len) {
	#if defined(PU32_DEBUG)
	sim_io_eprintf (sd,
		"pu32-sim: %s: vaddr == 0x%x; len == %u",
		__FUNCTION__, x, len);
	#endif
	sim_cpu *scpu = STATE_CPU (sd, 0 /*coreid*/);
	pu32state *scpustate = scpu->state;
	if (scpustate->curctx) {
		uint32_t *scpustateregs = scpustate->regs;
		// Translate as possible regardless of
		// whether in userspace or kernelspace.
		if (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL]) {
			uint32_t d1 = walk_page_table (x, 0 /*coreid*/);
			if (d1)
				x = ((d1 & PAGE_MASK) | (x & ~PAGE_MASK));
			else {
				#if defined(PU32_DEBUG)
				sim_io_eprintf (sd, "; no paddr\n", x);
				#endif
				return 0;
			}
		}
	}
	if (!(x >= PU32_MEM_START && x < PU32_MEM_END))
		return 0;
	#if defined(PU32_DEBUG)
	sim_io_eprintf (sd, "; paddr == 0x%x\n", x);
	#endif
	unsigned count; for (count = 0; count < len; ++count) {
		address_word raddr = x + count;
		sim_core_mapping *mapping =
			sim_core_find_mapping (
				scpu, read_map, raddr, 1, read_transfer,
				0 /*dont-abort*/);
		buf[count] = *(uint8_t *)sim_core_translate(mapping, raddr);
	}
	return count;
}

int sim_write (
	SIM_DESC _ /* ignore */,
	SIM_ADDR x,
	const unsigned char *buf,
	int len) {
	#if defined(PU32_DEBUG)
	sim_io_eprintf (sd,
		"pu32-sim: %s: vaddr == 0x%x; len == %u",
		__FUNCTION__, x, len);
	#endif
	sim_cpu *scpu = STATE_CPU (sd, 0 /*coreid*/);
	pu32state *scpustate = scpu->state;
	if (scpustate->curctx) {
		uint32_t *scpustateregs = scpustate->regs;
		// Translate as possible regardless of
		// whether in userspace or kernelspace.
		if (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL]) {
			uint32_t d1 = walk_page_table (x, 0 /*coreid*/);
			if (d1)
				x = ((d1 & PAGE_MASK) | (x & ~PAGE_MASK));
			else {
				#if defined(PU32_DEBUG)
				sim_io_eprintf (sd, "; no paddr\n", x);
				#endif
				return 0;
			}
		}
	}
	if (!(x >= PU32_MEM_START && x < PU32_MEM_END))
		return 0;
	#if defined(PU32_DEBUG)
	sim_io_eprintf (sd, "; paddr == 0x%x\n", x);
	#endif
	unsigned count; for (count = 0; count < len; ++count) {
		address_word waddr = x + count;
		sim_core_mapping *mapping =
			sim_core_find_mapping (
				scpu, write_map, waddr, 1, write_transfer,
				0 /*dont-abort*/);
		*(uint8_t *)sim_core_translate(mapping, waddr) = buf[count];
	}
	return count;
}

static char* hdd = NULL;

static DECLARE_OPTION_HANDLER (pu32_option_handler);

enum {
	OPTION_HDD = OPTION_START,
	OPTION_CORECNT,
};

static SIM_RC pu32_option_handler (
	SIM_DESC _ /* ignore */,
	sim_cpu *cpu, int opt, char *arg, int is_command) {
	switch (opt) {
		case OPTION_HDD:
			if (arg) {
				hdd = zalloc(strlen(arg)+1);
				strcpy(hdd, arg);
			}
			return SIM_RC_OK;
		case OPTION_CORECNT:
			if (arg) {
				errno = 0; /* To distinguish success/failure after call */
				corecnt = strtol(arg, 0, 0);
				if (errno != 0) {
					perror("strtol");
					return SIM_RC_FAIL;
				}
				if (!corecnt || corecnt > PU32_CPUCNT) {
					fprintf(stderr, "invalid number of cores\n");
					return SIM_RC_FAIL;
				}
			}
			return SIM_RC_OK;
	}
	return SIM_RC_OK;
}

static const OPTION pu32_options[] = {
	{{"hdd", required_argument, NULL, OPTION_HDD},
		'\0', "FILEPATH", "Hard disk drive file path", pu32_option_handler },
	{{"corecnt", required_argument, NULL, OPTION_CORECNT},
		'\0', "CORECNT", "Number of cores", pu32_option_handler },
	{{NULL, no_argument, NULL, 0}, '\0', NULL, NULL, NULL }
};

SIM_DESC sim_open (
	SIM_OPEN_KIND kind,
	host_callback *cb,
	struct bfd *abfd,
	char * const *argv) {

	#if defined(PU32_DEBUG)
	printf ("pu32-sim: %s\n", __FUNCTION__);
	#endif

	// PU32_TLBSZ must be a powerof2,
	// as the instruction gettlbsize must
	// return a powerof2 value.
	SIM_ASSERT(__builtin_popcount(PU32_TLBSZ) == 1);
	// An interrupt-id must be <= 255 as it is expected by restart_intrfds_poll().
	SIM_ASSERT ((unsigned)POLL_NFDS <= 255);

	if (sd)
		return SIM_RC_FAIL;

	sd = sim_state_alloc (kind, cb);
	SIM_ASSERT(STATE_MAGIC(sd) == SIM_MAGIC_NUMBER);

	// Set default options before parsing user options.
	current_target_byte_order = BFD_ENDIAN_LITTLE;

	void free_state (void) {
		if (STATE_MODULES (sd) != NULL)
			sim_module_uninstall (sd);
		sim_cpu_free_all (sd);
		sim_state_free (sd);
	}

	// The cpu data is kept in a separately allocated chunk of memory.
	// sim_cpu_alloc_all() needs to be called before sim_pre_argv_init().
	if (sim_cpu_alloc_all (sd, PU32_CPUCNT) != SIM_RC_OK) {
		free_state();
		return SIM_RC_FAIL;
	}

	if (sim_pre_argv_init (sd, argv[0]) != SIM_RC_OK) {
		free_state();
		return SIM_RC_FAIL;
	}

	sim_add_option_table (sd, NULL, pu32_options);

	// The parser will print an error message
	// for us, so we silently return.
	if (sim_parse_args (sd, argv) != SIM_RC_OK) {
		free_state();
		return SIM_RC_FAIL;
	}

	// Configure/verify the target byte order
	// and other runtime configuration options.
	if (sim_config (sd) != SIM_RC_OK) {
		free_state();
		return SIM_RC_FAIL;
	}

	if (sim_post_argv_init (sd) != SIM_RC_OK) {
		free_state();
		return SIM_RC_FAIL;
	}

	sim_open_kind = kind;

	if (sim_open_kind == SIM_OPEN_STANDALONE) {
		// When (sim_open_kind == SIM_OPEN_DEBUG),
		// _initialize_pu32_tdep() has already done this.
		int devnullfd = open("/dev/null", O_RDWR);
		if (devnullfd == -1) {
			sim_io_eprintf(sd,
				"pu32-gdb: %s: open(\"/dev/null\") failed\n",
				__FUNCTION__);
			return SIM_RC_FAIL;
		}
		for (unsigned i = 3; i < PU32_RESERVED_FDS; ++i) {
			if (dup2(devnullfd, i) == -1) {
				sim_io_eprintf(sd,
					"pu32-gdb: %s: dup2(devnullfd, %u) failed\n",
					__FUNCTION__, i);
				return SIM_RC_FAIL;
			}
		}
	}

	if (isatty(STDOUT_FILENO)) {
		// Discard any data currently buffered in STDIN.
		tcflush(STDIN_FILENO, TCIFLUSH);
		// Retrieve the current STDOUT config.
		if (tcgetattr(STDOUT_FILENO, &ttyconfig) == 0) {
			// Save the current STDOUT config.
			savedttyconfig = ttyconfig;
			if (sim_open_kind == SIM_OPEN_STANDALONE) {
				cfmakeraw(&ttyconfig);
				ttyconfig.c_oflag |= (/*ONLCR | ONLRET |*/ OPOST);
			} else
				ttyconfig.c_lflag &= ~(ICANON | ECHO | ECHOE);
			ttyconfig.c_cc[VMIN] = 1;
			ttyconfig.c_cc[VTIME] = 0;
			void ttyrestore (void) {
				tcsetattr(STDOUT_FILENO, TCSAFLUSH, &savedttyconfig);
			}
			atexit(ttyrestore);
		} else {
			sim_io_eprintf(sd,
				"pu32-sim: %s: retrieving STDOUT config failed\n",
				__FUNCTION__);
			return SIM_RC_FAIL;
		}
	}
	if (dup2(STDIN_FILENO, STDIN_DUP_FILENO) == -1) {
		sim_io_eprintf(sd,
			"pu32-sim: %s: dup2(STDIN_FILENO, STDIN_DUP_FILENO) failed\n",
			__FUNCTION__);
		return SIM_RC_FAIL;
	}
	if (pipe((int *)stdinpipe) == -1) {
		sim_io_eprintf(sd,
			"pu32-sim: %s: pipe(stdinpipe) failed\n",
			__FUNCTION__);
		return SIM_RC_FAIL;
	}
	if ((stdinpipe[0] = dup2(stdinpipe[0], PU32_BIOS_FD_STDIN)) != PU32_BIOS_FD_STDIN) {
		sim_io_eprintf(sd,
			"pu32-sim: %s: dup2(stdinpipe[0], PU32_BIOS_FD_STDIN) failed\n",
			__FUNCTION__);
		return SIM_RC_FAIL;
	}
	fcntl(stdinpipe[0], F_SETFL, fcntl(stdinpipe[0], F_GETFL) | O_NONBLOCK);
	fcntl(stdinpipe[1], F_SETFL, fcntl(stdinpipe[1], F_GETFL) | O_NONBLOCK);
	for (unsigned i = 0; i < corecnt; ++i) {
		if (pipe((int *)intctrlpipe[i]) == -1) {
			sim_io_eprintf(sd,
				"pu32-sim: %s: pipe(intctrlpipe[%u) failed\n",
				__FUNCTION__, i);
			return SIM_RC_FAIL;
		}
		fcntl(intctrlpipe[i][0], F_SETFL, fcntl(intctrlpipe[i][0], F_GETFL) | O_NONBLOCK);
		if (pipe((int *)intrsyncpipe[i]) == -1) {
			sim_io_eprintf(sd,
				"pu32-sim: %s: pipe(intrsyncpipe[%u]) failed\n",
				__FUNCTION__, i);
			return SIM_RC_FAIL;
		}
		if (pipe((int *)haltsyncpipe[i]) == -1) {
			sim_io_eprintf(sd,
				"pu32-sim: %s: pipe(haltsyncpipe[%u]) failed\n",
				__FUNCTION__, i);
			return SIM_RC_FAIL;
		}
		int fd = timerfd_create(CLOCK_BOOTTIME, 0);
		if (fd == -1) {
			perror("timerfd_create()");
			sim_io_eprintf(sd,
				"pu32-sim: %s: timerfd_create(timerfd[%u]) failed\n",
				__FUNCTION__, i);
			return SIM_RC_FAIL;
		}
		timerfd[i] = -fd; // Negate to disable it as part of intrfds[].
	}

	sim_core_map_memory (
		STATE_CPU (sd, 0),
		PU32_MEM_START,
		PU32_MEM_SIZE,
		-1, 0);

	if (hdd) { // Must be checked after arguments have been parsed.
		int fd = open (hdd, O_RDWR|O_NONBLOCK);
		if (fd == -1) {
			sim_io_eprintf(sd,
				"pu32-sim: %s: open(\"%s\") failed\n",
				__FUNCTION__, hdd);
			free_state();
			return SIM_RC_FAIL;
		}
		if (dup2(fd, PU32_BIOS_FD_STORAGEDEV) == -1) {
			sim_io_eprintf(sd,
				"pu32-sim: %s: dup2(%u, PU32_BIOS_FD_STORAGEDEV) failed\n",
				__FUNCTION__, fd);
			free_state();
			return SIM_RC_FAIL;
		}
	}

	pu32state *states = mmap (0,
		ROUNDUPTOPOWEROFTWO(sizeof(pu32state)*corecnt, 0x1000),
		PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS|MAP_UNINITIALIZED,
		0, 0);
	if (states == MAP_FAILED) {
		free_state();
		return SIM_RC_FAIL;
	}

	// CPU specific initialization.
	for (unsigned i = 0; i < corecnt; ++i) {

		int pu32_reg_fetch (
			sim_cpu *scpu,
			int regno,
			void *mem,
			int length) {

			unsigned char *buf = mem;

			if ((unsigned int)regno < PU32_REGCNT) {

				pu32state *scpustate = scpu->state;

				regno += (scpustate->curctx*PU32_GPRCNT);

				uint32_t val = scpustate->regs[regno];

				if (length == 1) {

					buf[0] = val;

				} else if (length == 2) {

					buf[0] = val;
					buf[1] = val >> 8;

				} else if (length == 4) {

					buf[0] = val;
					buf[1] = val >> 8;
					buf[2] = val >> 16;
					buf[3] = val >> 24;

				} else return 0;

				return length;

			} else return 0;
		}

		int pu32_reg_store (
			sim_cpu *scpu,
			int regno,
			const void *mem,
			int length) {

			const unsigned char *buf = mem;

			if ((unsigned int)regno < PU32_REGCNT) {

				pu32state *scpustate = scpu->state;

				regno += (scpustate->curctx*PU32_GPRCNT);

				if (length == 1) {

					scpustate->regs[regno] = buf[0];

				} else if (length == 2) {

					scpustate->regs[regno] = ((buf[1] << 8) + buf[0]);

				} else if (length == 4) {

					scpustate->regs[regno] = (
						(buf[3] << 24) + (buf[2] << 16) +
						(buf[1] << 8) + buf[0]);

				} else return 0;

				return length;

			} else return 0;
		}

		sim_cia pu32_pc_get (sim_cpu *scpu) {

			pu32state *scpustate = scpu->state;

			sim_cia pc = scpustate->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)];

			return pc;
		}

		void pu32_pc_set (sim_cpu *scpu, sim_cia pc) {

			pu32state *scpustate = scpu->state;

			scpustate->regs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)] = pc;
		}

		sim_cpu *scpu = STATE_CPU (sd, i);

		CPU_REG_FETCH(scpu) = pu32_reg_fetch;
		CPU_REG_STORE(scpu) = pu32_reg_store;
		CPU_PC_FETCH(scpu) = pu32_pc_get;
		CPU_PC_STORE(scpu) = pu32_pc_set;

		scpu->coreid = i;
		scpu->state = &states[i];
	}

	for (unsigned long i = 0; i < corecnt; ++i) {
		// Allocate memory to be used for the stack of intrthread(i).
		void *stack = mmap (
			0, PU32_INTRCHECK_STACK_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
			-1, 0);
		if (stack == MAP_FAILED) {
			sim_io_eprintf (sd, "pu32-sim: %s: mmap(intrthread_stack) failed\n", __FUNCTION__);
			free_state();
			return SIM_RC_FAIL;
		}
		intrthread_stack[i] = stack;
		// Allocate memory to be used for the stack of corethread(i).
		stack = mmap (
			0, PU32_CORETHREAD_STACK_SIZE, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
			-1, 0);
		if (stack == MAP_FAILED) {
			sim_io_eprintf (sd, "pu32-sim: %s: mmap(corethread_stack) failed\n", __FUNCTION__);
			free_state();
			return SIM_RC_FAIL;
		}
		corethread_stack[i] = stack;
	}

	corethreadid[0] = 0;

	return sd;
}

static bfd *pu32_sim_load_file (
	SIM_DESC sd,
	const char *myname,
	const char *prog_name,
	bfd *prog_bfd,
	int verbose_p,
	int lma_p,
	sim_write_fn do_write) {

	/* Record separately as we don't want to close PROG_BFD if it was passed.  */
	bfd *result_bfd;

	if (prog_bfd != NULL)
		result_bfd = prog_bfd;
	else {
		result_bfd = bfd_openr (prog_name, 0);
		if (result_bfd == NULL) {
			sim_io_eprintf (sd, "%s: can't open \"%s\": %s\n",
				myname, prog_name, bfd_errmsg (bfd_get_error ()));
			return NULL;
		}
	}

	if (!bfd_check_format (result_bfd, bfd_object)) {
		sim_io_eprintf (sd, "%s: \"%s\" is not an object file: %s\n",
			myname, prog_name, bfd_errmsg (bfd_get_error ()));
		if (prog_bfd == NULL)
			bfd_close (result_bfd);
		return NULL;
	}

	time_t start_time = 0;

	if (verbose_p)
		start_time = time (NULL);

	int found_loadable_phdr = 0;

	long sizeof_phdrs = bfd_get_elf_phdr_upper_bound (prog_bfd);
	if (sizeof_phdrs == 0) {
		sim_io_eprintf (sd, "%s: Failed to get size of program headers\n", myname);
		return NULL;
	}

	Elf_Internal_Phdr *phdrs = malloc (sizeof_phdrs);
	int num_headers = bfd_get_elf_phdrs (prog_bfd, phdrs);

	if (num_headers < 1) {
		sim_io_eprintf (sd, "%s: Failed to read program headers\n", myname);
		return NULL;
	}

	unsigned long data_count = 0;

	for (unsigned i = 0; i < num_headers; ++i) {

		Elf_Internal_Phdr *p = phdrs + i;

		if (p->p_type != PT_LOAD)
			continue;

		bfd_vma size = p->p_filesz;
		if (size <= 0)
			continue;

		bfd_vma base = p->p_paddr;
		if (verbose_p)
			sim_io_printf (sd,
				"Program header: size %#lx lma %08lx vma %08lx\n",
				size, base, p->p_vaddr);

		unsigned char *buf = malloc (size);

		file_ptr offset = p->p_offset;
		if (bfd_seek (prog_bfd, offset, SEEK_SET) != 0) {
			sim_io_eprintf (sd, "%s, Failed to seek to offset %lx\n", myname, (long)offset);
			continue;
		}

		if (bfd_bread (buf, size, prog_bfd) != size) {
			sim_io_eprintf (sd, "%s: Failed to read %lx bytes\n", myname, size);
			continue;
		}

		do_write (sd, base, buf, size);

		data_count += size;

		found_loadable_phdr = 1;

		free (buf);
	}

	free (phdrs);

	if (!found_loadable_phdr) {
		sim_io_eprintf (sd, "%s: no program headers \"%s\"\n", myname, prog_name);
		return NULL;
	}

	if (verbose_p) {
		time_t end_time = time (NULL);
		sim_io_printf (sd, "Start address: %lx\n", bfd_get_start_address (result_bfd));
		if (end_time != start_time)
			sim_io_printf (sd,
				"Transfer rate: %ld bytes/sec\n",
				data_count / (end_time - start_time));
		else
			sim_io_printf (sd,
				"Transfer rate: %ld bytes in <1 sec\n",
				data_count);
	}

	bfd_cache_close (result_bfd);

	return result_bfd;
}

SIM_RC sim_load (
	SIM_DESC sd,
	const char *prog_name,
	struct bfd *prog_bfd,
	int from_tty) {
	bfd *result_bfd;
	SIM_ASSERT (STATE_MAGIC (sd) == SIM_MAGIC_NUMBER);
	if (sim_analyze_program (sd, prog_name, prog_bfd) != SIM_RC_OK)
		return SIM_RC_FAIL;
	SIM_ASSERT (STATE_PROG_BFD (sd) != NULL);
	result_bfd = pu32_sim_load_file (sd,
				STATE_MY_NAME (sd),
				prog_name,
				STATE_PROG_BFD (sd),
				STATE_OPEN_KIND (sd) == SIM_OPEN_DEBUG,
				STATE_LOAD_AT_LMA_P (sd),
				sim_write);
	if (result_bfd == NULL) {
		bfd_close (STATE_PROG_BFD (sd));
		STATE_PROG_BFD (sd) = NULL;
		return SIM_RC_FAIL;
	}
	// Generated from: pu32-elf-objdump -Sdrl /opt/pu32-toolchain/lib/socbios.elf
	char parkpu_instr[] = {
		'\xa9', '\xd0', '\x00', '\x20', // li16 %sr, 0x2000 # 8192
		'\x3e', '\xd0',                 // setflags %sr
		'\x03', '\x00',                 // halt
		'\x00', '\x00',                 // sysret
		'\x04', '\x00',                 // icacherst
		'\xad', '\xd0', '\xf6', '\xff', // rli16 %sr, -10 # 0xfffffff6
		'\xd1', '\xdd'                  // j %sr
	};
	sim_cpu *scpu = STATE_CPU(sd, 0);
	sim_core_write_buffer ( // Install parkpu().
		sd, scpu, write_map,
		parkpu_instr, PARKPU_ADDR, sizeof(parkpu_instr));
	return SIM_RC_OK;
}

SIM_RC sim_create_inferior (
	SIM_DESC sd,
	struct bfd *abfd,
	char * const *argv,
	char * const *env) {

	#if defined(PU32_DEBUG)
	printf ("pu32-sim: %s\n", __FUNCTION__);
	#endif

	if (corethreadid[0]) {
		// I get here if all intrthread() and corethread() were already created.
		// I halt non-zero cores.
		for (unsigned i = 1; i < corecnt; ++i) {
			pu32state *scpustate = STATE_CPU(sd, i)->state;
			while (!haltedcore[i]) {
				scpustate->curctx = 1;
				clraddrtranslcache[i]._ = -1;
				scpustate->resettimer = 1;
				scpustate->dohalt = 1;
				uint32_t *scpustateregs = scpustate->regs;
				scpustateregs[PU32_REG_PC] = PARKPU_RESUME_ADDR;
				scpustateregs[PU32_REG_FLAGS] = PU32_FLAGS_disTimerIntr;
				scpustateregs[PU32_REG_KSL] = PU32_KERNELSPACE_START;
			}
		}

	} else for (unsigned long i = 0; i < corecnt; ++i) {
		intrpending[i][0] = -1; // Using intrpending[i][0] to wait until intrthread(i) has initialized.
		int tid = clone ((int(*)(void *))intrthread,
			(void *)((unsigned long)intrthread_stack[i] + PU32_INTRCHECK_STACK_SIZE),
			CLONE_FILES | CLONE_FS | CLONE_IO |
			CLONE_SIGHAND | CLONE_VM | CLONE_THREAD, (void *)i);
		if (tid == -1) {
			sim_io_eprintf (sd, "pu32-sim: %s: clone(intrthread) failed\n", __FUNCTION__);
			return SIM_RC_FAIL;
		}
		intrthreadid[i] = tid;
		while (intrpending[i][0]); // Wait until intrthread(i) has initialized.
		if (i == 0) {
			corethreadid[0] = getpid(); // Get thread group ID.
			continue;
		}
		pu32state *scpustate = STATE_CPU(sd, i)->state;
		scpustate->curctx = 1;
		clraddrtranslcache[i]._ = -1;
		scpustate->resettimer = 1;
		scpustate->dohalt = 1;
		uint32_t *scpustateregs = scpustate->regs;
		scpustateregs[PU32_REG_PC] = PARKPU_RESUME_ADDR;
		scpustateregs[PU32_REG_FLAGS] = PU32_FLAGS_disTimerIntr;
		scpustateregs[PU32_REG_KSL] = PU32_KERNELSPACE_START;
		tid = clone ((int(*)(void *))corethread,
			(void *)((unsigned long)corethread_stack[i] + PU32_CORETHREAD_STACK_SIZE),
			CLONE_FILES | CLONE_FS | CLONE_IO |
			CLONE_SIGHAND | CLONE_VM | CLONE_THREAD, (void *)i);
		if (tid == -1) {
			sim_io_eprintf (sd, "pu32-sim: %s: clone(corethread) failed\n", __FUNCTION__);
			return SIM_RC_FAIL;
		}
		corethreadid[i] = tid;
	}

	sim_cpu *scpu = STATE_CPU(sd, 0);

	// Write 4 bytes data to memory.
	INLINE void st32at (uint32_t x, uint32_t v) {
		if (x&0b11)
			sim_engine_halt (sd, scpu, scpu, 0, sim_stopped, SIM_SIGBUS);
		sim_core_mapping *mapping =
			sim_core_find_mapping (
				scpu, write_map, x, 4, write_transfer,
				1 /*abort*/);
		*(uint32_t *)sim_core_translate(mapping, x) = v;
	}

	// Initialize target memory as follow in
	// the similar manner it is done by Linux:
	// - argc
	// - null-terminated argv pointers array.
	// - null-terminated envp pointers array.
	// - AT_NULL auxv vector.
	// - argv null-terminated strings.
	// - envp null-terminated strings.

	unsigned n = 0;
	while (argv[n])
		++n;
	n += 1;

	char *envp[] = {
		"MEMSTARTADDR="stringify(PU32_MEM_START),
		#if PU32_MEM_END == 0x78000000
		"MEMENDADDR="stringify(0x78000000),
		#else
		#error PU32_MEM_END was updated
		#endif
		0 };

	n += (sizeof(envp)/sizeof(char *));

	// Copied from glibc's elf.h .
	typedef struct {
		uint32_t a_type; // Entry type.
		union {
			uint32_t a_val; // Integer value.
		} a_un;
	} Elf32_auxv_t;

	n += (sizeof(Elf32_auxv_t)/sizeof(uint32_t));

	unsigned tp = (PU32_ARG_REGION_ADDR + (n * sizeof(uint32_t)));

	char *p;
	unsigned i;

	for (i = 0; (p = argv[i]); ++i) {

		unsigned len = strlen(p) + 1;

		if ((unsigned)(PU32_ARG_REGION_SIZE - ((tp + len) - PU32_ARG_REGION_ADDR)) >
			(unsigned)PU32_ARG_REGION_SIZE) {
			sim_io_eprintf (sd,
				"pu32-sim: %s: arg-region overflow\n",
				__FUNCTION__);
			return SIM_RC_FAIL;
		}

		// Set the argv value.
		st32at (PU32_ARG_REGION_ADDR + (i * sizeof(uint32_t)), tp);

		// Store the string.
		sim_core_write_buffer (
			sd, scpu, write_map,
			p, tp, len);

		tp += len;
	}

	st32at (PU32_ARG_REGION_ADDR + (i * sizeof(uint32_t)), 0);

	unsigned j = (i + 1);

	for (i = 0; (p = envp[i]); ++i) {

		unsigned len = strlen(p) + 1;

		if ((unsigned)(PU32_ARG_REGION_SIZE - ((tp + len) - PU32_ARG_REGION_ADDR)) >
			(unsigned)PU32_ARG_REGION_SIZE) {
			sim_io_eprintf (sd,
				"pu32-sim: %s: arg-region overflow\n",
				__FUNCTION__);
			return SIM_RC_FAIL;
		}

		// Set the envp value.
		st32at (PU32_ARG_REGION_ADDR + ((i + j) * sizeof(uint32_t)), tp);

		// Store the string.
		sim_core_write_buffer (
			sd, scpu, write_map,
			p, tp, len);

		tp += len;
	}

	i += j;

	st32at (PU32_ARG_REGION_ADDR + (i * sizeof(uint32_t)), 0);

	st32at (PU32_ARG_REGION_ADDR + ((i + 1) * sizeof(uint32_t)), 0);

	tp = (PU32_INITIAL_STACK_BOTTOM - sizeof(uint32_t));

	st32at (tp, (j - 1));

	pu32state *scpustate = STATE_CPU(sd, 0)->state;
	scpustate->curctx = 0;
	clraddrtranslcache[0]._ = -1;
	scpustate->resettimer = 1;
	scpustate->dohalt = 0;
	uint32_t *scpustateregs = scpustate->regs;
	scpustateregs[PU32_REG_PC] = (abfd != NULL) ? bfd_get_start_address (abfd) : PU32_KERNELSPACE_START;
	scpustateregs[PU32_REG_FLAGS] = PU32_FLAGS_disTimerIntr;
	scpustateregs[PU32_REG_KSL] = PU32_KERNELSPACE_START;
	scpustateregs[0] = tp;
	scpustateregs[14] = tp;

	uint64_t clkperiod = getclkperiod(0);

	struct timespec stime;
	if (clock_gettime(CLOCK_BOOTTIME, &stime) == -1) {
		sim_io_eprintf (sd, "pu32-sim: clock_gettime() failed\n");
		return SIM_RC_FAIL;
	}

	for (unsigned i = 0; i < corecnt; ++i) {
		pu32state *scpustate = STATE_CPU(sd, i)->state;
		scpustate->clkperiod = clkperiod;
		scpustate->stime = stime;
	}

	brkcoreid = 0;

	return SIM_RC_OK;
}
