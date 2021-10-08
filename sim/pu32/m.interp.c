// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

// Write 1 byte data to memory.
INLINE void st8at (uint32_t x, uint8_t v) {
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].st8at) {
		*(uint8_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK)) = v;
		return; }
	clraddrtranslcache[coreid].st8at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.writable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110010/*present+user+writable*/) == 0b110010)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32WriteFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, write_map, x, 1, write_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	*(volatile uint8_t *)x_translated = v;
}

// Write 2 bytes data to memory.
INLINE void st16at (uint32_t x, uint16_t v) {
	if (x&0b1) {
		if (scpustate->curctx)
			dopfault (pu32AlignFaultIntr, x);
		else {
			address_word ip = scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)];
			sim_io_eprintf (sd,
				"pu32-sim: core%u: %u bytes write to unaligned address 0x%x at 0x%x\n",
				scpu->coreid, (unsigned)sizeof(uint16_t), x, ip);
			sim_engine_halt (
				sd, scpu, scpu, ip,
				sim_stopped, SIM_SIGBUS);
		}
	}
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].st16at) {
		*(uint16_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK)) = v;
		return; }
	clraddrtranslcache[coreid].st16at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.writable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110010/*present+user+writable*/) == 0b110010)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32WriteFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, write_map, x, 2, write_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	*(volatile uint16_t *)x_translated = v;
}

// Write 4 bytes data to memory.
INLINE void st32at (uint32_t x, uint32_t v) {
	if (x&0b11) {
		if (scpustate->curctx)
			dopfault (pu32AlignFaultIntr, x);
		else {
			address_word ip = scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)];
			sim_io_eprintf (sd,
				"pu32-sim: core%u: %u bytes write to unaligned address 0x%x at 0x%x\n",
				scpu->coreid, (int)sizeof(uint32_t), x, ip);
			sim_engine_halt (
				sd, scpu, scpu, ip,
				sim_stopped, SIM_SIGBUS);
		}
	}
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].st32at) {
		*(uint32_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK)) = v;
		return; }
	clraddrtranslcache[coreid].st32at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.writable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110010/*present+user+writable*/) == 0b110010)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32WriteFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, write_map, x, 4, write_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	*(volatile uint32_t *)x_translated = v;
}

// Read 1 byte data from memory.
INLINE uint8_t ld8at (uint32_t x) {
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].ld8at)
		return *(uint8_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK));
	clraddrtranslcache[coreid].ld8at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.readable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110100/*present+user+readable*/) == 0b110100)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32ReadFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, read_map, x, 1, read_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	return *(volatile uint8_t *)x_translated;
}

// Read 2 bytes data from memory.
INLINE uint16_t ld16at (uint32_t x) {
	if (x&0b1) {
		if (scpustate->curctx)
			dopfault (pu32AlignFaultIntr, x);
		else {
			address_word ip = scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)];
			sim_io_eprintf (sd,
				"pu32-sim: core%u: %u bytes read from unaligned address 0x%x at 0x%x\n",
				scpu->coreid, (int)sizeof(uint16_t), x, ip);
			sim_engine_halt (
				sd, scpu, scpu, ip,
				sim_stopped, SIM_SIGBUS);
		}
	}
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].ld16at)
		return *(uint16_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK));
	clraddrtranslcache[coreid].ld16at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.readable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110100/*present+user+readable*/) == 0b110100)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32ReadFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, read_map, x, 2, read_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	return *(volatile uint16_t *)x_translated;
}

// Read 4 bytes data from memory.
INLINE uint32_t ld32at (uint32_t x) {
	if (x&0b11) {
		if (scpustate->curctx)
			dopfault (pu32AlignFaultIntr, x);
		else {
			address_word ip = scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)];
			sim_io_eprintf (sd,
				"pu32-sim: core%u: %u bytes read from unaligned address 0x%x at 0x%x\n",
				scpu->coreid, (int)sizeof(uint32_t), x, ip);
			sim_engine_halt (
				sd, scpu, scpu, ip,
				sim_stopped, SIM_SIGBUS);
		}
	}
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].ld32at)
		return *(uint32_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK));
	clraddrtranslcache[coreid].ld32at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.readable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110100/*present+user+readable*/) == 0b110100)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32ReadFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, read_map, x, 4, read_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	return *(volatile uint32_t *)x_translated;
}

// ReadWrite 1 byte data to memory.
INLINE uint8_t ldst8at (uint32_t x, uint8_t v) {
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].ldst8at)
		return __sync_lock_test_and_set (
			(uint8_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK)), v);
	clraddrtranslcache[coreid].ldst8at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.readable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110100/*present+user+readable*/) == 0b110100)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32ReadFaultIntr, x);
				}
			} else if (!tlbentry.writable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110010/*present+user+writable*/) == 0b110010)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32WriteFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, write_map, x, 1, write_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	return __sync_lock_test_and_set ((uint8_t *)x_translated, v);
}

// ReadWrite 2 bytes data to memory.
INLINE uint16_t ldst16at (uint32_t x, uint16_t v) {
	if (x&0b1) {
		if (scpustate->curctx)
			dopfault (pu32AlignFaultIntr, x);
		else {
			address_word ip = scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)];
			sim_io_eprintf (sd,
				"pu32-sim: core%u: %u bytes atomic read-write from unaligned address 0x%x at 0x%x\n",
				scpu->coreid, (int)sizeof(uint16_t), x, ip);
			sim_engine_halt (
				sd, scpu, scpu, ip,
				sim_stopped, SIM_SIGBUS);
		}
	}
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].ldst16at)
		return __sync_lock_test_and_set (
			(uint16_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK)), v);
	clraddrtranslcache[coreid].ldst16at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.readable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110100/*present+user+readable*/) == 0b110100)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32ReadFaultIntr, x);
				}
			} else if (!tlbentry.writable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110010/*present+user+writable*/) == 0b110010)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32WriteFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, write_map, x, 2, write_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	return __sync_lock_test_and_set ((uint16_t *)x_translated, v);
}

// ReadWrite 4 bytes data to memory.
INLINE uint32_t ldst32at (uint32_t x, uint32_t v) {
	if (x&0b11) {
		if (scpustate->curctx)
			dopfault (pu32AlignFaultIntr, x);
		else {
			address_word ip = scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)];
			sim_io_eprintf (sd,
				"pu32-sim: core%u: %u bytes atomic read-write from unaligned address 0x%x at 0x%x\n",
				scpu->coreid, (int)sizeof(uint32_t), x, ip);
			sim_engine_halt (
				sd, scpu, scpu, ip,
				sim_stopped, SIM_SIGBUS);
		}
	}
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].ldst32at)
		return __sync_lock_test_and_set (
			(uint32_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK)), v);
	clraddrtranslcache[coreid].ldst32at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.readable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110100/*present+user+readable*/) == 0b110100)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32ReadFaultIntr, x);
				}
			} else if (!tlbentry.writable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110010/*present+user+writable*/) == 0b110010)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32WriteFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, write_map, x, 4, write_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	return __sync_lock_test_and_set ((uint32_t *)x_translated, v);
}

// Compare-ReadWrite 1 byte data to memory.
INLINE uint8_t cldst8at (uint32_t x, uint8_t v, uint8_t ov) {
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].cldst8at)
		return __sync_val_compare_and_swap (
			(uint8_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK)), ov, v);
	clraddrtranslcache[coreid].cldst8at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.readable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110100/*present+user+readable*/) == 0b110100)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32ReadFaultIntr, x);
				}
			} else if (!tlbentry.writable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110010/*present+user+writable*/) == 0b110010)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32WriteFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, write_map, x, 1, write_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	return __sync_val_compare_and_swap ((uint8_t *)x_translated, ov, v);
}

// Compare-ReadWrite 2 bytes data to memory.
INLINE uint16_t cldst16at (uint32_t x, uint16_t v, uint16_t ov) {
	if (x&0b1) {
		if (scpustate->curctx)
			dopfault (pu32AlignFaultIntr, x);
		else {
			address_word ip = scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)];
			sim_io_eprintf (sd,
				"pu32-sim: core%u: %u bytes atomic read-write from unaligned address 0x%x at 0x%x\n",
				scpu->coreid, (int)sizeof(uint16_t), x, ip);
			sim_engine_halt (
				sd, scpu, scpu, ip,
				sim_stopped, SIM_SIGBUS);
		}
	}
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].cldst16at)
		return __sync_val_compare_and_swap (
			(uint16_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK)), ov, v);
	clraddrtranslcache[coreid].cldst16at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.readable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110100/*present+user+readable*/) == 0b110100)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32ReadFaultIntr, x);
				}
			} else if (!tlbentry.writable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110010/*present+user+writable*/) == 0b110010)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32WriteFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, write_map, x, 2, write_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	return __sync_val_compare_and_swap ((uint16_t *)x_translated, ov, v);
}

// Compare-ReadWrite 4 bytes data to memory.
INLINE uint32_t cldst32at (uint32_t x, uint32_t v, uint32_t ov) {
	if (x&0b11) {
		if (scpustate->curctx)
			dopfault (pu32AlignFaultIntr, x);
		else {
			address_word ip = scpustateregs[PU32_REG_PC+(scpustate->curctx*PU32_GPRCNT)];
			sim_io_eprintf (sd,
				"pu32-sim: core%u: %u bytes atomic read-write from unaligned address 0x%x at 0x%x\n",
				scpu->coreid, (int)sizeof(uint32_t), x, ip);
			sim_engine_halt (
				sd, scpu, scpu, ip,
				sim_stopped, SIM_SIGBUS);
		}
	}
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].cldst32at)
		return __sync_val_compare_and_swap (
			(uint32_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK)), ov, v);
	clraddrtranslcache[coreid].cldst32at = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustatedtlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.readable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110100/*present+user+readable*/) == 0b110100)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32ReadFaultIntr, x);
				}
			} else if (!tlbentry.writable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110010/*present+user+writable*/) == 0b110010)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32WriteFaultIntr, x);
				}
			} else if (retried)
				scpustatedtlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, write_map, x, 4, write_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	return __sync_val_compare_and_swap ((uint32_t *)x_translated, ov, v);
}

// Read 2 bytes instruction from memory.
INLINE uint16_t ldinst (uint32_t x) {
	// The value of x is assumed always properly aligned to 16 bits.
	static uint32_t x_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	static unsigned long x_translated_cached[PU32_CPUCNT] = {[0 ... PU32_CPUCNT - 1] = 0};
	uint32_t x_masked = (x & PAGE_MASK);
	if (x_masked == x_cached[coreid] && !clraddrtranslcache[coreid].ldinst)
		return *(uint16_t *)(x_translated_cached[coreid] + (x & ~PAGE_MASK));
	clraddrtranslcache[coreid].ldinst = 0;
	x_cached[coreid] = x_masked;
	if (scpustate->curctx) {
		uint32_t asid = scpustateregs[PU32_REG_ASID+(scpustate->curctx-1)];
		uint32_t in_userspace = (asid>>12);
		if (in_userspace || (x < PU32_KERNELSPACE_START || x >= scpustateregs[PU32_REG_KSL])) {
			uint32_t vpn = (x >> PAGE_SHIFT);
			unsigned tlbidx = (vpn & (PU32_TLBSZ - 1));
			asid = (asid & ~PAGE_MASK);
			unsigned retried = 0;
			pu32tlbentry tlbentry = scpustateitlb[tlbidx];
			retry:;
			if ((in_userspace && !tlbentry.user) || tlbentry.asid != asid ||
				tlbentry.vpn != vpn || !tlbentry.executable) {
				#if (PU32_CAP & PU32_CAP_hptw)
				if (!retried) {
					uint32_t d2 = ((vpn << PAGE_SHIFT) | asid);
					uint32_t d1 = walk_page_table (x, coreid);
					d1 |= (!in_userspace ? 0b10000 : 0); // Make bit "user" a don't-care if in kernelspace.
					if ((d1 & 0b110001/*present+user+executable*/) == 0b110001)
						tlbentry = ((pu32tlbentry){.d1 = d1, .d2 = d2});
					retried = 1;
					goto retry;
				} else
				#endif
				{
					dopfault (pu32ExecFaultIntr, x);
				}
			} else if (retried)
				scpustateitlb[tlbidx] = tlbentry;
			x = ((tlbentry.ppn << PAGE_SHIFT) | (x & ~PAGE_MASK));
		}
	}
	sim_core_mapping *mapping =
		sim_core_find_mapping (
			scpu, read_map, x, 2, read_transfer,
			1 /*abort*/);
	void *x_translated = sim_core_translate (mapping, x);
	x_translated_cached[coreid] = ((unsigned long)x_translated & PAGE_MASK);
	return *(uint16_t *)x_translated;
}
