// SPDX-License-Identifier: GPL-2.0-only
// (c) William Fonkou Tambe

typedef uint32_t pgd_t;
typedef uint32_t pmd_t;
typedef uint32_t pte_t;

#define PGD_ORDER 0 /* PGD is one page */
#define PTE_ORDER 0 /* PTE is one page */

#define PGD_T_LOG2	(__builtin_ffs(sizeof(pgd_t)) - 1) /* 2 */
#define PTE_T_LOG2	(__builtin_ffs(sizeof(pte_t)) - 1) /* 2 */

#define PTRS_PER_PGD_LOG2	(PAGE_SHIFT + PGD_ORDER - PGD_T_LOG2) /* 10 */
#define PTRS_PER_PTE_LOG2	(PAGE_SHIFT + PTE_ORDER - PTE_T_LOG2) /* 10 */

#define PTRS_PER_PGD		(1 << PTRS_PER_PGD_LOG2) /* 1024 */
#define PTRS_PER_PTE		(1 << PTRS_PER_PTE_LOG2) /* 1024 */

#define PGDIR_SHIFT		(PTRS_PER_PTE_LOG2 + PAGE_SHIFT) /* 10 + 12 */
#define PGDIR_SIZE		(1 << PGDIR_SHIFT)
#define PGDIR_MASK		(~(PGDIR_SIZE - 1))

#define _PAGE_DIRTY		(1 << 7) /* was written to when 1 */
#define _PAGE_ACCESSED		(1 << 6) /* was accessed when 1 */
#define _PAGE_PRESENT		(1 << 5) /* is present when 1 */
#define _PAGE_USER		(1 << 4) /* accessible from userspace when 1 */
#define _PAGE_CACHED		(1 << 3) /* cached when 1 */
#define _PAGE_READABLE		(1 << 2) /* readable when 1 */
#define _PAGE_WRITABLE		(1 << 1) /* writable when 1 */
#define _PAGE_EXECUTABLE	(1 << 0) /* executable when 1 */

#define pgd_index(addr) ((addr) >> PGDIR_SHIFT)
#define pte_index(addr) (((addr) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_offset_kernel(dir, addr) \
	((((ld32at(dir))) & PAGE_MASK) + (pte_index((addr))*sizeof(uint32_t)))
#define pte_offset_map(dir, addr) pte_offset_kernel((dir), (addr))
#define e_present(x) ((x) & _PAGE_PRESENT)

static uint32_t walk_page_table (uint32_t addr, uint32_t coreid) {
	// Read 4 bytes from memory.
	INLINE uint32_t ld32at (uint32_t x) {
		sim_cpu *scpu = STATE_CPU (sd, 0);
		if (x&0b11)
			sim_engine_halt (
				sd, scpu, scpu, 0, sim_stopped, SIM_SIGBUS);
		sim_core_mapping *mapping =
			sim_core_find_mapping (
				scpu, read_map, x, 4, read_transfer,
				0 /*abort*/);
		if (mapping)
			return *(uint32_t *)sim_core_translate (mapping, x);
		return 0;
	}

	uint32_t d2 = 0;

	pgd_t pgd = (pgds[coreid] + (pgd_index(addr)*sizeof(uint32_t)));
	if (!e_present(ld32at(pgd))) // ld32at() will also return null for a bad address.
		goto out;

	pte_t pte = ld32at(pte_offset_map(pgd, addr)); // ld32at() will also return null for a bad address.
	if (!e_present(pte))
		goto out;

	d2 = pte;

	out:
	return d2;
}
