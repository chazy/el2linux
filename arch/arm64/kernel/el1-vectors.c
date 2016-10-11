/*
 * EL1 Shim Vectors to route synchronous exceptions from EL0 to EL2 via EL1
 *
 * Copyright (C) 2016 Columbia University
 * Author: Christoffer Dall <cdall@cs.columbia.edu>
 *         Shih-Wei Li <shihwei@cs.columbia.edu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kernel.h>
#include <linux/err.h>
#include <linux/errno.h>
#include <linux/gfp.h>
#include <linux/mm.h>

#include <asm/cacheflush.h>
#include <asm/pgalloc.h>
#include <asm/virt.h>

extern char el1_shim_vectors[];
extern char __el1_shim_vectors_start[], __el1_shim_vectors_end[];

static pte_t el1_shim_pte[PTRS_PER_PTE] __page_aligned_bss;
#if CONFIG_PGTABLE_LEVELS > 2
static pmd_t el1_shim_pmd[PTRS_PER_PMD] __page_aligned_bss;
#endif
#if CONFIG_PGTABLE_LEVELS > 3
static pud_t el1_shim_pud[PTRS_PER_PUD] __page_aligned_bss;
#endif
static pgd_t el1_shim_pgd[PTRS_PER_PGD] __page_aligned_bss;

struct el1_entry_info {
	unsigned long vbar_el1;
	phys_addr_t pgd_phys;
};

static struct el1_entry_info el1_entry_info;

void cpu_init_el1_entry(void)
{
	struct el1_entry_info *info = &el1_entry_info;

	BUG_ON(preemptible());

	/* Set the TTBR1_EL1 to the EL1 shim PGD */
	asm volatile("msr ttbr1_el1, %0": : "r" (info->pgd_phys));

	/* Configure the VBAR_EL1 to the mapped VA of the el1_shim_vectors */
	asm volatile("msr vbar_el1, %0": : "r" (info->vbar_el1));
}

void el1_shim_vectors_init(void)
{
	unsigned long start = (unsigned long)&__el1_shim_vectors_start;
	unsigned long end = ((unsigned long)&__el1_shim_vectors_end) - 1;
	unsigned long addr = EL1_VECTORS_VADDR;
	unsigned long kaddr;
	phys_addr_t phys;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	/* Ensure we're not spanning multiple pages*/
	BUG_ON((start & PAGE_MASK) != (end & PAGE_MASK));

	/* Get the physical address of the shim vectors page */
	phys = __pa(start);

	/*
	 * Create page tables and map the shim vectors page at
	 * EL1_VECTORS_VADDR
	 */
	pgd = el1_shim_pgd + pgd_index(addr);
	pgd_populate(NULL, pgd, el1_shim_pud);
	pud = pud_offset_kimg(pgd, addr);
	pud_populate(NULL, pud, el1_shim_pmd);
	pmd = pmd_offset_kimg(pud, addr);
	pmd_populate_kernel(NULL, pmd, el1_shim_pte);
	pte = pte_offset_kimg(pmd, addr);
	set_pte(pte, pfn_pte(phys >> PAGE_SHIFT, PAGE_KERNEL_EXEC_EL1));

	/*
	 * Configure the EL1 exception entry on each CPU.
	 */
	el1_entry_info.pgd_phys = virt_to_phys(el1_shim_pgd);
	kaddr = (unsigned long)el1_shim_vectors;
	el1_entry_info.vbar_el1 = EL1_VECTORS_VADDR + (kaddr & ~PAGE_MASK);
	cpu_init_el1_entry();


	/* TODO: Not sure if this is needed? */
	flush_icache_range(addr, addr + PAGE_SIZE);
}
