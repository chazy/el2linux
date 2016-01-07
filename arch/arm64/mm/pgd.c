/*
 * PGD allocation/freeing
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
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

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/tlbflush.h>

#include "mm.h"

static struct kmem_cache *pgd_cache;

#ifdef CONFIG_EL2_KERNEL
static void copy_kernel_pgd_entries(pgd_t *new_pgd)
{
	pgd_t *init_pgd;

	init_pgd = pgd_offset_k(0);
	memcpy(new_pgd + USER_PTRS_PER_PGD, init_pgd + USER_PTRS_PER_PGD,
	       (PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof(pgd_t));
}
#else
static void copy_kernel_pgd_entries(pgd_t *new_pgd) { }
#endif

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgd;

	if (PGD_SIZE == PAGE_SIZE)
		pgd = (pgd_t *)__get_free_page(PGALLOC_GFP);
	else
		pgd = kmem_cache_alloc(pgd_cache, PGALLOC_GFP);

	if (pgd)
		copy_kernel_pgd_entries(pgd);
	return pgd;
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	if (PGD_SIZE == PAGE_SIZE)
		free_page((unsigned long)pgd);
	else
		kmem_cache_free(pgd_cache, pgd);
}

void __init pgd_cache_init(void)
{
	if (PGD_SIZE == PAGE_SIZE)
		return;

	/*
	 * Naturally aligned pgds required by the architecture.
	 */
	pgd_cache = kmem_cache_create("pgd_cache", PGD_SIZE, PGD_SIZE,
				      SLAB_PANIC, NULL);
}
