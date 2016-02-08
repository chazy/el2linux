/*
 * Copyright (C) 2012 ARM Ltd.
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 *
 * This program is free software: you can redistribute it and/or modify
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

#ifndef __ASM__VIRT_H
#define __ASM__VIRT_H

/*
 * The arm64 hcall implementation uses x0 to specify the hcall type. A value
 * less than 0xfff indicates a special hcall, such as get/set vector.
 * Any other value is used as a pointer to the function to call.
 */

/* HVC_GET_VECTORS - Return the value of the vbar_el2 register. */
#define HVC_GET_VECTORS 0

/*
 * HVC_SET_VECTORS - Set the value of the vbar_el2 register.
 *
 * @x1: Physical address of the new vector table.
 */
#define HVC_SET_VECTORS 1

/*
 * HVC_SOFT_RESTART - CPU soft reset, used by the cpu_soft_restart routine.
 */
#define HVC_SOFT_RESTART 2

#define BOOT_CPU_MODE_EL1	(0xe11)
#define BOOT_CPU_MODE_EL2	(0xe12)


#ifndef CONFIG_EL2_KERNEL
#define EL2_HOST_HCR	HCR_RW
#else
/*
 * We need to configure the HCR to run Linux in EL2. Specificially we
 * set the following bits:
 *
 * HCR.RW = 1 (assume AArch64 userspace for now)
 * HCR.HCD = 0 (disable hypercalls)
 * HCR.TDZ = 0 (allow EL0 to do DC)
 * HCR.TGE = 0 (do not trap general exceptions, forces EL1/0 MMU off)
 * HCR.TPU = 0
 * HCR.TPC = 0
 * HCR.TID2 = 0
 * HCR.TID1 = 0
 * HCR.TID0 = 0
 * HCR.TWE = 0 (EL1 kernels allow EL0 execution of WFE)
 * HCR.TWI = 0 (EL1 kernels allow EL0 execution of WFI)
 * HCR.DC = 0 (we must be able to use the MMU in EL0)
 * HCR.BSU = 0
 * HCR.VSE = 0 (defined as HCR_VA)
 * HCR.VI = 0
 * HCR.VF = 0
 * HCR.AMO = 1
 * HCR.IMO = 1
 * HCR.FMO = 1
 * HCR.VM = 0
 */
#define EL2_HOST_HCR	(HCR_RW | HCR_AMO | HCR_IMO | HCR_FMO)
#endif

#ifndef __ASSEMBLY__

#include <asm/ptrace.h>

/*
 * __boot_cpu_mode records what mode CPUs were booted in.
 * A correctly-implemented bootloader must start all CPUs in the same mode:
 * In this case, both 32bit halves of __boot_cpu_mode will contain the
 * same value (either 0 if booted in EL1, BOOT_CPU_MODE_EL2 if booted in EL2).
 *
 * Should the bootloader fail to do this, the two values will be different.
 * This allows the kernel to flag an error when the secondaries have come up.
 */
extern u32 __boot_cpu_mode[2];

#ifdef CONFIG_EL2_KERNEL
extern void el1_shim_vectors_init(void);
extern void cpu_init_el1_entry(void);
#else
static inline void el1_shim_vectors_init(void) { }
static inline void cpu_init_el1_entry(void) { }
#endif

void __hyp_set_vectors(phys_addr_t phys_vector_base);
phys_addr_t __hyp_get_vectors(void);

/* Reports the availability of HYP mode */
static inline bool is_hyp_mode_available(void)
{
	return (__boot_cpu_mode[0] == BOOT_CPU_MODE_EL2 &&
		__boot_cpu_mode[1] == BOOT_CPU_MODE_EL2);
}

/* Check if the bootloader has booted CPUs in different modes */
static inline bool is_hyp_mode_mismatched(void)
{
	return __boot_cpu_mode[0] != __boot_cpu_mode[1];
}

static inline bool is_kernel_in_hyp_mode(void)
{
	u64 el;

	asm("mrs %0, CurrentEL" : "=r" (el));
	return el == CurrentEL_EL2;
}

#ifdef CONFIG_ARM64_VHE
extern void verify_cpu_run_el(void);
#else
static inline void verify_cpu_run_el(void) {}
#endif

/* The section containing the hypervisor idmap text */
extern char __hyp_idmap_text_start[];
extern char __hyp_idmap_text_end[];

static inline bool is_vhe_present(void)
{
#ifdef CONFIG_EL2_KERNEL
	return false;
#else
	u64 mmfr1;

	asm("mrs %0, id_aa64mmfr1_el1" : "=r" (mmfr1));
	return (((mmfr1 >> 8) & 0xf) == 0x1);
#endif
}

/* The section containing the hypervisor text */
extern char __hyp_text_start[];
extern char __hyp_text_end[];

#endif /* __ASSEMBLY__ */

#endif /* ! __ASM__VIRT_H */
