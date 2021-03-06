/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
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

#include <linux/types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/debug-monitors.h>
#include <asm/kvm_emulate.h>

static bool __hyp_text __fpsimd_enabled_nvhe(void)
{
	return !(read_sysreg(cptr_el2) & CPTR_EL2_TFP);
}

static bool __hyp_text __fpsimd_enabled_vhe(void)
{
	return !!(read_sysreg(cpacr_el1) & CPACR_EL1_FPEN);
}

static void __hyp_text __activate_fpsimd_nvhe(struct kvm_vcpu *vcpu)
{
	u64 val;

	val = CPTR_EL2_DEFAULT;
	val |= CPTR_EL2_TTA;
	if (vcpu->arch.guest_vfp_loaded)
		val &= ~CPTR_EL2_TFP;
	else
		val |= CPTR_EL2_TFP;
	write_sysreg(val, cptr_el2);
}

static void __hyp_text __deactivate_fpsimd_nvhe(void)
{
	write_sysreg(CPTR_EL2_DEFAULT, cptr_el2);
}

static void __hyp_text __activate_traps_vm(struct kvm_vcpu *vcpu)
{
	u64 val;

	/*
	 * We are about to set CPTR_EL2.TFP to trap all floating point
	 * register accesses to EL2, however, the ARM ARM clearly states that
	 * traps are only taken to EL2 if the operation would not otherwise
	 * trap to EL1.  Therefore, always make sure that for 32-bit guests,
	 * we set FPEXC.EN to prevent traps to EL1, when setting the TFP bit.
	 */
	val = vcpu->arch.hcr_el2;
	if (!(val & HCR_RW) && !vcpu->arch.guest_vfp_loaded) {
		write_sysreg(1 << 30, fpexc32_el2);
		isb();
	}
	write_sysreg(val, hcr_el2);
	/* Trap on AArch32 cp15 c15 accesses (EL1 or EL0) */
	write_sysreg(1 << 15, hstr_el2);
	/* Make sure we trap PMU access from EL0 to EL2 */
	write_sysreg(ARMV8_PMU_USERENR_MASK, pmuserenr_el0);
	write_sysreg(vcpu->arch.mdcr_el2, mdcr_el2);
}

static void __hyp_text __deactivate_traps_vm(void)
{
	write_sysreg(0, hstr_el2);
	write_sysreg(read_sysreg(mdcr_el2) & MDCR_EL2_HPMN_MASK, mdcr_el2);
	write_sysreg(0, pmuserenr_el0);
}

static hyp_alternate_select(__fpsimd_is_enabled,
			    __fpsimd_enabled_nvhe, __fpsimd_enabled_vhe,
			    ARM64_HAS_VIRT_HOST_EXTN);

bool __hyp_text __fpsimd_enabled(void)
{
	return __fpsimd_is_enabled()();
}

static void __hyp_text __activate_traps_vhe(struct kvm_vcpu *vcpu)
{
	u64 val;

	val = read_sysreg(cpacr_el1);
	val |= CPACR_EL1_TTA;
	if (vcpu->arch.guest_vfp_loaded)
		val |= CPACR_EL1_FPEN;
	else
		val &= ~CPACR_EL1_FPEN;
	write_sysreg(val, cpacr_el1);

	write_sysreg(__kvm_hyp_vector, vbar_el1);
}

static inline void __hyp_text set_kvm_vbar(void)
{
	write_sysreg(__kvm_hyp_vector, vbar_el2);
}

static void __hyp_text __activate_traps_nvhe(struct kvm_vcpu *vcpu)
{
#ifndef CONFIG_EL2_KERNEL
	__activate_fpsimd_nvhe(vcpu);
#else
	set_kvm_vbar();
#endif
}

static hyp_alternate_select(__activate_traps_arch,
			    __activate_traps_nvhe, __activate_traps_vhe,
			    ARM64_HAS_VIRT_HOST_EXTN);

static void __hyp_text __activate_traps(struct kvm_vcpu *vcpu)
{
#ifndef CONFIG_EL2_KERNEL
	__activate_traps_vm(vcpu);
#endif
	__activate_traps_arch()(vcpu);
}

static void __hyp_text __deactivate_traps_vhe(void)
{
	extern char vectors[];	/* kernel exception vectors */

	write_sysreg(HCR_HOST_VHE_FLAGS, hcr_el2);
	write_sysreg(CPACR_EL1_FPEN, cpacr_el1);
	write_sysreg(vectors, vbar_el1);
}

static inline void __hyp_text restore_host_vbar(void)
{
	extern char vectors[];	/* kernel exception vectors */

	write_sysreg(vectors, vbar_el2);
}

static void __hyp_text __deactivate_traps_nvhe(void)
{
#ifndef CONFIG_EL2_KERNEL
	write_sysreg(EL2_HOST_HCR, hcr_el2);
	__deactivate_fpsimd_nvhe();
#endif
}

static hyp_alternate_select(__deactivate_traps_arch,
			    __deactivate_traps_nvhe, __deactivate_traps_vhe,
			    ARM64_HAS_VIRT_HOST_EXTN);

static void __hyp_text __deactivate_traps(struct kvm_vcpu *vcpu)
{
	__deactivate_traps_arch()();
#ifndef CONFIG_EL2_KERNEL
	__deactivate_traps_vm();
#endif
}

static void __hyp_text __activate_vm(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = kern_hyp_va(vcpu->kvm);
	write_sysreg(kvm->arch.vttbr, vttbr_el2);
}

static void __hyp_text __deactivate_vm(struct kvm_vcpu *vcpu)
{
	write_sysreg(0, vttbr_el2);
}

static hyp_alternate_select(__vgic_call_save_state,
			    vgic_v2_save_state, __vgic_v3_save_state,
			    ARM64_HAS_SYSREG_GIC_CPUIF);

static hyp_alternate_select(__vgic_call_restore_state,
			    vgic_v2_restore_state, __vgic_v3_restore_state,
			    ARM64_HAS_SYSREG_GIC_CPUIF);

static void __hyp_text __vgic_save_state(struct kvm_vcpu *vcpu)
{
	__vgic_call_save_state()(vcpu);
}

static void __hyp_text __vgic_restore_state(struct kvm_vcpu *vcpu)
{
	__vgic_call_restore_state()(vcpu);
}

static bool __hyp_text __true_value(void)
{
	return true;
}

static bool __hyp_text __false_value(void)
{
	return false;
}

static hyp_alternate_select(__check_arm_834220,
			    __false_value, __true_value,
			    ARM64_WORKAROUND_834220);

#ifdef CONFIG_EL2_KERNEL
void kvm_vcpu_save_vmconfig(struct kvm_vcpu *vcpu)
{
	write_sysreg(EL2_HOST_HCR, hcr_el2);
	__deactivate_fpsimd_nvhe();
	__deactivate_traps_vm();
	__deactivate_vm(vcpu);
}

void kvm_vcpu_restore_vmconfig(struct kvm_vcpu *vcpu)
{
	write_sysreg(vcpu->arch.hcr_el2, hcr_el2);
	__activate_traps_vm(vcpu);
	__activate_fpsimd_nvhe(vcpu);
}
#endif

static bool __hyp_text __translate_far_to_hpfar(u64 far, u64 *hpfar)
{
	u64 par, tmp;

	/*
	 * Resolve the IPA the hard way using the guest VA.
	 *
	 * Stage-1 translation already validated the memory access
	 * rights. As such, we can use the EL1 translation regime, and
	 * don't have to distinguish between EL0 and EL1 access.
	 *
	 * We do need to save/restore PAR_EL1 though, as we haven't
	 * saved the guest context yet, and we may return early...
	 */
	par = read_sysreg(par_el1);
	asm volatile("at s1e1r, %0" : : "r" (far));
	isb();

	tmp = read_sysreg(par_el1);
	write_sysreg(par, par_el1);

	if (unlikely(tmp & 1))
		return false; /* Translation failed, back to guest */

	/* Convert PAR to HPFAR format */
	*hpfar = ((tmp >> 12) & ((1UL << 36) - 1)) << 4;
	return true;
}

static inline bool __is_debug_dirty(struct kvm_vcpu *vcpu)
{
	return (vcpu->arch.ctxt.sys_regs[MDSCR_EL1] & DBG_MDSCR_KDE) ||
		(vcpu->arch.ctxt.sys_regs[MDSCR_EL1] & DBG_MDSCR_MDE) ||
		(vcpu->arch.debug_flags & KVM_ARM64_DEBUG_DIRTY);
}

static bool __hyp_text __populate_fault_info(struct kvm_vcpu *vcpu,
					     unsigned long host_tpidr_el2)
{
	u64 esr = read_sysreg_el2(esr);
	u8 ec = ESR_ELx_EC(esr);
	u64 hpfar, far;

	vcpu->arch.fault.esr_el2 = esr;

	if (ec != ESR_ELx_EC_DABT_LOW && ec != ESR_ELx_EC_IABT_LOW)
		return true;

	far = read_sysreg_el2(far);

	/*
	 * The HPFAR can be invalid if the stage 2 fault did not
	 * happen during a stage 1 page table walk (the ESR_EL2.S1PTW
	 * bit is clear) and one of the two following cases are true:
	 *   1. The fault was due to a permission fault
	 *   2. The processor carries errata 834220
	 *
	 * Therefore, for all non S1PTW faults where we either have a
	 * permission fault or the errata workaround is enabled, we
	 * resolve the IPA using the AT instruction.
	 */
	if (!(esr & ESR_ELx_S1PTW) &&
	    (__check_arm_834220()() || (esr & ESR_ELx_FSC_TYPE) == FSC_PERM)) {
		if (!__translate_far_to_hpfar(far, &hpfar))
			return false;
	} else {
		hpfar = read_sysreg(hpfar_el2);
	}

	vcpu->arch.fault.far_el2 = far;
	vcpu->arch.fault.hpfar_el2 = hpfar;

	if (kvm_runs_in_hyp())
		return __early_handle_mmio(vcpu, host_tpidr_el2);
	else
		return true;
}

int kvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	u64 exit_code;

	host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	guest_ctxt = &vcpu->arch.ctxt;

#ifdef CONFIG_EL2_KERNEL
	/* TODO: Can we get rid of this? */
	host_ctxt->host_tpidr = read_sysreg(tpidr_el2);
#endif
	write_sysreg(vcpu, tpidr_el2);

	/* make sure we're using the latest VMID for this VM */
	write_sysreg(vcpu->kvm->arch.vttbr, vttbr_el2);

	/* switch sp_el0 */
	host_ctxt->gp_regs.regs.sp = read_sysreg(sp_el0);
	write_sysreg(guest_ctxt->gp_regs.regs.sp, sp_el0);

	/* restore guest return state */
	write_sysreg_el2(guest_ctxt->gp_regs.regs.pc,     elr);
	write_sysreg_el2(guest_ctxt->gp_regs.regs.pstate, spsr);

	/* set the vector to KVM's vector */
	write_sysreg(__kvm_hyp_vector, vbar_el2);

	/* Jump in the fire! */
again:
	exit_code = __guest_enter(vcpu, host_ctxt);
	/* And we're baaack! */

	if (exit_code == ARM_EXCEPTION_TRAP &&
	    !__populate_fault_info(vcpu, host_ctxt->host_tpidr))
		goto again;

	/* switch sp_el0 */
	guest_ctxt->gp_regs.regs.sp = read_sysreg(sp_el0);
	write_sysreg(host_ctxt->gp_regs.regs.sp, sp_el0);

	/* save guest return state */
	guest_ctxt->gp_regs.regs.pc	= read_sysreg_el2(elr);
	guest_ctxt->gp_regs.regs.pstate	= read_sysreg_el2(spsr);

	/* restore the host's vector */
	restore_host_vbar();

	__sysreg_restore_common_state(host_ctxt);

#ifdef CONFIG_EL2_KERNEL
	write_sysreg(host_ctxt->host_tpidr, tpidr_el2);
#endif

	return exit_code;
}

static int __hyp_text __guest_run(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	u64 exit_code;
	unsigned long host_tpidr_el2;

#ifdef CONFIG_EL2_KERNEL
	host_tpidr_el2 = read_sysreg(tpidr_el2);
#endif

	vcpu = kern_hyp_va(vcpu);
	write_sysreg(vcpu, tpidr_el2);

	host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	guest_ctxt = &vcpu->arch.ctxt;

	__sysreg_save_host_state(host_ctxt);

	__activate_traps(vcpu);
	__activate_vm(vcpu);

	__vgic_restore_state(vcpu);
	__timer_enable_traps(vcpu);

	/*
	 * We must restore the 32-bit state before the sysregs, thanks
	 * to erratum #852523 (Cortex-A57) or #853709 (Cortex-A72).
	 */
	__sysreg32_restore_state(vcpu);
	__sysreg_restore_guest_state(guest_ctxt);
	if (__is_debug_dirty(vcpu)) {
		__debug_cond_save_host_state(vcpu);
		__debug_restore_state(vcpu, kern_hyp_va(vcpu->arch.debug_ptr), guest_ctxt);
	}

	/* Jump in the fire! */
again:
	exit_code = __guest_enter(vcpu, host_ctxt);
	/* And we're baaack! */

	if (exit_code == ARM_EXCEPTION_TRAP && !__populate_fault_info(vcpu, host_tpidr_el2))
		goto again;

#ifdef CONFIG_EL2_KERNEL
	write_sysreg(host_tpidr_el2, tpidr_el2);
#endif

	__sysreg_save_guest_state(guest_ctxt);
	__sysreg32_save_state(vcpu);
	__timer_disable_traps(vcpu);
	__vgic_save_state(vcpu);

	__deactivate_traps(vcpu);
#ifndef CONFIG_EL2_KERNEL
	__deactivate_vm(vcpu);
#endif
	if (__is_debug_dirty(vcpu)) {
		__debug_save_state(vcpu, kern_hyp_va(vcpu->arch.debug_ptr), guest_ctxt);
		__debug_cond_restore_host_state(vcpu);
	}

	__sysreg_restore_host_state(host_ctxt);


	return exit_code;
}

__alias(__guest_run) int __kvm_vcpu_run(struct kvm_vcpu *vcpu);

static const char __hyp_panic_string[] = "HYP panic:\nPS:%08llx PC:%016llx ESR:%08llx\nFAR:%016llx HPFAR:%016llx PAR:%016llx\nVCPU:%p\n";

static void __hyp_text __hyp_call_panic_nvhe(u64 spsr, u64 elr, u64 par)
{
	unsigned long str_va;

	/*
	 * Force the panic string to be loaded from the literal pool,
	 * making sure it is a kernel address and not a PC-relative
	 * reference.
	 */
	asm volatile("ldr %0, =__hyp_panic_string" : "=r" (str_va));

	__hyp_do_panic(str_va,
		       spsr,  elr,
		       read_sysreg(esr_el2),   read_sysreg_el2(far),
		       read_sysreg(hpfar_el2), par,
		       (void *)read_sysreg(tpidr_el2));
}

static void __hyp_text __hyp_call_panic_vhe(u64 spsr, u64 elr, u64 par)
{
	panic(__hyp_panic_string,
	      spsr,  elr,
	      read_sysreg_el2(esr),   read_sysreg_el2(far),
	      read_sysreg(hpfar_el2), par,
	      (void *)read_sysreg(tpidr_el2));
}

static hyp_alternate_select(__hyp_call_panic,
			    __hyp_call_panic_nvhe, __hyp_call_panic_vhe,
			    ARM64_RUNS_AT_EL2);

void __hyp_text __noreturn __hyp_panic(void)
{
	u64 spsr = read_sysreg_el2(spsr);
	u64 elr = read_sysreg_el2(elr);
	u64 par = read_sysreg(par_el1);

	if (read_sysreg(vttbr_el2)) {
		struct kvm_vcpu *vcpu;
		struct kvm_cpu_context *host_ctxt;

		vcpu = (struct kvm_vcpu *)read_sysreg(tpidr_el2);
		host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
#ifdef CONFIG_EL2_KERNEL
		write_sysreg(host_ctxt->host_tpidr, tpidr_el2);
#endif
		__deactivate_traps(vcpu);
		__deactivate_vm(vcpu);
		__sysreg_restore_host_state(host_ctxt);
	}

	/* Call panic for real */
	__hyp_call_panic()(spsr, elr, par);

	unreachable();
}
