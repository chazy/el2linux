/*
 * Copyright (C) 2012-2015 - ARM Ltd
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

#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_sysregs.h>

/* Yes, this does nothing, on purpose */
static void __hyp_text __sysreg_do_nothing(struct kvm_cpu_context *ctxt) { }

/*
 * Non-VHE: Both host and guest must save everything.
 *
 * VHE: Host and guest must save tpidr_el1, mdscr_el1, pc, sp_el0 and pstate
 * on every switch.  tpidr_el0, tpidrro_el0, and actlr_el1, and only need
 * to be switched when going to host userspace or a different VCPU.  EL1
 * registers only need to be switched when potentially going to run a
 * different VCPU.  The latter two classes are handled as part of
 * kvm_arch_vcpu_load/put}.
 */

static void __hyp_text __sysreg_save_common_state(struct kvm_cpu_context *ctxt)
{
	ctxt->sys_regs[TPIDR_EL1]	= read_sysreg(tpidr_el1);
	ctxt->sys_regs[MDSCR_EL1]	= read_sysreg(mdscr_el1);
	ctxt->gp_regs.regs.sp		= read_sysreg(sp_el0);
	ctxt->gp_regs.regs.pc		= read_sysreg_el2(elr);
	ctxt->gp_regs.regs.pstate	= read_sysreg_el2(spsr);
}

static void __hyp_text __sysreg_save_user_state(struct kvm_cpu_context *ctxt)
{
	ctxt->sys_regs[ACTLR_EL1]	= read_sysreg(actlr_el1);
	ctxt->sys_regs[TPIDR_EL0]	= read_sysreg(tpidr_el0);
	ctxt->sys_regs[TPIDRRO_EL0]	= read_sysreg(tpidrro_el0);
}

static void __hyp_text __sysreg_save_el1_state(struct kvm_cpu_context *ctxt)
{
	ctxt->sys_regs[MPIDR_EL1]	= read_sysreg(vmpidr_el2);
	ctxt->sys_regs[CSSELR_EL1]	= read_sysreg(csselr_el1);
	ctxt->sys_regs[SCTLR_EL1]	= read_sysreg_el1(sctlr);
	ctxt->sys_regs[CPACR_EL1]	= read_sysreg_el1(cpacr);
	ctxt->sys_regs[TTBR0_EL1]	= read_sysreg_el1(ttbr0);
	ctxt->sys_regs[TTBR1_EL1]	= read_sysreg_el1(ttbr1);
	ctxt->sys_regs[TCR_EL1]		= read_sysreg_el1(tcr);
	ctxt->sys_regs[ESR_EL1]		= read_sysreg_el1(esr);
	ctxt->sys_regs[AFSR0_EL1]	= read_sysreg_el1(afsr0);
	ctxt->sys_regs[AFSR1_EL1]	= read_sysreg_el1(afsr1);
	ctxt->sys_regs[FAR_EL1]		= read_sysreg_el1(far);
	ctxt->sys_regs[MAIR_EL1]	= read_sysreg_el1(mair);
	ctxt->sys_regs[VBAR_EL1]	= read_sysreg_el1(vbar);
	ctxt->sys_regs[CONTEXTIDR_EL1]	= read_sysreg_el1(contextidr);
	ctxt->sys_regs[AMAIR_EL1]	= read_sysreg_el1(amair);
	ctxt->sys_regs[CNTKCTL_EL1]	= read_sysreg_el1(cntkctl);
	ctxt->sys_regs[PAR_EL1]		= read_sysreg(par_el1);

	ctxt->gp_regs.sp_el1		= read_sysreg(sp_el1);
	ctxt->gp_regs.elr_el1		= read_sysreg_el1(elr);
	ctxt->gp_regs.spsr[KVM_SPSR_EL1]= read_sysreg_el1(spsr);

	__sysreg_save_user_state(ctxt);
}

static hyp_alternate_select(__sysreg_call_save_el1_state,
			    __sysreg_save_el1_state, __sysreg_do_nothing,
			    ARM64_HAS_VIRT_HOST_EXTN);

static void __hyp_text __sysreg_save_el2_return_state(struct kvm_cpu_context *ctxt)
{
	ctxt->gp_regs.regs.pc		= read_sysreg_el2(elr);
	ctxt->gp_regs.regs.pstate	= read_sysreg_el2(spsr);
}

static hyp_alternate_select(__sysreg_call_save_host_el2_return_state,
			    __sysreg_save_el2_return_state, __sysreg_do_nothing,
			    ARM64_HAS_VIRT_HOST_EXTN);

void __hyp_text __sysreg_save_host_state(struct kvm_cpu_context *ctxt)
{
	__sysreg_call_save_el1_state()(ctxt);
	__sysreg_save_common_state(ctxt);
	__sysreg_call_save_host_el2_return_state()(ctxt);
}

void __hyp_text __sysreg_save_guest_state(struct kvm_cpu_context *ctxt)
{
	__sysreg_call_save_el1_state()(ctxt);
	__sysreg_save_common_state(ctxt);
	__sysreg_save_el2_return_state(ctxt);
}

static void __hyp_text __sysreg_restore_common_state(struct kvm_cpu_context *ctxt)
{
	write_sysreg(ctxt->sys_regs[TPIDR_EL1],	  tpidr_el1);
	write_sysreg(ctxt->sys_regs[MDSCR_EL1],	  mdscr_el1);
	write_sysreg(ctxt->gp_regs.regs.sp,	  sp_el0);
}

static void __hyp_text __sysreg_restore_user_state(struct kvm_cpu_context *ctxt)
{
	write_sysreg(ctxt->sys_regs[ACTLR_EL1],	  	actlr_el1);
	write_sysreg(ctxt->sys_regs[TPIDR_EL0],	  	tpidr_el0);
	write_sysreg(ctxt->sys_regs[TPIDRRO_EL0], 	tpidrro_el0);
}

static void __hyp_text __sysreg_restore_el1_state(struct kvm_cpu_context *ctxt)
{
	write_sysreg(ctxt->sys_regs[MPIDR_EL1],		vmpidr_el2);
	write_sysreg(ctxt->sys_regs[CSSELR_EL1],	csselr_el1);
	write_sysreg_el1(ctxt->sys_regs[SCTLR_EL1],	sctlr);
	write_sysreg_el1(ctxt->sys_regs[CPACR_EL1],	cpacr);
	write_sysreg_el1(ctxt->sys_regs[TTBR0_EL1],	ttbr0);
	write_sysreg_el1(ctxt->sys_regs[TTBR1_EL1],	ttbr1);
	write_sysreg_el1(ctxt->sys_regs[TCR_EL1],	tcr);
	write_sysreg_el1(ctxt->sys_regs[ESR_EL1],	esr);
	write_sysreg_el1(ctxt->sys_regs[AFSR0_EL1],	afsr0);
	write_sysreg_el1(ctxt->sys_regs[AFSR1_EL1],	afsr1);
	write_sysreg_el1(ctxt->sys_regs[FAR_EL1],	far);
	write_sysreg_el1(ctxt->sys_regs[MAIR_EL1],	mair);
	write_sysreg_el1(ctxt->sys_regs[VBAR_EL1],	vbar);
	write_sysreg_el1(ctxt->sys_regs[CONTEXTIDR_EL1],contextidr);
	write_sysreg_el1(ctxt->sys_regs[AMAIR_EL1],	amair);
	write_sysreg_el1(ctxt->sys_regs[CNTKCTL_EL1], 	cntkctl);
	write_sysreg(ctxt->sys_regs[PAR_EL1],		par_el1);

	write_sysreg(ctxt->gp_regs.sp_el1,		sp_el1);
	write_sysreg_el1(ctxt->gp_regs.elr_el1,		elr);
	write_sysreg_el1(ctxt->gp_regs.spsr[KVM_SPSR_EL1],spsr);

	__sysreg_restore_user_state(ctxt);
}

static hyp_alternate_select(__sysreg_call_restore_el1_state,
			    __sysreg_restore_el1_state, __sysreg_do_nothing,
			    ARM64_HAS_VIRT_HOST_EXTN);

static void __hyp_text
__sysreg_restore_el2_return_state(struct kvm_cpu_context *ctxt)
{
	write_sysreg_el2(ctxt->gp_regs.regs.pc,     elr);
	write_sysreg_el2(ctxt->gp_regs.regs.pstate, spsr);
}

static hyp_alternate_select(__sysreg_call_restore_host_el2_return_state,
			    __sysreg_restore_el2_return_state,
			    __sysreg_do_nothing,
			    ARM64_HAS_VIRT_HOST_EXTN);

void __hyp_text __sysreg_restore_host_state(struct kvm_cpu_context *ctxt)
{
	__sysreg_call_restore_el1_state()(ctxt);
	__sysreg_restore_common_state(ctxt);
	__sysreg_call_restore_host_el2_return_state()(ctxt);
}

void __hyp_text __sysreg_restore_guest_state(struct kvm_cpu_context *ctxt)
{
	__sysreg_call_restore_el1_state()(ctxt);
	__sysreg_restore_common_state(ctxt);
	__sysreg_restore_el2_return_state(ctxt);
}

void __hyp_text __sysreg32_save_state(struct kvm_vcpu *vcpu)
{
	u64 *spsr, *sysreg;

	if (read_sysreg(hcr_el2) & HCR_RW)
		return;

	spsr = vcpu->arch.ctxt.gp_regs.spsr;
	sysreg = vcpu->arch.ctxt.sys_regs;

	spsr[KVM_SPSR_ABT] = read_sysreg(spsr_abt);
	spsr[KVM_SPSR_UND] = read_sysreg(spsr_und);
	spsr[KVM_SPSR_IRQ] = read_sysreg(spsr_irq);
	spsr[KVM_SPSR_FIQ] = read_sysreg(spsr_fiq);

	sysreg[DACR32_EL2] = read_sysreg(dacr32_el2);
	sysreg[IFSR32_EL2] = read_sysreg(ifsr32_el2);

	if (__fpsimd_enabled())
		sysreg[FPEXC32_EL2] = read_sysreg(fpexc32_el2);

	if (vcpu->arch.debug_flags & KVM_ARM64_DEBUG_DIRTY)
		sysreg[DBGVCR32_EL2] = read_sysreg(dbgvcr32_el2);
}

void __hyp_text __sysreg32_restore_state(struct kvm_vcpu *vcpu)
{
	u64 *spsr, *sysreg;

	if (read_sysreg(hcr_el2) & HCR_RW)
		return;

	spsr = vcpu->arch.ctxt.gp_regs.spsr;
	sysreg = vcpu->arch.ctxt.sys_regs;

	write_sysreg(spsr[KVM_SPSR_ABT], spsr_abt);
	write_sysreg(spsr[KVM_SPSR_UND], spsr_und);
	write_sysreg(spsr[KVM_SPSR_IRQ], spsr_irq);
	write_sysreg(spsr[KVM_SPSR_FIQ], spsr_fiq);

	write_sysreg(sysreg[DACR32_EL2], dacr32_el2);
	write_sysreg(sysreg[IFSR32_EL2], ifsr32_el2);

	if (vcpu->arch.debug_flags & KVM_ARM64_DEBUG_DIRTY)
		write_sysreg(sysreg[DBGVCR32_EL2], dbgvcr32_el2);
}

unsigned long __read_sysreg_from_cpu(enum vcpu_sysreg num)
{
	switch (num) {
	case MPIDR_EL1:		return read_sysreg(vmpidr_el2);
	case CSSELR_EL1:	return read_sysreg(csselr_el1);
	case SCTLR_EL1:		return read_sysreg_el1(sctlr);
	case ACTLR_EL1:		return read_sysreg(actlr_el1);
	case CPACR_EL1:		return read_sysreg_el1(cpacr);
	case TTBR0_EL1:		return read_sysreg_el1(ttbr0);
	case TTBR1_EL1:		return read_sysreg_el1(ttbr1);
	case TCR_EL1:		return read_sysreg_el1(tcr);
	case ESR_EL1:		return read_sysreg_el1(esr);
	case AFSR0_EL1:		return read_sysreg_el1(afsr0);
	case AFSR1_EL1:		return read_sysreg_el1(afsr1);
	case FAR_EL1:		return read_sysreg_el1(far);
	case MAIR_EL1:		return read_sysreg_el1(mair);
	case VBAR_EL1:		return read_sysreg_el1(vbar);
	case CONTEXTIDR_EL1:	return read_sysreg_el1(contextidr);
	case TPIDR_EL0:		return read_sysreg(tpidr_el0);
	case TPIDRRO_EL0:	return read_sysreg(tpidrro_el0);
	case TPIDR_EL1:		return read_sysreg(tpidr_el1);
	case AMAIR_EL1:		return read_sysreg_el1(amair);
	case CNTKCTL_EL1:	return read_sysreg_el1(cntkctl);
	case PAR_EL1:		return read_sysreg(par_el1);
	case MDSCR_EL1:		return read_sysreg(mdscr_el1);
	case MDCCINT_EL1:	BUG(); return 0;

	/* 32bit specific registers. Keep them at the end of the range */
	case DACR32_EL2:	return read_sysreg(dacr32_el2);
	case IFSR32_EL2:	return read_sysreg(ifsr32_el2);
	case FPEXC32_EL2:	return read_sysreg(fpexc32_el2);
	case DBGVCR32_EL2:	return read_sysreg(dbgvcr32_el2);
	default:		BUG(); return 0;
	}
}

void __write_sysreg_to_cpu(enum vcpu_sysreg num, unsigned long v)
{
	switch (num) {
	case MPIDR_EL1:		write_sysreg(v, vmpidr_el2);	break;
	case CSSELR_EL1:	write_sysreg(v, csselr_el1);	break;
	case SCTLR_EL1:		write_sysreg_el1(v, sctlr); 	break;
	case ACTLR_EL1:		write_sysreg(v, actlr_el1); 	break;
	case CPACR_EL1:		write_sysreg_el1(v, cpacr); 	break;
	case TTBR0_EL1:		write_sysreg_el1(v, ttbr0); 	break;
	case TTBR1_EL1:		write_sysreg_el1(v, ttbr1); 	break;
	case TCR_EL1:		write_sysreg_el1(v, tcr);	break;
	case ESR_EL1:		write_sysreg_el1(v, esr);	break;
	case AFSR0_EL1:		write_sysreg_el1(v, afsr0);	break;
	case AFSR1_EL1:		write_sysreg_el1(v, afsr1);	break;
	case FAR_EL1:		write_sysreg_el1(v, far);	break;
	case MAIR_EL1:		write_sysreg_el1(v, mair);	break;
	case VBAR_EL1:		write_sysreg_el1(v, vbar);	break;
	case CONTEXTIDR_EL1:	write_sysreg_el1(v, contextidr);break;
	case TPIDR_EL0:		write_sysreg(v, tpidr_el0);	break;
	case TPIDRRO_EL0:	write_sysreg(v, tpidrro_el0);	break;
	case TPIDR_EL1:		write_sysreg(v, tpidr_el1);	break;
	case AMAIR_EL1:		write_sysreg_el1(v, amair);	break;
	case CNTKCTL_EL1:	write_sysreg_el1(v, cntkctl);	break;
	case PAR_EL1:		write_sysreg(v, par_el1);	break;
	case MDSCR_EL1:		write_sysreg(v, mdscr_el1);	break;
	case MDCCINT_EL1:	BUG(); break;

	/* 32bit specific registers. Keep them at the end of the range */
	case DACR32_EL2:	write_sysreg(v, dacr32_el2);	break;
	case IFSR32_EL2:	write_sysreg(v, ifsr32_el2);	break;
	case FPEXC32_EL2:	write_sysreg(v, fpexc32_el2);	break;
	case DBGVCR32_EL2:	write_sysreg(v, dbgvcr32_el2);	break;
	default:		BUG(); break;
	}
}

/**
 * kvm_vcpu_load_sysregs - Load guest system register to physical CPU
 *
 * @vcpu: The VCPU pointer
 *
 * If the kernel runs in EL2 then load the system register state for the VCPU
 * for EL1 onto the physical CPU so that we can go back and foward between the
 * VM and the hypervisor without switching all this state around.
 */
void kvm_vcpu_load_sysregs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;

	if (!is_kernel_in_hyp_mode() || vcpu->arch.ctxt.sysregs_loaded_on_cpu)
		return;

	host_ctxt = vcpu->arch.host_cpu_context;
	guest_ctxt = &vcpu->arch.ctxt;

	/* Save host user state */
	__sysreg_save_user_state(host_ctxt);
	host_ctxt->gp_regs.regs.pc	= read_sysreg_el2(elr);
	host_ctxt->gp_regs.regs.pstate	= read_sysreg_el2(spsr);

	/* Load guest EL1 and user state */
	__sysreg_restore_el1_state(guest_ctxt);

	vcpu->arch.ctxt.sysregs_loaded_on_cpu = true;
}

/**
 * kvm_vcpu_put_sysregs - Restore host system register state to physical CPU
 *
 * @vcpu: The VCPU pointer
 *
 * If the kernel runs in EL2 and the physical register state belongs to the
 * VCPU, then restore the system register state for the host for EL1 onto the
 * physical CPU so that we can run userspace and other threads on this
 * physical CPU.
 */
void kvm_vcpu_put_sysregs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;

	if (!is_kernel_in_hyp_mode() || !vcpu->arch.ctxt.sysregs_loaded_on_cpu)
		return;

	host_ctxt = vcpu->arch.host_cpu_context;
	guest_ctxt = &vcpu->arch.ctxt;

	/* Save guest EL1 and user state */
	__sysreg_save_el1_state(guest_ctxt);

	/* Restore host user state */
	__sysreg_restore_user_state(host_ctxt);
	write_sysreg_el2(host_ctxt->gp_regs.regs.pc,	  elr);
	write_sysreg_el2(host_ctxt->gp_regs.regs.pstate, spsr);

	vcpu->arch.ctxt.sysregs_loaded_on_cpu = false;
}
