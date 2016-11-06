/*
 * Copyright (C) 2016 - Columbia University
 * Author: Shih-Wei Li <shihwei@cs.columbia.edu>
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
#include <kvm/arm_vgic.h>
#include <linux/irqchip/arm-gic.h>


static unsigned long __hyp_text pre_early_handle_mmio(struct kvm_vcpu *vcpu,
						struct kvm_cpu_context *host_ctxt,
						struct kvm_cpu_context *guest_ctxt,
						int len)
{
	unsigned long rt, data;

	/*
	 * We need to resotre host's sp_el0 and tpidr_el1 in order
	 * to grab spinlocks.
	 */
	__early_sysreg_save_state(guest_ctxt);
	__early_sysreg_restore_state(host_ctxt);

	rt = kvm_vcpu_dabt_get_rd(vcpu);
	vcpu->arch.mmio_decode.rt = rt;
	data = vcpu_data_guest_to_host(vcpu, vcpu_get_reg(vcpu, rt), len);

	return data;
}

static void __hyp_text post_early_handle_mmio(struct kvm_vcpu *vcpu,
					struct kvm_cpu_context *host_ctxt,
					struct kvm_cpu_context *guest_ctxt,
					bool no_skip)
{
	if (!no_skip) {
		guest_ctxt->gp_regs.regs.pc = read_sysreg_el2(elr);
		vcpu->stat.vgic_early_exits++;
		kvm_skip_instr(vcpu, kvm_vcpu_trap_il_is32bit(vcpu));
		write_sysreg_el2(guest_ctxt->gp_regs.regs.pc, elr);
	}

	__early_sysreg_save_state(host_ctxt);
	__early_sysreg_restore_state(guest_ctxt);
}

static bool inline is_vgic_write_senable(u32 offset)
{
	return (offset >= GIC_DIST_ENABLE_SET) &&
		(offset < (GIC_DIST_ENABLE_SET + 0x80));
}

bool __hyp_text __early_handle_gicd_access(struct kvm_vcpu *vcpu, u64 fault_ipa,
					   unsigned long host_tpidr_el2)
{
	struct vgic_dist *dist = &vcpu->kvm->arch.vgic;
	struct kvm_cpu_context *guest_ctxt;
	struct kvm_cpu_context *host_ctxt;
	bool ret = true, is_write = kvm_vcpu_dabt_iswrite(vcpu);
	int len = kvm_vcpu_dabt_get_as(vcpu);
	unsigned long data;
	u32 offset;

	if (!is_write)
		goto out;

	/* Handle GIC Dist operations */
	if ((fault_ipa & ~(KVM_VGIC_V2_DIST_SIZE-1)) != dist->vgic_dist_base)
		goto out;
	else {
		host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
		guest_ctxt = &vcpu->arch.ctxt;

		data = pre_early_handle_mmio(vcpu, host_ctxt, guest_ctxt, len);
		/*
		 * The host used tpidr_el2 when it runs in EL2, so we'll have
		 * switch to its context before jumping to host.
		 */
		write_sysreg(host_tpidr_el2, tpidr_el2);

		offset = fault_ipa & (KVM_VGIC_V2_DIST_SIZE-1);

		if (is_vgic_write_senable(offset))
			ret = early_vgic_mmio_write_senable(vcpu, fault_ipa, len, data);
		else if (offset == GIC_DIST_SOFTINT) {
			vgic_mmio_write_sgir(vcpu, fault_ipa, len, data);
			ret = false;
		}

		post_early_handle_mmio(vcpu, host_ctxt, guest_ctxt, ret);

		/* Restore tpidr_el2 to point to vcpu */
		vcpu = kern_hyp_va(vcpu);
		write_sysreg(vcpu, tpidr_el2);
	}

out:
	return ret;
}

bool __hyp_text __early_handle_mmio(struct kvm_vcpu *vcpu, unsigned long host_tpidr_el2)
{
	u64 fault_ipa, far;
	bool ret = true;

	fault_ipa = (vcpu->arch.fault.hpfar_el2 & HPFAR_MASK) << 8;
	far = vcpu->arch.fault.far_el2;
	fault_ipa |= far & ((1 << 12) - 1);

	ret = __early_handle_gicd_access(vcpu, fault_ipa, host_tpidr_el2);

	return ret;
}
