/*
 * Copyright (C) 2015, 2016 ARM Ltd.
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

#include <linux/irqchip/arm-gic.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <kvm/arm_vgic.h>
#include <asm/kvm_mmu.h>

#include "vgic.h"
#include "../trace.h"

static inline void vgic_v2_write_lr(int lr, u32 val)
{
	void __iomem *base = kvm_vgic_global_state.vctrl_base;

	writel_relaxed(val, base + GICH_LR0 + (lr * 4));
}

void vgic_v2_init_lrs(void)
{
	int i;

	for (i = 0; i < kvm_vgic_global_state.nr_lr; i++)
		vgic_v2_write_lr(i, 0);
}

void vgic_v2_clear_uie(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpuif = &vcpu->arch.vgic_cpu.vgic_v2;
	cpuif->vgic_hcr &= ~GICH_HCR_UIE;
}

void vgic_v2_handle_maintenance(struct kvm_vcpu *vcpu)
{
	void __iomem *base = kvm_vgic_global_state.vctrl_base;

	/*
	 * Disable maintenance interrupt as we only use it to generate an exit
	 * from the VM.
	 */
	writel_relaxed(0, base + GICH_HCR);
}

void vgic_v2_set_underflow(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpuif = &vcpu->arch.vgic_cpu.vgic_v2;

	cpuif->vgic_hcr |= GICH_HCR_UIE;
}

static bool lr_signals_eoi_mi(u32 lr_val)
{
	return !(lr_val & GICH_LR_STATE) && (lr_val & GICH_LR_EOI) &&
	       !(lr_val & GICH_LR_HW);
}

/*
 * transfer the content of the LRs back into the corresponding ap_list:
 * - active bit is transferred as is
 * - pending bit is
 *   - transferred as is in case of edge sensitive IRQs
 *   - set to the line-level (resample time) for level sensitive IRQs
 */
void vgic_v2_fold_lr_state(struct kvm_vcpu *vcpu, int used_lrs)
{
	struct vgic_v2_cpu_if *cpuif = &vcpu->arch.vgic_cpu.vgic_v2;
	int lr;

	for (lr = 0; lr < used_lrs; lr++) {
		u32 val = cpuif->vgic_lr[lr];
		u32 intid = val & GICH_LR_VIRTUALID;
		struct vgic_irq *irq;

		/* Notify fds when the guest EOI'ed a level-triggered SPI */
		if (lr_signals_eoi_mi(val) && intid >= VGIC_NR_PRIVATE_IRQS)
			kvm_notify_acked_irq(vcpu->kvm, 0,
					     intid - VGIC_NR_PRIVATE_IRQS);

		irq = vgic_get_irq(vcpu->kvm, vcpu, intid);

		spin_lock(&irq->irq_lock);

		/* Always preserve the active bit */
		irq->active = !!(val & GICH_LR_ACTIVE_BIT);

		/* Edge is the only case where we preserve the pending bit */
		if (irq->config == VGIC_CONFIG_EDGE &&
		    (val & GICH_LR_PENDING_BIT)) {
			irq->pending = true;

			if (vgic_irq_is_sgi(intid)) {
				u32 cpuid = val & GICH_LR_PHYSID_CPUID;

				cpuid >>= GICH_LR_PHYSID_CPUID_SHIFT;
				irq->source |= (1 << cpuid);
			}
		}

		/*
		 * Clear soft pending state when level irqs have been acked.
		 * Always regenerate the pending state.
		 */
		if (irq->config == VGIC_CONFIG_LEVEL) {
			if (!(val & GICH_LR_PENDING_BIT))
				irq->soft_pending = false;

			irq->pending = irq->line_level || irq->soft_pending;
		}

		spin_unlock(&irq->irq_lock);
		vgic_put_irq(vcpu->kvm, irq);
	}
}

/*
 * Populates the particular LR with the state of a given IRQ:
 * - for an edge sensitive IRQ the pending state is cleared in struct vgic_irq
 * - for a level sensitive IRQ the pending state value is unchanged;
 *   it is dictated directly by the input level
 *
 * If @irq describes an SGI with multiple sources, we choose the
 * lowest-numbered source VCPU and clear that bit in the source bitmap.
 *
 * The irq_lock must be held by the caller.
 */
void vgic_v2_populate_lr(struct kvm_vcpu *vcpu, struct vgic_irq *irq, int lr)
{
	u32 val = irq->intid;

	if (irq->pending) {
		/* The active+pending state cannot be used for HW irqs */
		if (!(irq->hw && irq->active))
			val |= GICH_LR_PENDING_BIT;

		if (irq->config == VGIC_CONFIG_EDGE)
			irq->pending = false;

		if (vgic_irq_is_sgi(irq->intid)) {
			u32 src = ffs(irq->source);

			BUG_ON(!src);
			val |= (src - 1) << GICH_LR_PHYSID_CPUID_SHIFT;
			irq->source &= ~(1 << (src - 1));
			if (irq->source)
				irq->pending = true;
		}
	}

	if (irq->active)
		val |= GICH_LR_ACTIVE_BIT;

	if (irq->hw) {
		val |= GICH_LR_HW;
		val |= irq->hwintid << GICH_LR_PHYSID_CPUID_SHIFT;
	} else {
		if (irq->config == VGIC_CONFIG_LEVEL)
			val |= GICH_LR_EOI;
	}

	/* The GICv2 LR only holds five bits of priority. */
	val |= (irq->priority >> 3) << GICH_LR_PRIORITY_SHIFT;

	vcpu->arch.vgic_cpu.vgic_v2.vgic_lr[lr] = val;
}

void vgic_v2_clear_lr(struct kvm_vcpu *vcpu, int lr)
{
	vcpu->arch.vgic_cpu.vgic_v2.vgic_lr[lr] = 0;
}

/**
 * vgic_v2_deliver_virq_now - Directly deliver vIRQ into another CPU
 *
 * We take advantage of a feature present on GICv2 only, where the hypervisor
 * control interface for each CPU is available from other CPUs at a fixed
 * address.  The challenge here is synchronization, because we will be writing
 * directly into the hardware list registers from multiple CPUs.
 *
 * These are the actions that can access a CPU's LRs:
 *   1. vgic_flush_lr_state
 *   2. vgic_sync_lr_state
 *   3. deliver_virq_now (can happen multiple times in parallel from different
 *      PCPUs to the same PCPU).
 *
 * (1) and (2) both take the ap_list_lock around critical sections allocating
 * LRs, *or* they work based on the used_lrs value.  As we will allocate an LR
 * for this purpose we will bump the used_lrs, so we have to make sure other
 * CPUs can only observe the updated used_lrs value after we're finished
 * populating an LR, and also only accesses the LRs once.
 *
 * We also have to make sure that we only write into a hardware LR before the
 * physical CPU runs vgic_sync, since otherwise that LR could linger around
 * when another vcpu gets scheduled onto the CPU and we loose edge-triggered
 * interrupt semantics.  We can accomplish this by locking and unlocking the
 * ap_list_lock in the sync path.  TODO: Attempt making this lockless by only
 * grabbing the lock when necessary.
 *
 * (3) is synchronized simply via holding the AP list lock during this
 * operation.
 *
 * Return true if direct delivery was successful */
bool vgic_v2_deliver_virq_now(struct kvm_vcpu *vcpu, struct vgic_irq *irq)
{
	void __iomem *base;
	struct vgic_v2_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v2;
	int used_lrs = vcpu->arch.vgic_cpu.used_lrs;
	int lr = used_lrs++;
	int cpu = vcpu->cpu;

	if (vcpu->mode != IN_GUEST_MODE)
		return false;

	if (used_lrs > kvm_vgic_global_state.nr_lr)
		return false;

	base = kvm_vgic_global_state.vctrl_cpubase[cpu];
	vgic_v2_populate_lr(vcpu, irq, lr);
	writel(cpu_if->vgic_lr[lr], base + GICH_LR0 + (lr * 4));

	smp_wmb(); /* Paired with smp_rmb() in __vgic_v2_restore_state and
	            * save_rlrsr. */
	WRITE_ONCE(vcpu->arch.vgic_cpu.used_lrs, used_lrs);

	trace_vgic_v2_deliver_virq_now(irq->intid, vcpu->vcpu_id,
				       vcpu->cpu, used_lrs);

	return true;
}


void vgic_v2_set_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcrp)
{
	struct vgic_dist *vgic = &vcpu->kvm->arch.vgic;
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	u32 vmcr;

	vmcr  = (vmcrp->ctlr << GICH_VMCR_CTRL_SHIFT) & GICH_VMCR_CTRL_MASK;
	vmcr |= (vmcrp->abpr << GICH_VMCR_ALIAS_BINPOINT_SHIFT) &
		GICH_VMCR_ALIAS_BINPOINT_MASK;
	vmcr |= (vmcrp->bpr << GICH_VMCR_BINPOINT_SHIFT) &
		GICH_VMCR_BINPOINT_MASK;
	vmcr |= (vmcrp->pmr << GICH_VMCR_PRIMASK_SHIFT) &
		GICH_VMCR_PRIMASK_MASK;

	if (vgic_cpu->loaded)
		writel_relaxed(vmcr, vgic->vctrl_base + GICH_VMCR);

	vcpu->arch.vgic_cpu.vgic_v2.vgic_vmcr = vmcr;
}

void vgic_v2_get_vmcr(struct kvm_vcpu *vcpu, struct vgic_vmcr *vmcrp)
{
	struct vgic_dist *vgic = &vcpu->kvm->arch.vgic;
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	u32 vmcr;

	if (vgic_cpu->loaded) {
		vmcr = readl_relaxed(vgic->vctrl_base + GICH_VMCR);
		vgic_cpu->vgic_v2.vgic_vmcr = vmcr;
	} else {
		vmcr = vgic_cpu->vgic_v2.vgic_vmcr;
	}

	vmcrp->ctlr = (vmcr & GICH_VMCR_CTRL_MASK) >>
			GICH_VMCR_CTRL_SHIFT;
	vmcrp->abpr = (vmcr & GICH_VMCR_ALIAS_BINPOINT_MASK) >>
			GICH_VMCR_ALIAS_BINPOINT_SHIFT;
	vmcrp->bpr  = (vmcr & GICH_VMCR_BINPOINT_MASK) >>
			GICH_VMCR_BINPOINT_SHIFT;
	vmcrp->pmr  = (vmcr & GICH_VMCR_PRIMASK_MASK) >>
			GICH_VMCR_PRIMASK_SHIFT;
}

void vgic_v2_enable(struct kvm_vcpu *vcpu)
{
	/*
	 * By forcing VMCR to zero, the GIC will restore the binary
	 * points to their reset values. Anything else resets to zero
	 * anyway.
	 */
	vcpu->arch.vgic_cpu.vgic_v2.vgic_vmcr = 0;
	vcpu->arch.vgic_cpu.vgic_v2.vgic_elrsr = ~0;

	/* Get the show on the road... */
	vcpu->arch.vgic_cpu.vgic_v2.vgic_hcr = GICH_HCR_EN;
}

/* check for overlapping regions and for regions crossing the end of memory */
static bool vgic_v2_check_base(gpa_t dist_base, gpa_t cpu_base)
{
	if (dist_base + KVM_VGIC_V2_DIST_SIZE < dist_base)
		return false;
	if (cpu_base + KVM_VGIC_V2_CPU_SIZE < cpu_base)
		return false;

	if (dist_base + KVM_VGIC_V2_DIST_SIZE <= cpu_base)
		return true;
	if (cpu_base + KVM_VGIC_V2_CPU_SIZE <= dist_base)
		return true;

	return false;
}

int vgic_v2_map_resources(struct kvm *kvm)
{
	struct vgic_dist *dist = &kvm->arch.vgic;
	int ret = 0;

	if (vgic_ready(kvm))
		goto out;

	if (IS_VGIC_ADDR_UNDEF(dist->vgic_dist_base) ||
	    IS_VGIC_ADDR_UNDEF(dist->vgic_cpu_base)) {
		kvm_err("Need to set vgic cpu and dist addresses first\n");
		ret = -ENXIO;
		goto out;
	}

	if (!vgic_v2_check_base(dist->vgic_dist_base, dist->vgic_cpu_base)) {
		kvm_err("VGIC CPU and dist frames overlap\n");
		ret = -EINVAL;
		goto out;
	}

	/*
	 * Initialize the vgic if this hasn't already been done on demand by
	 * accessing the vgic state from userspace.
	 */
	ret = vgic_init(kvm);
	if (ret) {
		kvm_err("Unable to initialize VGIC dynamic data structures\n");
		goto out;
	}

	ret = vgic_register_dist_iodev(kvm, dist->vgic_dist_base, VGIC_V2);
	if (ret) {
		kvm_err("Unable to register VGIC MMIO regions\n");
		goto out;
	}

	ret = kvm_phys_addr_ioremap(kvm, dist->vgic_cpu_base,
				    kvm_vgic_global_state.vcpu_base,
				    KVM_VGIC_V2_CPU_SIZE, true);
	if (ret) {
		kvm_err("Unable to remap VGIC CPU to VCPU\n");
		goto out;
	}

	dist->ready = true;

out:
	if (ret)
		kvm_vgic_destroy(kvm);
	return ret;
}

/**
 * vgic_v2_probe - probe for a GICv2 compatible interrupt controller in DT
 * @node:	pointer to the DT node
 *
 * Returns 0 if a GICv2 has been found, returns an error code otherwise
 */
int vgic_v2_probe(const struct gic_kvm_info *info)
{
	int ret;
	u32 vtr;
	void __iomem *base;
	int i;

	if (!info->vctrl.start) {
		kvm_err("GICH not present in the firmware table\n");
		return -ENXIO;
	}

	if (!PAGE_ALIGNED(info->vcpu.start)) {
		kvm_err("GICV physical address 0x%llx not page aligned\n",
			(unsigned long long)info->vcpu.start);
		return -ENXIO;
	}

	if (!PAGE_ALIGNED(resource_size(&info->vcpu))) {
		kvm_err("GICV size 0x%llx not a multiple of page size 0x%lx\n",
			(unsigned long long)resource_size(&info->vcpu),
			PAGE_SIZE);
		return -ENXIO;
	}

	kvm_vgic_global_state.vctrl_base = ioremap(info->vctrl.start,
						   resource_size(&info->vctrl));
	if (!kvm_vgic_global_state.vctrl_base) {
		kvm_err("Cannot ioremap GICH\n");
		return -ENOMEM;
	}

	/* TODO: Hack for AMD Seattle */
	base = ioremap(0xe1150000, 0x10000);
	if (!base) {
		kvm_err("Cannot ioremap GICH cpu bases\n");
		return -ENOMEM;
	}
	for (i = 0; i < 8; i++) {
		kvm_vgic_global_state.vctrl_cpubase[i] = base + i * 0x200;
	}

	vtr = readl_relaxed(kvm_vgic_global_state.vctrl_base + GICH_VTR);
	kvm_vgic_global_state.nr_lr = (vtr & 0x3f) + 1;

	ret = kvm_register_vgic_device(KVM_DEV_TYPE_ARM_VGIC_V2);
	if (ret) {
		kvm_err("Cannot register GICv2 KVM device\n");
		iounmap(kvm_vgic_global_state.vctrl_base);
		return ret;
	}

	ret = create_hyp_io_mappings(kvm_vgic_global_state.vctrl_base,
				     kvm_vgic_global_state.vctrl_base +
					 resource_size(&info->vctrl),
				     info->vctrl.start);
	if (ret) {
		kvm_err("Cannot map VCTRL into hyp\n");
		kvm_unregister_device_ops(KVM_DEV_TYPE_ARM_VGIC_V2);
		iounmap(kvm_vgic_global_state.vctrl_base);
		return ret;
	}

	kvm_vgic_global_state.can_emulate_gicv2 = true;
	kvm_vgic_global_state.vcpu_base = info->vcpu.start;
	kvm_vgic_global_state.type = VGIC_V2;
	kvm_vgic_global_state.max_gic_vcpus = VGIC_V2_MAX_CPUS;

	kvm_info("vgic-v2@%llx\n", info->vctrl.start);

	return 0;
}

void vgic_v2_load(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v2;
	struct vgic_dist *vgic = &vcpu->kvm->arch.vgic;
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	if (!kvm_runs_in_hyp())
		return;

	if (vgic_cpu->loaded)
		return;

	writel_relaxed(cpu_if->vgic_vmcr, vgic->vctrl_base + GICH_VMCR);

	vgic_cpu->loaded = true;
}

void vgic_v2_put(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v2;
	struct vgic_dist *vgic = &vcpu->kvm->arch.vgic;
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	int i;

	if (!kvm_runs_in_hyp())
		return;

	if (!vgic_cpu->loaded)
		return;

	cpu_if->vgic_vmcr = readl_relaxed(vgic->vctrl_base + GICH_VMCR);

	vgic_cpu->loaded = false;

	for (i = 0; i < kvm_vgic_global_state.nr_lr; i++)
		vgic_v2_write_lr(i, 0);
}

bool vgic_v2_irq_is_active_in_lr(struct kvm_vcpu *vcpu, int intid,
				 bool *act, bool *pend)
{
	struct vgic_v2_cpu_if *cpuif = &vcpu->arch.vgic_cpu.vgic_v2;
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	int i;

	for (i = 0; i < vgic_cpu->used_lrs; i++) {
		u32 val = cpuif->vgic_lr[i];

		if ((val & GICH_LR_VIRTUALID) != intid)
			continue;

		if (act)
			*act = val & GICH_LR_ACTIVE_BIT;
		if (pend)
			*pend = val & GICH_LR_PENDING_BIT;
		return true;
	}

	return false;
}
