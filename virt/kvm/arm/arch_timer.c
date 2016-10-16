/*
 * Copyright (C) 2012 ARM Ltd.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/irq.h>

#include <clocksource/arm_arch_timer.h>
#include <asm/arch_timer.h>
#include <asm/kvm_hyp.h>

#include <kvm/arm_vgic.h>
#include <kvm/arm_arch_timer.h>

#include "trace.h"

static struct timecounter *timecounter;
static struct workqueue_struct *wqueue;
static unsigned int host_vtimer_irq;
static u32 host_vtimer_irq_flags;

static bool kvm_timer_irq_can_fire(struct kvm_vcpu *vcpu);
static void kvm_timer_update_irq(struct kvm_vcpu *vcpu, bool new_level);

static cycle_t kvm_phys_timer_read(void)
{
	return timecounter->cc->read(timecounter->cc);
}

static bool timer_is_armed(struct arch_timer_cpu *timer)
{
	return timer->armed;
}

/* timer_arm: as in "arm the timer", not as in ARM the company */
static void timer_arm(struct arch_timer_cpu *timer, u64 ns)
{
	timer->armed = true;
	hrtimer_start(&timer->timer, ktime_add_ns(ktime_get(), ns),
		      HRTIMER_MODE_ABS);
}

static void timer_disarm(struct arch_timer_cpu *timer)
{
	if (timer_is_armed(timer)) {
		hrtimer_cancel(&timer->timer);
		cancel_work_sync(&timer->expired);
		timer->armed = false;
	}
}

static irqreturn_t kvm_arch_timer_handler(int irq, void *dev_id)
{
	struct kvm_vcpu *vcpu = *(struct kvm_vcpu **)dev_id;
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	if (!timer->irq.level) {
		timer->cntv_ctl = read_sysreg_el0(cntv_ctl);
		if (kvm_timer_irq_can_fire(vcpu))
			kvm_timer_update_irq(vcpu, true);
	}

	return IRQ_HANDLED;
}

/*
 * Work function for handling the backup timer that we schedule when a vcpu is
 * no longer running, but had a timer programmed to fire in the future.
 */
static void kvm_timer_inject_irq_work(struct work_struct *work)
{
	struct kvm_vcpu *vcpu;

	vcpu = container_of(work, struct kvm_vcpu, arch.timer_cpu.expired);
	vcpu->arch.timer_cpu.armed = false;

	WARN_ON(!kvm_timer_should_fire(vcpu));

	/*
	 * If the vcpu is blocked we want to wake it up so that it will see
	 * the timer has expired when entering the guest.
	 */
	kvm_vcpu_kick(vcpu);
}

static u64 kvm_timer_compute_delta(struct kvm_vcpu *vcpu)
{
	cycle_t cval, now;

	cval = vcpu->arch.timer_cpu.cntv_cval;
	now = kvm_phys_timer_read() - vcpu->kvm->arch.timer.cntvoff;

	if (now < cval) {
		u64 ns;

		ns = cyclecounter_cyc2ns(timecounter->cc,
					 cval - now,
					 timecounter->mask,
					 &timecounter->frac);
		return ns;
	}

	return 0;
}

static enum hrtimer_restart kvm_timer_expire(struct hrtimer *hrt)
{
	struct arch_timer_cpu *timer;
	struct kvm_vcpu *vcpu;
	u64 ns;

	timer = container_of(hrt, struct arch_timer_cpu, timer);
	vcpu = container_of(timer, struct kvm_vcpu, arch.timer_cpu);

	/*
	 * Check that the timer has really expired from the guest's
	 * PoV (NTP on the host may have forced it to expire
	 * early). If we should have slept longer, restart it.
	 */
	ns = kvm_timer_compute_delta(vcpu);
	if (unlikely(ns)) {
		hrtimer_forward_now(hrt, ns_to_ktime(ns));
		return HRTIMER_RESTART;
	}

	queue_work(wqueue, &timer->expired);
	return HRTIMER_NORESTART;
}

static bool kvm_timer_irq_can_fire(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	return !(timer->cntv_ctl & ARCH_TIMER_CTRL_IT_MASK) &&
		(timer->cntv_ctl & ARCH_TIMER_CTRL_ENABLE);
}

bool kvm_timer_should_fire(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	cycle_t cval, now;

	/*
	 * If somebody is asking if the timer should fire, but the timer state
	 * is maintained in hardware, we need to take a snapshot of the
	 * current hardware state first.
	 */
	if (timer->loaded) {
		timer->cntv_ctl = read_sysreg_el0(cntv_ctl);
		timer->cntv_cval = read_sysreg_el0(cntv_cval);
	}

	if (!kvm_timer_irq_can_fire(vcpu))
		return false;

	cval = timer->cntv_cval;
	now = kvm_phys_timer_read() - vcpu->kvm->arch.timer.cntvoff;

	return cval <= now;
}

static void kvm_timer_update_irq(struct kvm_vcpu *vcpu, bool new_level)
{
	int ret;
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	BUG_ON(!vgic_initialized(vcpu->kvm));

	timer->irq.level = new_level;
	trace_kvm_timer_update_irq(vcpu->vcpu_id, timer->irq.irq,
				   timer->irq.level);
	ret = kvm_vgic_inject_mapped_irq(vcpu->kvm, vcpu->vcpu_id,
					 timer->irq.irq,
					 timer->irq.level);
	WARN_ON(ret);
}

/*
 * Check if there was a change in the timer state (should we raise or lower
 * the line level to the GIC).
 */
static int kvm_timer_update_state(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	/*
	 * If userspace modified the timer registers via SET_ONE_REG before
	 * the vgic was initialized, we mustn't set the timer->irq.level value
	 * because the guest would never see the interrupt.  Instead wait
	 * until we call this function from kvm_timer_flush_hwstate.
	 */
	if (!vgic_initialized(vcpu->kvm) || !timer->enabled)
		return -ENODEV;

	if (kvm_timer_should_fire(vcpu) != timer->irq.level)
		kvm_timer_update_irq(vcpu, !timer->irq.level);

	return 0;
}

static void timer_save_state(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	unsigned long flags;

	local_irq_save(flags);

	if (!timer->loaded)
		goto out;

	if (timer->enabled) {
		timer->cntv_ctl = read_sysreg_el0(cntv_ctl);
		timer->cntv_cval = read_sysreg_el0(cntv_cval);
	}

	/* Disable the virtual timer */
	write_sysreg_el0(0, cntv_ctl);

	timer->loaded = false;
out:
	local_irq_restore(flags);
}

/*
 * Schedule the background timer before calling kvm_vcpu_block, so that this
 * thread is removed from its waitqueue and made runnable when there's a timer
 * interrupt to handle.
 */
void kvm_timer_schedule(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	BUG_ON(timer_is_armed(timer));

	timer_save_state(vcpu);

	/*
	 * No need to schedule a background timer if the guest timer has
	 * already expired, because kvm_vcpu_block will return before putting
	 * the thread to sleep.
	 */
	if (kvm_timer_should_fire(vcpu))
		return;

	/*
	 * If the timer is not capable of raising interrupts (disabled or
	 * masked), then there's no more work for us to do.
	 */
	if (!kvm_timer_irq_can_fire(vcpu))
		return;

	/*  The timer has not yet expired, schedule a background timer */
	timer_arm(timer, kvm_timer_compute_delta(vcpu));
}

static void timer_restore_state(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	unsigned long flags;

	local_irq_save(flags);

	if (timer->loaded)
		goto out;

	if (timer->enabled) {
		write_sysreg_el0(timer->cntv_cval, cntv_cval);
		isb();
		write_sysreg_el0(timer->cntv_ctl, cntv_ctl);
	}

	timer->loaded = true;
out:
	local_irq_restore(flags);
}

void kvm_timer_unschedule(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	timer_disarm(timer);

	timer_restore_state(vcpu);
}

static void set_cntvoff(u64 cntvoff)
{
	u32 low = cntvoff & GENMASK(31, 0);
	u32 high = (cntvoff >> 32) & GENMASK(31, 0);
	kvm_call_hyp(__kvm_timer_set_cntvoff, low, high);
}

void kvm_timer_vcpu_load(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	bool phys_active;
	int ret;

	if (timer->irq.level || kvm_vgic_map_is_active(vcpu, timer->irq.irq))
		phys_active = true;
	else
		phys_active = false;
	ret = irq_set_irqchip_state(host_vtimer_irq,
				    IRQCHIP_STATE_ACTIVE,
				    phys_active);
	WARN_ON(ret);

	set_cntvoff(vcpu->kvm->arch.timer.cntvoff);
	timer_restore_state(vcpu);

	if (kvm_runs_in_hyp())
		disable_phys_timer();
}

void kvm_timer_vcpu_put(struct kvm_vcpu *vcpu)
{
	if (kvm_runs_in_hyp())
		enable_phys_timer();

	timer_save_state(vcpu);

	set_cntvoff(0);
}

/**
 * kvm_timer_sync_hwstate - sync timer state from cpu
 * @vcpu: The vcpu pointer
 *
 * Check if the virtual timer has expired while we were running in the guest,
 * and inject an interrupt if that was the case.
 */
void kvm_timer_sync_hwstate(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	BUG_ON(timer_is_armed(timer));

	/*
	 * If we entered the guest with the timer output asserted we have to
	 * check if the guest has modified the timer so that we should lower
	 * the line at this point.
	 */
	if (timer->irq.level) {
		timer->cntv_ctl = read_sysreg_el0(cntv_ctl);
		timer->cntv_cval = read_sysreg_el0(cntv_cval);
		if (!kvm_timer_should_fire(vcpu))
			kvm_timer_update_irq(vcpu, false);
	}
}

int kvm_timer_vcpu_reset(struct kvm_vcpu *vcpu,
			 const struct kvm_irq_level *irq)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	/*
	 * The vcpu timer irq number cannot be determined in
	 * kvm_timer_vcpu_init() because it is called much before
	 * kvm_vcpu_set_target(). To handle this, we determine
	 * vcpu timer irq number when the vcpu is reset.
	 */
	timer->irq.irq = irq->irq;

	/*
	 * The bits in CNTV_CTL are architecturally reset to UNKNOWN for ARMv8
	 * and to 0 for ARMv7.  We provide an implementation that always
	 * resets the timer to be disabled and unmasked and is compliant with
	 * the ARMv7 architecture.
	 */
	timer->cntv_ctl = 0;
	kvm_timer_update_state(vcpu);

	return 0;
}

void kvm_timer_vcpu_init(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	INIT_WORK(&timer->expired, kvm_timer_inject_irq_work);
	hrtimer_init(&timer->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	timer->timer.function = kvm_timer_expire;
}

static void kvm_timer_init_interrupt(void *info)
{
	enable_percpu_irq(host_vtimer_irq, host_vtimer_irq_flags);
}

int kvm_arm_timer_set_reg(struct kvm_vcpu *vcpu, u64 regid, u64 value)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	switch (regid) {
	case KVM_REG_ARM_TIMER_CTL:
		timer->cntv_ctl = value;
		break;
	case KVM_REG_ARM_TIMER_CNT:
		vcpu->kvm->arch.timer.cntvoff = kvm_phys_timer_read() - value;
		break;
	case KVM_REG_ARM_TIMER_CVAL:
		timer->cntv_cval = value;
		break;
	default:
		return -1;
	}

	kvm_timer_update_state(vcpu);
	return 0;
}

u64 kvm_arm_timer_get_reg(struct kvm_vcpu *vcpu, u64 regid)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	switch (regid) {
	case KVM_REG_ARM_TIMER_CTL:
		return timer->cntv_ctl;
	case KVM_REG_ARM_TIMER_CNT:
		return kvm_phys_timer_read() - vcpu->kvm->arch.timer.cntvoff;
	case KVM_REG_ARM_TIMER_CVAL:
		return timer->cntv_cval;
	}
	return (u64)-1;
}

static int kvm_timer_starting_cpu(unsigned int cpu)
{
	kvm_timer_init_interrupt(NULL);
	return 0;
}

static int kvm_timer_dying_cpu(unsigned int cpu)
{
	disable_percpu_irq(host_vtimer_irq);
	return 0;
}

static bool has_split_eoi_deactivate_support(void)
{
	struct irq_desc *desc;
	struct irq_data *data;
	struct irq_chip *chip;

	/*
	 * Check if split EOI and deactivate is supported on this machine.
	 */
	desc = irq_to_desc(host_vtimer_irq);
	if (!desc) {
		kvm_err("kvm_arch_timer: no host_vtimer_irq descriptor\n");
		return false;
	}

	data = irq_desc_get_irq_data(desc);
	chip = irq_data_get_irq_chip(data);
	if (!chip || !chip->irq_set_vcpu_affinity) {
		kvm_err("kvm_arch_timer: no split EOI/deactivate; abort\n");
		return false;
	}

	return true;
}

int kvm_timer_hyp_init(void)
{
	struct arch_timer_kvm_info *info;
	int err;

	info = arch_timer_get_kvm_info();
	timecounter = &info->timecounter;

	if (info->virtual_irq <= 0) {
		kvm_err("kvm_arch_timer: invalid virtual timer IRQ: %d\n",
			info->virtual_irq);
		return -ENODEV;
	}
	host_vtimer_irq = info->virtual_irq;

	host_vtimer_irq_flags = irq_get_trigger_type(host_vtimer_irq);
	if (host_vtimer_irq_flags != IRQF_TRIGGER_HIGH &&
	    host_vtimer_irq_flags != IRQF_TRIGGER_LOW) {
		kvm_err("Invalid trigger for IRQ%d, assuming level low\n",
			host_vtimer_irq);
		host_vtimer_irq_flags = IRQF_TRIGGER_LOW;
	}

	err = request_percpu_irq(host_vtimer_irq, kvm_arch_timer_handler,
				 "kvm guest timer", kvm_get_running_vcpus());
	if (err) {
		kvm_err("kvm_arch_timer: can't request interrupt %d (%d)\n",
			host_vtimer_irq, err);
		goto out;
	}

	wqueue = create_singlethread_workqueue("kvm_arch_timer");
	if (!wqueue) {
		err = -ENOMEM;
		goto out_free;
	}

	if (!has_split_eoi_deactivate_support()) {
		err = -ENODEV;
		goto out_free;
	}

	/*
	 * We don't have a VCPU pointer here, but that is not used anyhow, so
	 * we just choose a non-NULL value for now.
	 */
	err = irq_set_vcpu_affinity(host_vtimer_irq, (void *)1);
	if (err) {
		kvm_err("kvm_arch_timer: error setting vcpu affinity\n");
		goto out_free;
	}

	kvm_info("virtual timer IRQ%d\n", host_vtimer_irq);

	cpuhp_setup_state(CPUHP_AP_KVM_ARM_TIMER_STARTING,
			  "AP_KVM_ARM_TIMER_STARTING", kvm_timer_starting_cpu,
			  kvm_timer_dying_cpu);
	goto out;
out_free:
	free_percpu_irq(host_vtimer_irq, kvm_get_running_vcpus());
out:
	return err;
}

void kvm_timer_vcpu_terminate(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;

	timer_disarm(timer);
	kvm_vgic_unmap_phys_irq(vcpu, timer->irq.irq);
}

int kvm_timer_enable(struct kvm_vcpu *vcpu)
{
	struct arch_timer_cpu *timer = &vcpu->arch.timer_cpu;
	struct irq_desc *desc;
	struct irq_data *data;
	int phys_irq;
	int ret;

	if (timer->enabled)
		return 0;

	/*
	 * Find the physical IRQ number corresponding to the host_vtimer_irq
	 */
	desc = irq_to_desc(host_vtimer_irq);
	if (!desc) {
		kvm_err("%s: no interrupt descriptor\n", __func__);
		return -EINVAL;
	}

	data = irq_desc_get_irq_data(desc);
	while (data->parent_data)
		data = data->parent_data;

	phys_irq = data->hwirq;

	/*
	 * Tell the VGIC that the virtual interrupt is tied to a
	 * physical interrupt. We do that once per VCPU.
	 */
	ret = kvm_vgic_map_phys_irq(vcpu, timer->irq.irq, phys_irq);
	if (ret)
		return ret;


	/*
	 * There is a potential race here between VCPUs starting for the first
	 * time, which may be enabling the timer multiple times.  That doesn't
	 * hurt though, because we're just setting a variable to the same
	 * variable that it already was.  The important thing is that all
	 * VCPUs have the enabled variable set, before entering the guest, if
	 * the arch timers are enabled.
	 */
	if (timecounter && wqueue)
		timer->enabled = 1;

	return 0;
}

void kvm_timer_init(struct kvm *kvm)
{
	kvm->arch.timer.cntvoff = kvm_phys_timer_read();
}

/*
 * On VHE system, we only need to configure trap on physical timer and counter
 * accesses in EL0 and EL1 once, not for every world switch.
 * The host kernel runs at EL2 with HCR_EL2.TGE == 1,
 * and this makes those bits have no effect for the host kernel execution.
 */
void kvm_timer_init_vhe(void)
{
	/* When HCR_EL2.E2H ==1, EL1PCEN and EL1PCTEN are shifted by 10 */
	u32 cnthctl_shift = 10;
	u64 val;

	/*
	 * Disallow physical timer access for the guest.
	 * Physical counter access is allowed.
	 */
	val = read_sysreg(cnthctl_el2);
	val &= ~(CNTHCTL_EL1PCEN << cnthctl_shift);
	val |= (CNTHCTL_EL1PCTEN << cnthctl_shift);
	write_sysreg(val, cnthctl_el2);
}
