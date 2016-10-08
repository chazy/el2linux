/*
 * Copyright (C) 2016,2017 - Linaro
 * Author: Christoffer Dall <christoffer.dall@linaro.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __ARM_KVM_SYSREGS_H
#define __ARM_KVM_SYSREGS_H

/*
 * CP14 and CP15 live in the same array, as they are backed by the
 * same system registers.
 */
#define __vcpu_cp14(v,r)	((v)->arch.ctxt.copro[(r)])
#define __vcpu_cp15(v,r)	((v)->arch.ctxt.copro[(r)])

static inline u32 vcpu_get_cpreg(struct kvm_vcpu *vcpu, int cpreg)
{
	int sysreg = cpreg / 2;
	if (cpreg % 2 == 1)
		return upper_32_bits(vcpu_get_sys_reg(vcpu, sysreg));
	else
		return vcpu_get_sys_reg(vcpu, sysreg);
}

static inline void vcpu_set_cpreg(struct kvm_vcpu *vcpu, int cpreg, u32 val)
{
	int sysreg = cpreg / 2;
	u64 reg = vcpu_get_sys_reg(vcpu, sysreg);

	if (cpreg % 2 == 1)
		reg = (reg & GENMASK(31, 0)) | ((u64)val << 32);
	else
		reg = (reg & GENMASK(36, 32)) | (u64)val;
	vcpu_set_sys_reg(vcpu, sysreg, reg);
}

static inline u64 vcpu_get_cpreg_64(struct kvm_vcpu *vcpu, int cpreg)
{
	int sysreg = cpreg / 2;
	return vcpu_get_sys_reg(vcpu, sysreg);
}

static inline void vcpu_set_cpreg_64(struct kvm_vcpu *vcpu, int cpreg, u64 val)
{
	int sysreg = cpreg / 2;
	vcpu_set_sys_reg(vcpu, sysreg, val);
}

#endif /* __ARM_KVM_HOST_H__ */
