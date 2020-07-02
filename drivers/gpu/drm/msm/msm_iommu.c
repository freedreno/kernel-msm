// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2013 Red Hat
 * Author: Rob Clark <robdclark@gmail.com>
 */

#include <linux/io-pgtable.h>
#include "msm_drv.h"
#include "msm_mmu.h"

struct msm_iommu {
	struct msm_mmu base;
	struct iommu_domain *domain;
	struct iommu_domain *aux_domain;
};

#define to_msm_iommu(x) container_of(x, struct msm_iommu, base)

struct msm_iommu_pagetable {
	struct msm_mmu base;
	struct msm_mmu *parent;
	struct io_pgtable_ops *pgtbl_ops;

	u64 iova_mask;
	phys_addr_t ttbr;
	u32 asid;
};

void arm_smmu_dump_mmu_config(struct iommu_domain *domain);

void dump_mmu_config(struct msm_mmu *mmu)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	arm_smmu_dump_mmu_config(iommu->domain);
}

static struct msm_iommu_pagetable *to_pagetable(struct msm_mmu *mmu)
{
	return container_of(mmu, struct msm_iommu_pagetable, base);
}

static int msm_iommu_pagetable_unmap(struct msm_mmu *mmu, u64 iova,
		size_t size)
{
	struct msm_iommu_pagetable *pagetable = to_pagetable(mmu);
	struct io_pgtable_ops *ops = pagetable->pgtbl_ops;
	size_t unmapped = 0;

	iova &= pagetable->iova_mask;
pr_err("A6XX: unmap: iova=%016llx, size=%d\n", iova, size);

	/* Unmap the block one page at a time */
	while (size) {
		unmapped += ops->unmap(ops, iova, 4096, NULL);
		iova += 4096;
		size -= 4096;
	}

	iommu_flush_tlb_all(to_msm_iommu(pagetable->parent)->domain);

	return (unmapped == size) ? 0 : -EINVAL;
}

static int msm_iommu_pagetable_map(struct msm_mmu *mmu, u64 iova,
		struct sg_table *sgt, size_t len, int prot)
{
	struct msm_iommu_pagetable *pagetable = to_pagetable(mmu);
	struct io_pgtable_ops *ops = pagetable->pgtbl_ops;
	struct scatterlist *sg;
	size_t mapped = 0;
	u64 addr = iova & pagetable->iova_mask;
	unsigned int i;

	for_each_sg(sgt->sgl, sg, sgt->nents, i) {
		size_t size = sg->length;
		phys_addr_t phys = sg_phys(sg);
pr_err("A6XX: map: iova=%016llx, size=%d\n", iova, size);

		/* Map the block one page at a time */
		while (size) {
			if (ops->map(ops, addr, phys, 4096, prot)) {
				msm_iommu_pagetable_unmap(mmu, iova, mapped);
				return -EINVAL;
			}

			phys += 4096;
			addr += 4096;
			size -= 4096;
			mapped += 4096;
		}
	}

	return 0;
}

static void msm_iommu_pagetable_destroy(struct msm_mmu *mmu)
{
	struct msm_iommu_pagetable *pagetable = to_pagetable(mmu);

	free_io_pgtable_ops(pagetable->pgtbl_ops);
	kfree(pagetable);
}

/*
 * Given a parent device, create and return an aux domain. This will enable the
 * TTBR0 region
 */
static struct iommu_domain *msm_iommu_get_aux_domain(struct msm_mmu *parent)
{
	struct msm_iommu *iommu = to_msm_iommu(parent);
	struct iommu_domain *domain;
	int ret;

	if (iommu->aux_domain)
		return iommu->aux_domain;

	if (!iommu_dev_has_feature(parent->dev, IOMMU_DEV_FEAT_AUX))
		return ERR_PTR(-ENODEV);

	domain = iommu_domain_alloc(&platform_bus_type);
	if (!domain)
		return ERR_PTR(-ENODEV);

	ret = iommu_aux_attach_device(domain, parent->dev);
	if (ret) {
		iommu_domain_free(domain);
		return ERR_PTR(ret);
	}

	iommu->aux_domain = domain;
	return domain;
}

int msm_iommu_pagetable_params(struct msm_mmu *mmu,
		phys_addr_t *ttbr, int *asid)
{
	struct msm_iommu_pagetable *pagetable;

	if (mmu->type != MSM_MMU_IOMMU_PAGETABLE)
		return -EINVAL;

	pagetable = to_pagetable(mmu);

	if (ttbr)
		*ttbr = pagetable->ttbr;

	if (asid)
		*asid = pagetable->asid;

	return 0;
}

static const struct msm_mmu_funcs pagetable_funcs = {
		.map = msm_iommu_pagetable_map,
		.unmap = msm_iommu_pagetable_unmap,
		.destroy = msm_iommu_pagetable_destroy,
};

struct msm_mmu *msm_iommu_pagetable_create(struct msm_mmu *parent)
{
	static int next_asid = 16;
	struct msm_iommu_pagetable *pagetable;
	struct iommu_domain *aux_domain;
	struct io_pgtable_cfg cfg;
	int ret;

	/* Make sure that the parent has a aux domain attached */
	aux_domain = msm_iommu_get_aux_domain(parent);
	if (IS_ERR(aux_domain))
		return ERR_CAST(aux_domain);

	/* Get the pagetable configuration from the aux domain */
	ret = iommu_domain_get_attr(aux_domain, DOMAIN_ATTR_PGTABLE_CFG, &cfg);
	if (ret)
		return ERR_PTR(ret);

	pagetable = kzalloc(sizeof(*pagetable), GFP_KERNEL);
	if (!pagetable)
		return ERR_PTR(-ENOMEM);

	msm_mmu_init(&pagetable->base, parent->dev, &pagetable_funcs,
		MSM_MMU_IOMMU_PAGETABLE);

	cfg.tlb = NULL;

	pagetable->pgtbl_ops = alloc_io_pgtable_ops(ARM_64_LPAE_S1,
		&cfg, aux_domain);

	if (!pagetable->pgtbl_ops) {
		kfree(pagetable);
		return ERR_PTR(-ENOMEM);
	}
pr_err("A6XX: quirks=%lx, pgsize_bitmap=%lx, ias=%u, oas=%u, coherent_walk=%d\n", cfg.quirks, cfg.pgsize_bitmap, cfg.ias, cfg.oas, cfg.coherent_walk);

	/* Needed later for TLB flush */
	pagetable->parent = parent;
	pagetable->iova_mask = (1ULL << cfg.ias) - 1;
	pagetable->ttbr = cfg.arm_lpae_s1_cfg.ttbr;

	pagetable->asid = next_asid;
	next_asid = (next_asid + 1)  % 255;
	if (next_asid < 16)
		next_asid = 16;

	return &pagetable->base;
}

static int msm_fault_handler(struct iommu_domain *domain, struct device *dev,
		unsigned long iova, int flags, void *arg)
{
	struct msm_iommu *iommu = arg;
	if (iommu->base.handler)
		return iommu->base.handler(iommu->base.arg, iova, flags);
	pr_warn_ratelimited("*** fault: iova=%16lx, flags=%d\n", iova, flags);
	return 0;
}

static void msm_iommu_detach(struct msm_mmu *mmu)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);

	iommu_detach_device(iommu->domain, mmu->dev);
}

static int msm_iommu_map(struct msm_mmu *mmu, uint64_t iova,
		struct sg_table *sgt, size_t len, int prot)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	size_t ret;

	/* The arm-smmu driver expects the addresses to be sign extended */
	if (iova & BIT_ULL(48))
		iova |= GENMASK_ULL(63, 49);


	ret = iommu_map_sg(iommu->domain, iova, sgt->sgl, sgt->nents, prot);
	WARN_ON(!ret);

	return (ret == len) ? 0 : -EINVAL;
}

static int msm_iommu_unmap(struct msm_mmu *mmu, uint64_t iova, size_t len)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);

	if (iova & BIT_ULL(48))
		iova |= GENMASK_ULL(63, 49);

	iommu_unmap(iommu->domain, iova, len);

	return 0;
}

static void msm_iommu_destroy(struct msm_mmu *mmu)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	iommu_domain_free(iommu->domain);
	kfree(iommu);
}

static const struct msm_mmu_funcs funcs = {
		.detach = msm_iommu_detach,
		.map = msm_iommu_map,
		.unmap = msm_iommu_unmap,
		.destroy = msm_iommu_destroy,
};

struct msm_mmu *msm_iommu_new(struct device *dev, struct iommu_domain *domain)
{
	struct msm_iommu *iommu;
	int ret;

	if (!domain)
		return ERR_PTR(-ENODEV);

	iommu = kzalloc(sizeof(*iommu), GFP_KERNEL);
	if (!iommu)
		return ERR_PTR(-ENOMEM);

	iommu->domain = domain;
	msm_mmu_init(&iommu->base, dev, &funcs, MSM_MMU_IOMMU);
	iommu_set_fault_handler(domain, msm_fault_handler, iommu);

	ret = iommu_attach_device(iommu->domain, dev);
	if (ret) {
		kfree(iommu);
		return ERR_PTR(ret);
	}

	return &iommu->base;
}
