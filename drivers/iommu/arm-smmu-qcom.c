// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2019, The Linux Foundation. All rights reserved.
 */

#include <linux/of_device.h>
#include <linux/qcom_scm.h>

#include "arm-smmu.h"

struct qcom_smmu {
	struct arm_smmu_device smmu;
};

static bool qcom_adreno_smmu_is_gpu_device(struct arm_smmu_domain *smmu_domain)
{
	return of_device_is_compatible(smmu_domain->dev->of_node, "qcom,adreno");
}

static int qcom_adreno_smmu_init_context(struct arm_smmu_domain *smmu_domain,
		struct io_pgtable_cfg *pgtbl_cfg)
{
	/* TTBR1 is only for the GPU stream ID and not the GMU */
	if (!qcom_adreno_smmu_is_gpu_device(smmu_domain))
		return 0;

	WARN_ON(smmu_domain->stage != ARM_SMMU_DOMAIN_S1);
	WARN_ON(smmu_domain->cfg.fmt != ARM_SMMU_CTX_FMT_AARCH64);

	/*
	 * All targets that use the qcom,adreno-smmu compatible string *should*
	 * be AARCH64 stage 1 but double check because the arm-smmu code assumes
	 * that is the case when the TTBR1 quirk is enabled
	 */
	if ((smmu_domain->stage == ARM_SMMU_DOMAIN_S1) &&
	    (smmu_domain->cfg.fmt == ARM_SMMU_CTX_FMT_AARCH64))
		pgtbl_cfg->quirks |= IO_PGTABLE_QUIRK_ARM_TTBR1;

	return 0;
}

static const struct of_device_id qcom_smmu_client_of_match[] __maybe_unused = {
	{ .compatible = "qcom,adreno" },
	{ .compatible = "qcom,mdp4" },
	{ .compatible = "qcom,mdss" },
	{ .compatible = "qcom,sc7180-mdss" },
	{ .compatible = "qcom,sc7180-mss-pil" },
	{ .compatible = "qcom,sdm845-mdss" },
	{ .compatible = "qcom,sdm845-mss-pil" },
	{ }
};

static int qcom_smmu_def_domain_type(struct device *dev)
{
	const struct of_device_id *match =
		of_match_device(qcom_smmu_client_of_match, dev);

	return match ? IOMMU_DOMAIN_IDENTITY : 0;
}

static int qcom_sdm845_smmu500_reset(struct arm_smmu_device *smmu)
{
	int ret;

	/*
	 * To address performance degradation in non-real time clients,
	 * such as USB and UFS, turn off wait-for-safe on sdm845 based boards,
	 * such as MTP and db845, whose firmwares implement secure monitor
	 * call handlers to turn on/off the wait-for-safe logic.
	 */
	ret = qcom_scm_qsmmu500_wait_safe_toggle(0);
	if (ret)
		dev_warn(smmu->dev, "Failed to turn off SAFE logic\n");

	return ret;
}

static int qcom_smmu500_reset(struct arm_smmu_device *smmu)
{
	const struct device_node *np = smmu->dev->of_node;

	arm_mmu500_reset(smmu);

	if (of_device_is_compatible(np, "qcom,sdm845-smmu-500"))
		return qcom_sdm845_smmu500_reset(smmu);

	return 0;
}

static const struct arm_smmu_impl qcom_smmu_impl = {
	.def_domain_type = qcom_smmu_def_domain_type,
	.reset = qcom_smmu500_reset,
};

static const struct arm_smmu_impl qcom_adreno_smmu_impl = {
	.init_context = qcom_adreno_smmu_init_context,
	.def_domain_type = qcom_smmu_def_domain_type,
	.reset = qcom_smmu500_reset,
};


static struct arm_smmu_device *qcom_smmu_create(struct arm_smmu_device *smmu,
		const struct arm_smmu_impl *impl)
{
	struct qcom_smmu *qsmmu;

	qsmmu = devm_kzalloc(smmu->dev, sizeof(*qsmmu), GFP_KERNEL);
	if (!qsmmu)
		return ERR_PTR(-ENOMEM);

	qsmmu->smmu = *smmu;

	qsmmu->smmu.impl = impl;
	devm_kfree(smmu->dev, smmu);

	return &qsmmu->smmu;
}

struct arm_smmu_device *qcom_smmu_impl_init(struct arm_smmu_device *smmu)
{
	return qcom_smmu_create(smmu, &qcom_smmu_impl);
}

struct arm_smmu_device *qcom_adreno_smmu_impl_init(struct arm_smmu_device *smmu)
{
	return qcom_smmu_create(smmu, &qcom_adreno_smmu_impl);
}
