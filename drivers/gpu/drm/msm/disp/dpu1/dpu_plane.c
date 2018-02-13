/*
 * Copyright (C) 2014-2018 The Linux Foundation. All rights reserved.
 * Copyright (C) 2013 Red Hat
 * Author: Rob Clark <robdclark@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt)	"[drm:%s:%d] " fmt, __func__, __LINE__

#include <linux/debugfs.h>
#include <linux/dma-buf.h>
#include <uapi/drm/dpu_drm.h>
#include <uapi/drm/msm_drm_pp.h>

#include "msm_prop.h"
#include "msm_drv.h"

#include "dpu_kms.h"
#include "dpu_fence.h"
#include "dpu_formats.h"
#include "dpu_hw_sspp.h"
#include "dpu_hw_catalog_format.h"
#include "dpu_trace.h"
#include "dpu_crtc.h"
#include "dpu_vbif.h"
#include "dpu_plane.h"
#include "dpu_color_processing.h"
#include "dpu_hw_rot.h"

static bool suspend_blank = true;
module_param(suspend_blank, bool, 0400);
MODULE_PARM_DESC(suspend_blank,
		"If set, active planes will force their outputs to black,\n"
		"by temporarily enabling the color fill, when recovering\n"
		"from a system resume instead of attempting to display the\n"
		"last provided frame buffer.");

#define DPU_DEBUG_PLANE(pl, fmt, ...) DPU_DEBUG("plane%d " fmt,\
		(pl) ? (pl)->base.base.id : -1, ##__VA_ARGS__)

#define DPU_ERROR_PLANE(pl, fmt, ...) DPU_ERROR("plane%d " fmt,\
		(pl) ? (pl)->base.base.id : -1, ##__VA_ARGS__)

#define DECIMATED_DIMENSION(dim, deci) (((dim) + ((1 << (deci)) - 1)) >> (deci))
#define PHASE_STEP_SHIFT	21
#define PHASE_STEP_UNIT_SCALE   ((int) (1 << PHASE_STEP_SHIFT))
#define PHASE_RESIDUAL		15

#define SHARP_STRENGTH_DEFAULT	32
#define SHARP_EDGE_THR_DEFAULT	112
#define SHARP_SMOOTH_THR_DEFAULT	8
#define SHARP_NOISE_THR_DEFAULT	2

#define DPU_NAME_SIZE  12

#define DPU_PLANE_COLOR_FILL_FLAG	BIT(31)

/* multirect rect index */
enum {
	R0,
	R1,
	R_MAX
};

#define DPU_QSEED3_DEFAULT_PRELOAD_H 0x4
#define DPU_QSEED3_DEFAULT_PRELOAD_V 0x3

#define DEFAULT_REFRESH_RATE	60

/**
 * enum dpu_plane_qos - Different qos configurations for each pipe
 *
 * @DPU_PLANE_QOS_VBLANK_CTRL: Setup VBLANK qos for the pipe.
 * @DPU_PLANE_QOS_VBLANK_AMORTIZE: Enables Amortization within pipe.
 *	this configuration is mutually exclusive from VBLANK_CTRL.
 * @DPU_PLANE_QOS_PANIC_CTRL: Setup panic for the pipe.
 */
enum dpu_plane_qos {
	DPU_PLANE_QOS_VBLANK_CTRL = BIT(0),
	DPU_PLANE_QOS_VBLANK_AMORTIZE = BIT(1),
	DPU_PLANE_QOS_PANIC_CTRL = BIT(2),
};

/*
 * struct dpu_plane - local dpu plane structure
 * @aspace: address space pointer
 * @csc_cfg: Decoded user configuration for csc
 * @csc_usr_ptr: Points to csc_cfg if valid user config available
 * @csc_ptr: Points to dpu_csc_cfg structure to use for current
 * @mplane_list: List of multirect planes of the same pipe
 * @catalog: Points to dpu catalog structure
 * @sbuf_mode: force stream buffer mode if set
 * @sbuf_writeback: force stream buffer writeback if set
 * @revalidate: force revalidation of all the plane properties
 * @blob_rot_caps: Pointer to rotator capability blob
 */
struct dpu_plane {
	struct drm_plane base;

	struct mutex lock;

	enum dpu_sspp pipe;
	uint32_t features;      /* capabilities from catalog */
	uint32_t nformats;
	uint32_t formats[64];

	struct dpu_hw_pipe *pipe_hw;
	struct dpu_hw_pipe_cfg pipe_cfg;
	struct dpu_hw_sharp_cfg sharp_cfg;
	struct dpu_hw_pipe_qos_cfg pipe_qos_cfg;
	uint32_t color_fill;
	bool is_error;
	bool is_rt_pipe;
	bool is_virtual;
	struct list_head mplane_list;
	struct dpu_mdss_cfg *catalog;
	u32 sbuf_mode;
	u32 sbuf_writeback;
	bool revalidate;

	struct dpu_csc_cfg csc_cfg;
	struct dpu_csc_cfg *csc_usr_ptr;
	struct dpu_csc_cfg *csc_ptr;

	const struct dpu_sspp_sub_blks *pipe_sblk;

	char pipe_name[DPU_NAME_SIZE];

	struct msm_property_info property_info;
	struct msm_property_data property_data[PLANE_PROP_COUNT];
	struct drm_property_blob *blob_info;
	struct drm_property_blob *blob_rot_caps;

	/* debugfs related stuff */
	struct dentry *debugfs_root;
	struct dpu_debugfs_regset32 debugfs_src;
	struct dpu_debugfs_regset32 debugfs_scaler;
	struct dpu_debugfs_regset32 debugfs_csc;
	bool debugfs_default_scale;
};

#define to_dpu_plane(x) container_of(x, struct dpu_plane, base)

static struct dpu_kms *_dpu_plane_get_kms(struct drm_plane *plane)
{
	struct msm_drm_private *priv;

	if (!plane || !plane->dev)
		return NULL;
	priv = plane->dev->dev_private;
	if (!priv)
		return NULL;
	return to_dpu_kms(priv->kms);
}

/**
 * _dpu_plane_get_crtc_state - obtain crtc state attached to given plane state
 * @pstate: Pointer to drm plane state
 * return: Pointer to crtc state if success; pointer error, otherwise
 */
static struct drm_crtc_state *_dpu_plane_get_crtc_state(
		struct drm_plane_state *pstate)
{
	struct drm_crtc_state *cstate;

	if (!pstate || !pstate->crtc)
		return NULL;

	if (pstate->state)
		cstate = drm_atomic_get_crtc_state(pstate->state, pstate->crtc);
	else
		cstate = pstate->crtc->state;

	return cstate;
}

static bool dpu_plane_enabled(struct drm_plane_state *state)
{
	return state && state->fb && state->crtc;
}

static bool dpu_plane_sspp_enabled(struct drm_plane_state *state)
{
	return state && to_dpu_plane_state(state)->rot.out_fb && state->crtc;
}

/**
 * dpu_plane_crtc_enabled - determine if crtc of given plane state is enabled
 * @state: Pointer to drm plane state
 * return: true if plane and the associated crtc are both enabled
 */
static bool dpu_plane_crtc_enabled(struct drm_plane_state *state)
{
	return dpu_plane_enabled(state) && state->crtc->state &&
			state->crtc->state->active &&
			state->crtc->state->enable;
}

/**
 * _dpu_plane_calc_fill_level - calculate fill level of the given source format
 * @plane:		Pointer to drm plane
 * @fmt:		Pointer to source buffer format
 * @src_wdith:		width of source buffer
 * Return: fill level corresponding to the source buffer/format or 0 if error
 */
static inline int _dpu_plane_calc_fill_level(struct drm_plane *plane,
		const struct dpu_format *fmt, u32 src_width)
{
	struct dpu_plane *pdpu, *tmp;
	struct dpu_plane_state *pstate;
	struct dpu_plane_rot_state *rstate;
	u32 fixed_buff_size;
	u32 total_fl;
	u32 hflip_bytes;

	if (!plane || !fmt || !plane->state || !src_width || !fmt->bpp) {
		DPU_ERROR("invalid arguments\n");
		return 0;
	}

	pdpu = to_dpu_plane(plane);
	pstate = to_dpu_plane_state(plane->state);
	rstate = &pstate->rot;
	fixed_buff_size = pdpu->pipe_sblk->pixel_ram_size;

	list_for_each_entry(tmp, &pdpu->mplane_list, mplane_list) {
		if (!dpu_plane_enabled(tmp->base.state))
			continue;
		DPU_DEBUG("plane%d/%d src_width:%d/%d\n",
				pdpu->base.base.id, tmp->base.base.id,
				src_width, tmp->pipe_cfg.src_rect.w);
		src_width = max_t(u32, src_width, tmp->pipe_cfg.src_rect.w);
	}

	if ((rstate->out_rotation & DRM_MODE_REFLECT_X) &&
			DPU_FORMAT_IS_LINEAR(fmt))
		hflip_bytes = (src_width + 32) * fmt->bpp;
	else
		hflip_bytes = 0;

	if (fmt->fetch_planes == DPU_PLANE_PSEUDO_PLANAR) {
		if (fmt->chroma_sample == DPU_CHROMA_420) {
			/* NV12 */
			total_fl = (fixed_buff_size / 2 - hflip_bytes) /
				((src_width + 32) * fmt->bpp);
		} else {
			/* non NV12 */
			total_fl = (fixed_buff_size / 2 - hflip_bytes) * 2 /
				((src_width + 32) * fmt->bpp);
		}
	} else {
		if (pstate->multirect_mode == DPU_SSPP_MULTIRECT_PARALLEL) {
			total_fl = (fixed_buff_size / 2 - hflip_bytes) * 2 /
				((src_width + 32) * fmt->bpp);
		} else {
			total_fl = (fixed_buff_size - hflip_bytes) * 2 /
				((src_width + 32) * fmt->bpp);
		}
	}

	DPU_DEBUG("plane%u: pnum:%d fmt: %4.4s w:%u hf:%d fl:%u\n",
			plane->base.id, pdpu->pipe - SSPP_VIG0,
			(char *)&fmt->base.pixel_format,
			src_width, hflip_bytes, total_fl);

	return total_fl;
}

/**
 * _dpu_plane_get_qos_lut - get LUT mapping based on fill level
 * @tbl:		Pointer to LUT table
 * @total_fl:		fill level
 * Return: LUT setting corresponding to the fill level
 */
static u64 _dpu_plane_get_qos_lut(const struct dpu_qos_lut_tbl *tbl,
		u32 total_fl)
{
	int i;

	if (!tbl || !tbl->nentry || !tbl->entries)
		return 0;

	for (i = 0; i < tbl->nentry; i++)
		if (total_fl <= tbl->entries[i].fl)
			return tbl->entries[i].lut;

	/* if last fl is zero, use as default */
	if (!tbl->entries[i-1].fl)
		return tbl->entries[i-1].lut;

	return 0;
}

/**
 * _dpu_plane_set_qos_lut - set QoS LUT of the given plane
 * @plane:		Pointer to drm plane
 * @fb:			Pointer to framebuffer associated with the given plane
 */
static void _dpu_plane_set_qos_lut(struct drm_plane *plane,
		struct drm_framebuffer *fb)
{
	struct dpu_plane *pdpu;
	const struct dpu_format *fmt = NULL;
	u64 qos_lut;
	u32 total_fl = 0, lut_usage;

	if (!plane || !fb) {
		DPU_ERROR("invalid arguments plane %d fb %d\n",
				plane != 0, fb != 0);
		return;
	}

	pdpu = to_dpu_plane(plane);

	if (!pdpu->pipe_hw || !pdpu->pipe_sblk || !pdpu->catalog) {
		DPU_ERROR("invalid arguments\n");
		return;
	} else if (!pdpu->pipe_hw->ops.setup_creq_lut) {
		return;
	}

	if (!pdpu->is_rt_pipe) {
		lut_usage = DPU_QOS_LUT_USAGE_NRT;
	} else {
		fmt = dpu_get_dpu_format_ext(
				fb->format->format,
				fb->modifier);
		total_fl = _dpu_plane_calc_fill_level(plane, fmt,
				pdpu->pipe_cfg.src_rect.w);

		if (fmt && DPU_FORMAT_IS_LINEAR(fmt))
			lut_usage = DPU_QOS_LUT_USAGE_LINEAR;
		else
			lut_usage = DPU_QOS_LUT_USAGE_MACROTILE;
	}

	qos_lut = _dpu_plane_get_qos_lut(
			&pdpu->catalog->perf.qos_lut_tbl[lut_usage], total_fl);

	pdpu->pipe_qos_cfg.creq_lut = qos_lut;

	trace_dpu_perf_set_qos_luts(pdpu->pipe - SSPP_VIG0,
			(fmt) ? fmt->base.pixel_format : 0,
			pdpu->is_rt_pipe, total_fl, qos_lut, lut_usage);

	DPU_DEBUG("plane%u: pnum:%d fmt: %4.4s rt:%d fl:%u lut:0x%llx\n",
			plane->base.id,
			pdpu->pipe - SSPP_VIG0,
			fmt ? (char *)&fmt->base.pixel_format : NULL,
			pdpu->is_rt_pipe, total_fl, qos_lut);

	pdpu->pipe_hw->ops.setup_creq_lut(pdpu->pipe_hw, &pdpu->pipe_qos_cfg);
}

/**
 * _dpu_plane_set_panic_lut - set danger/safe LUT of the given plane
 * @plane:		Pointer to drm plane
 * @fb:			Pointer to framebuffer associated with the given plane
 */
static void _dpu_plane_set_danger_lut(struct drm_plane *plane,
		struct drm_framebuffer *fb)
{
	struct dpu_plane *pdpu;
	const struct dpu_format *fmt = NULL;
	u32 danger_lut, safe_lut;

	if (!plane || !fb) {
		DPU_ERROR("invalid arguments\n");
		return;
	}

	pdpu = to_dpu_plane(plane);

	if (!pdpu->pipe_hw || !pdpu->pipe_sblk || !pdpu->catalog) {
		DPU_ERROR("invalid arguments\n");
		return;
	} else if (!pdpu->pipe_hw->ops.setup_danger_safe_lut) {
		return;
	}

	if (!pdpu->is_rt_pipe) {
		danger_lut = pdpu->catalog->perf.danger_lut_tbl
				[DPU_QOS_LUT_USAGE_NRT];
		safe_lut = pdpu->catalog->perf.safe_lut_tbl
				[DPU_QOS_LUT_USAGE_NRT];
	} else {
		fmt = dpu_get_dpu_format_ext(
				fb->format->format,
				fb->modifier);

		if (fmt && DPU_FORMAT_IS_LINEAR(fmt)) {
			danger_lut = pdpu->catalog->perf.danger_lut_tbl
					[DPU_QOS_LUT_USAGE_LINEAR];
			safe_lut = pdpu->catalog->perf.safe_lut_tbl
					[DPU_QOS_LUT_USAGE_LINEAR];
		} else {
			danger_lut = pdpu->catalog->perf.danger_lut_tbl
					[DPU_QOS_LUT_USAGE_MACROTILE];
			safe_lut = pdpu->catalog->perf.safe_lut_tbl
					[DPU_QOS_LUT_USAGE_MACROTILE];
		}
	}

	pdpu->pipe_qos_cfg.danger_lut = danger_lut;
	pdpu->pipe_qos_cfg.safe_lut = safe_lut;

	trace_dpu_perf_set_danger_luts(pdpu->pipe - SSPP_VIG0,
			(fmt) ? fmt->base.pixel_format : 0,
			(fmt) ? fmt->fetch_mode : 0,
			pdpu->pipe_qos_cfg.danger_lut,
			pdpu->pipe_qos_cfg.safe_lut);

	DPU_DEBUG("plane%u: pnum:%d fmt: %4.4s mode:%d luts[0x%x, 0x%x]\n",
		plane->base.id,
		pdpu->pipe - SSPP_VIG0,
		fmt ? (char *)&fmt->base.pixel_format : NULL,
		fmt ? fmt->fetch_mode : -1,
		pdpu->pipe_qos_cfg.danger_lut,
		pdpu->pipe_qos_cfg.safe_lut);

	pdpu->pipe_hw->ops.setup_danger_safe_lut(pdpu->pipe_hw,
			&pdpu->pipe_qos_cfg);
}

/**
 * _dpu_plane_set_qos_ctrl - set QoS control of the given plane
 * @plane:		Pointer to drm plane
 * @enable:		true to enable QoS control
 * @flags:		QoS control mode (enum dpu_plane_qos)
 */
static void _dpu_plane_set_qos_ctrl(struct drm_plane *plane,
	bool enable, u32 flags)
{
	struct dpu_plane *pdpu;

	if (!plane) {
		DPU_ERROR("invalid arguments\n");
		return;
	}

	pdpu = to_dpu_plane(plane);

	if (!pdpu->pipe_hw || !pdpu->pipe_sblk) {
		DPU_ERROR("invalid arguments\n");
		return;
	} else if (!pdpu->pipe_hw->ops.setup_qos_ctrl) {
		return;
	}

	if (flags & DPU_PLANE_QOS_VBLANK_CTRL) {
		pdpu->pipe_qos_cfg.creq_vblank = pdpu->pipe_sblk->creq_vblank;
		pdpu->pipe_qos_cfg.danger_vblank =
				pdpu->pipe_sblk->danger_vblank;
		pdpu->pipe_qos_cfg.vblank_en = enable;
	}

	if (flags & DPU_PLANE_QOS_VBLANK_AMORTIZE) {
		/* this feature overrules previous VBLANK_CTRL */
		pdpu->pipe_qos_cfg.vblank_en = false;
		pdpu->pipe_qos_cfg.creq_vblank = 0; /* clear vblank bits */
	}

	if (flags & DPU_PLANE_QOS_PANIC_CTRL)
		pdpu->pipe_qos_cfg.danger_safe_en = enable;

	if (!pdpu->is_rt_pipe) {
		pdpu->pipe_qos_cfg.vblank_en = false;
		pdpu->pipe_qos_cfg.danger_safe_en = false;
	}

	DPU_DEBUG("plane%u: pnum:%d ds:%d vb:%d pri[0x%x, 0x%x] is_rt:%d\n",
		plane->base.id,
		pdpu->pipe - SSPP_VIG0,
		pdpu->pipe_qos_cfg.danger_safe_en,
		pdpu->pipe_qos_cfg.vblank_en,
		pdpu->pipe_qos_cfg.creq_vblank,
		pdpu->pipe_qos_cfg.danger_vblank,
		pdpu->is_rt_pipe);

	pdpu->pipe_hw->ops.setup_qos_ctrl(pdpu->pipe_hw,
			&pdpu->pipe_qos_cfg);
}

void dpu_plane_set_revalidate(struct drm_plane *plane, bool enable)
{
	struct dpu_plane *pdpu;

	if (!plane)
		return;

	pdpu = to_dpu_plane(plane);
	pdpu->revalidate = enable;
}

int dpu_plane_danger_signal_ctrl(struct drm_plane *plane, bool enable)
{
	struct dpu_plane *pdpu;
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;

	if (!plane || !plane->dev) {
		DPU_ERROR("invalid arguments\n");
		return -EINVAL;
	}

	priv = plane->dev->dev_private;
	if (!priv || !priv->kms) {
		DPU_ERROR("invalid KMS reference\n");
		return -EINVAL;
	}

	dpu_kms = to_dpu_kms(priv->kms);
	pdpu = to_dpu_plane(plane);

	if (!pdpu->is_rt_pipe)
		goto end;

	dpu_power_resource_enable(&priv->phandle, dpu_kms->core_client, true);

	_dpu_plane_set_qos_ctrl(plane, enable, DPU_PLANE_QOS_PANIC_CTRL);

	dpu_power_resource_enable(&priv->phandle, dpu_kms->core_client, false);

end:
	return 0;
}

/**
 * _dpu_plane_set_ot_limit - set OT limit for the given plane
 * @plane:		Pointer to drm plane
 * @crtc:		Pointer to drm crtc
 */
static void _dpu_plane_set_ot_limit(struct drm_plane *plane,
		struct drm_crtc *crtc)
{
	struct dpu_plane *pdpu;
	struct dpu_vbif_set_ot_params ot_params;
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;

	if (!plane || !plane->dev || !crtc) {
		DPU_ERROR("invalid arguments plane %d crtc %d\n",
				plane != 0, crtc != 0);
		return;
	}

	priv = plane->dev->dev_private;
	if (!priv || !priv->kms) {
		DPU_ERROR("invalid KMS reference\n");
		return;
	}

	dpu_kms = to_dpu_kms(priv->kms);
	pdpu = to_dpu_plane(plane);
	if (!pdpu->pipe_hw) {
		DPU_ERROR("invalid pipe reference\n");
		return;
	}

	memset(&ot_params, 0, sizeof(ot_params));
	ot_params.xin_id = pdpu->pipe_hw->cap->xin_id;
	ot_params.num = pdpu->pipe_hw->idx - SSPP_NONE;
	ot_params.width = pdpu->pipe_cfg.src_rect.w;
	ot_params.height = pdpu->pipe_cfg.src_rect.h;
	ot_params.is_wfd = !pdpu->is_rt_pipe;
	ot_params.frame_rate = crtc->mode.vrefresh;
	ot_params.vbif_idx = VBIF_RT;
	ot_params.clk_ctrl = pdpu->pipe_hw->cap->clk_ctrl;
	ot_params.rd = true;

	dpu_vbif_set_ot_limit(dpu_kms, &ot_params);
}

/**
 * _dpu_plane_set_vbif_qos - set vbif QoS for the given plane
 * @plane:		Pointer to drm plane
 */
static void _dpu_plane_set_qos_remap(struct drm_plane *plane)
{
	struct dpu_plane *pdpu;
	struct dpu_vbif_set_qos_params qos_params;
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;

	if (!plane || !plane->dev) {
		DPU_ERROR("invalid arguments\n");
		return;
	}

	priv = plane->dev->dev_private;
	if (!priv || !priv->kms) {
		DPU_ERROR("invalid KMS reference\n");
		return;
	}

	dpu_kms = to_dpu_kms(priv->kms);
	pdpu = to_dpu_plane(plane);
	if (!pdpu->pipe_hw) {
		DPU_ERROR("invalid pipe reference\n");
		return;
	}

	memset(&qos_params, 0, sizeof(qos_params));
	qos_params.vbif_idx = VBIF_RT;
	qos_params.clk_ctrl = pdpu->pipe_hw->cap->clk_ctrl;
	qos_params.xin_id = pdpu->pipe_hw->cap->xin_id;
	qos_params.num = pdpu->pipe_hw->idx - SSPP_VIG0;
	qos_params.is_rt = pdpu->is_rt_pipe;

	DPU_DEBUG("plane%d pipe:%d vbif:%d xin:%d rt:%d, clk_ctrl:%d\n",
			plane->base.id, qos_params.num,
			qos_params.vbif_idx,
			qos_params.xin_id, qos_params.is_rt,
			qos_params.clk_ctrl);

	dpu_vbif_set_qos_remap(dpu_kms, &qos_params);
}

/**
 * _dpu_plane_set_ts_prefill - set prefill with traffic shaper
 * @plane:	Pointer to drm plane
 * @pstate:	Pointer to dpu plane state
 */
static void _dpu_plane_set_ts_prefill(struct drm_plane *plane,
		struct dpu_plane_state *pstate)
{
	struct dpu_plane *pdpu;
	struct dpu_hw_pipe_ts_cfg cfg;
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;

	if (!plane || !plane->dev) {
		DPU_ERROR("invalid arguments");
		return;
	}

	priv = plane->dev->dev_private;
	if (!priv || !priv->kms) {
		DPU_ERROR("invalid KMS reference\n");
		return;
	}

	dpu_kms = to_dpu_kms(priv->kms);
	pdpu = to_dpu_plane(plane);
	if (!pdpu->pipe_hw) {
		DPU_ERROR("invalid pipe reference\n");
		return;
	}

	if (!pdpu->pipe_hw || !pdpu->pipe_hw->ops.setup_ts_prefill)
		return;

	_dpu_plane_set_qos_ctrl(plane, false, DPU_PLANE_QOS_VBLANK_AMORTIZE);

	memset(&cfg, 0, sizeof(cfg));
	cfg.size = dpu_plane_get_property(pstate,
			PLANE_PROP_PREFILL_SIZE);
	cfg.time = dpu_plane_get_property(pstate,
			PLANE_PROP_PREFILL_TIME);

	DPU_DEBUG("plane%d size:%llu time:%llu\n",
			plane->base.id, cfg.size, cfg.time);
	DPU_EVT32_VERBOSE(DRMID(plane), cfg.size, cfg.time);
	pdpu->pipe_hw->ops.setup_ts_prefill(pdpu->pipe_hw, &cfg,
			pstate->multirect_index);
}

/* helper to update a state's input fence pointer from the property */
static void _dpu_plane_set_input_fence(struct dpu_plane *pdpu,
		struct dpu_plane_state *pstate, uint64_t fd)
{
	if (!pdpu || !pstate) {
		DPU_ERROR("invalid arg(s), plane %d state %d\n",
				pdpu != 0, pstate != 0);
		return;
	}

	/* clear previous reference */
	if (pstate->input_fence)
		dpu_sync_put(pstate->input_fence);

	/* get fence pointer for later */
	pstate->input_fence = dpu_sync_get(fd);

	DPU_DEBUG_PLANE(pdpu, "0x%llX\n", fd);
}

/**
 * _dpu_plane_inline_rot_set_ot_limit - set OT limit for the given inline
 * rotation xin client
 * @plane: pointer to drm plane
 * @crtc: pointer to drm crtc
 * @cfg: pointer to rotator vbif config
 * @rect_w: rotator frame width
 * @rect_h: rotator frame height
 */
static void _dpu_plane_inline_rot_set_ot_limit(struct drm_plane *plane,
		struct drm_crtc *crtc, const struct dpu_rot_vbif_cfg *cfg,
		u32 rect_w, u32 rect_h)
{
	struct dpu_vbif_set_ot_params ot_params;
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;

	if (!plane || !plane->dev) {
		DPU_ERROR("invalid arguments\n");
		return;
	}

	priv = plane->dev->dev_private;
	if (!priv || !priv->kms) {
		DPU_ERROR("invalid KMS reference\n");
		return;
	}

	dpu_kms = to_dpu_kms(priv->kms);

	memset(&ot_params, 0, sizeof(ot_params));
	ot_params.xin_id = cfg->xin_id;
	ot_params.num = cfg->num;
	ot_params.width = rect_w;
	ot_params.height = rect_h;
	ot_params.is_wfd = false;
	ot_params.frame_rate = crtc->mode.vrefresh;
	ot_params.vbif_idx = VBIF_RT;
	ot_params.clk_ctrl = cfg->clk_ctrl;
	ot_params.rd = cfg->is_read;

	dpu_vbif_set_ot_limit(dpu_kms, &ot_params);
}

/**
 * _dpu_plane_inline_rot_set_qos_remap - set vbif QoS for the given inline
 * rotation xin client
 * @plane: Pointer to drm plane
 * @cfg: Pointer to rotator vbif cfg
 */
static void _dpu_plane_inline_rot_set_qos_remap(struct drm_plane *plane,
		const struct dpu_rot_vbif_cfg *cfg)
{
	struct dpu_vbif_set_qos_params qos_params;
	struct msm_drm_private *priv;
	struct dpu_kms *dpu_kms;

	if (!plane || !plane->dev) {
		DPU_ERROR("invalid arguments\n");
		return;
	}

	priv = plane->dev->dev_private;
	if (!priv || !priv->kms) {
		DPU_ERROR("invalid KMS reference\n");
		return;
	}

	dpu_kms = to_dpu_kms(priv->kms);

	memset(&qos_params, 0, sizeof(qos_params));
	qos_params.vbif_idx = VBIF_RT;
	qos_params.xin_id = cfg->xin_id;
	qos_params.clk_ctrl = cfg->clk_ctrl;
	qos_params.num = cfg->num;
	qos_params.is_rt = true;

	DPU_DEBUG("vbif:%d xin:%d num:%d rt:%d clk_ctrl:%d\n",
			qos_params.vbif_idx, qos_params.xin_id,
			qos_params.num, qos_params.is_rt, qos_params.clk_ctrl);

	dpu_vbif_set_qos_remap(dpu_kms, &qos_params);
}

int dpu_plane_wait_input_fence(struct drm_plane *plane, uint32_t wait_ms)
{
	struct dpu_plane *pdpu;
	struct dpu_plane_state *pstate;
	uint32_t prefix;
	void *input_fence;
	int ret = -EINVAL;
	signed long rc;

	if (!plane) {
		DPU_ERROR("invalid plane\n");
	} else if (!plane->state) {
		DPU_ERROR_PLANE(to_dpu_plane(plane), "invalid state\n");
	} else {
		pdpu = to_dpu_plane(plane);
		pstate = to_dpu_plane_state(plane->state);
		input_fence = pstate->input_fence;

		if (input_fence) {
			pdpu->is_error = false;
			prefix = dpu_sync_get_name_prefix(input_fence);
			rc = dpu_sync_wait(input_fence, wait_ms);

			switch (rc) {
			case 0:
				DPU_ERROR_PLANE(pdpu, "%ums timeout on %08X\n",
						wait_ms, prefix);
				pdpu->is_error = true;
				ret = -ETIMEDOUT;
				break;
			case -ERESTARTSYS:
				DPU_ERROR_PLANE(pdpu,
					"%ums wait interrupted on %08X\n",
					wait_ms, prefix);
				pdpu->is_error = true;
				ret = -ERESTARTSYS;
				break;
			case -EINVAL:
				DPU_ERROR_PLANE(pdpu,
					"invalid fence param for %08X\n",
						prefix);
				pdpu->is_error = true;
				ret = -EINVAL;
				break;
			default:
				DPU_DEBUG_PLANE(pdpu, "signaled\n");
				ret = 0;
				break;
			}

			DPU_EVT32_VERBOSE(DRMID(plane), -ret, prefix);
		} else {
			ret = 0;
		}
	}
	return ret;
}

/**
 * _dpu_plane_get_aspace: gets the address space based on the
 *            fb_translation mode property
 */
static int _dpu_plane_get_aspace(
		struct dpu_plane *pdpu,
		struct dpu_plane_state *pstate,
		struct msm_gem_address_space **aspace)
{
	struct dpu_kms *kms;
	int mode;

	if (!pdpu || !pstate || !aspace) {
		DPU_ERROR("invalid parameters\n");
		return -EINVAL;
	}

	kms = _dpu_plane_get_kms(&pdpu->base);
	if (!kms) {
		DPU_ERROR("invalid kms\n");
		return -EINVAL;
	}

	*aspace = kms->base.aspace;

	return 0;
}

static inline void _dpu_plane_set_scanout(struct drm_plane *plane,
		struct dpu_plane_state *pstate,
		struct dpu_hw_pipe_cfg *pipe_cfg,
		struct drm_framebuffer *fb)
{
	struct dpu_plane *pdpu;
	struct msm_gem_address_space *aspace = NULL;
	int ret;

	if (!plane || !pstate || !pipe_cfg || !fb) {
		DPU_ERROR(
			"invalid arg(s), plane %d state %d cfg %d fb %d\n",
			plane != 0, pstate != 0, pipe_cfg != 0, fb != 0);
		return;
	}

	pdpu = to_dpu_plane(plane);
	if (!pdpu->pipe_hw) {
		DPU_ERROR_PLANE(pdpu, "invalid pipe_hw\n");
		return;
	}

	ret = _dpu_plane_get_aspace(pdpu, pstate, &aspace);
	if (ret) {
		DPU_ERROR_PLANE(pdpu, "Failed to get aspace %d\n", ret);
		return;
	}

	/*
	 * framebuffer prepare is deferred for prepare_fb calls that
	 * happen during the transition from secure to non-secure.
	 * Handle the prepare at this point for such cases. This can be
	 * expected for one or two frames during the transition.
	 */
	if (aspace && pstate->defer_prepare_fb) {
		ret = msm_framebuffer_prepare(fb, pstate->aspace);
		if (ret) {
			DPU_ERROR_PLANE(pdpu,
				"failed to prepare framebuffer %d\n", ret);
			return;
		}
		pstate->defer_prepare_fb = false;
	}

	ret = dpu_format_populate_layout(aspace, fb, &pipe_cfg->layout);
	if (ret == -EAGAIN)
		DPU_DEBUG_PLANE(pdpu, "not updating same src addrs\n");
	else if (ret)
		DPU_ERROR_PLANE(pdpu, "failed to get format layout, %d\n", ret);
	else if (pdpu->pipe_hw->ops.setup_sourceaddress) {
		DPU_EVT32_VERBOSE(pdpu->pipe_hw->idx,
				pipe_cfg->layout.width,
				pipe_cfg->layout.height,
				pipe_cfg->layout.plane_addr[0],
				pipe_cfg->layout.plane_size[0],
				pipe_cfg->layout.plane_addr[1],
				pipe_cfg->layout.plane_size[1],
				pipe_cfg->layout.plane_addr[2],
				pipe_cfg->layout.plane_size[2],
				pipe_cfg->layout.plane_addr[3],
				pipe_cfg->layout.plane_size[3],
				pstate->multirect_index);
		pdpu->pipe_hw->ops.setup_sourceaddress(pdpu->pipe_hw, pipe_cfg,
						pstate->multirect_index);
	}
}

static int _dpu_plane_setup_scaler3_lut(struct dpu_plane *pdpu,
		struct dpu_plane_state *pstate)
{
	struct dpu_hw_scaler3_cfg *cfg;
	int ret = 0;

	if (!pdpu || !pstate) {
		DPU_ERROR("invalid args\n");
		return -EINVAL;
	}

	cfg = &pstate->scaler3_cfg;

	cfg->dir_lut = msm_property_get_blob(
			&pdpu->property_info,
			&pstate->property_state, &cfg->dir_len,
			PLANE_PROP_SCALER_LUT_ED);
	cfg->cir_lut = msm_property_get_blob(
			&pdpu->property_info,
			&pstate->property_state, &cfg->cir_len,
			PLANE_PROP_SCALER_LUT_CIR);
	cfg->sep_lut = msm_property_get_blob(
			&pdpu->property_info,
			&pstate->property_state, &cfg->sep_len,
			PLANE_PROP_SCALER_LUT_SEP);
	if (!cfg->dir_lut || !cfg->cir_lut || !cfg->sep_lut)
		ret = -ENODATA;
	return ret;
}

static void _dpu_plane_setup_scaler3(struct dpu_plane *pdpu,
		struct dpu_plane_state *pstate,
		uint32_t src_w, uint32_t src_h, uint32_t dst_w, uint32_t dst_h,
		struct dpu_hw_scaler3_cfg *scale_cfg,
		const struct dpu_format *fmt,
		uint32_t chroma_subsmpl_h, uint32_t chroma_subsmpl_v)
{
	uint32_t decimated, i;

	if (!pdpu || !pstate || !scale_cfg || !fmt || !chroma_subsmpl_h ||
			!chroma_subsmpl_v) {
		DPU_ERROR(
			"pdpu %d pstate %d scale_cfg %d fmt %d smp_h %d smp_v %d\n",
			!!pdpu, !!pstate, !!scale_cfg, !!fmt, chroma_subsmpl_h,
			chroma_subsmpl_v);
		return;
	}

	memset(scale_cfg, 0, sizeof(*scale_cfg));
	memset(&pstate->pixel_ext, 0, sizeof(struct dpu_hw_pixel_ext));

	decimated = DECIMATED_DIMENSION(src_w,
			pdpu->pipe_cfg.horz_decimation);
	scale_cfg->phase_step_x[DPU_SSPP_COMP_0] =
		mult_frac((1 << PHASE_STEP_SHIFT), decimated, dst_w);
	decimated = DECIMATED_DIMENSION(src_h,
			pdpu->pipe_cfg.vert_decimation);
	scale_cfg->phase_step_y[DPU_SSPP_COMP_0] =
		mult_frac((1 << PHASE_STEP_SHIFT), decimated, dst_h);


	scale_cfg->phase_step_y[DPU_SSPP_COMP_1_2] =
		scale_cfg->phase_step_y[DPU_SSPP_COMP_0] / chroma_subsmpl_v;
	scale_cfg->phase_step_x[DPU_SSPP_COMP_1_2] =
		scale_cfg->phase_step_x[DPU_SSPP_COMP_0] / chroma_subsmpl_h;

	scale_cfg->phase_step_x[DPU_SSPP_COMP_2] =
		scale_cfg->phase_step_x[DPU_SSPP_COMP_1_2];
	scale_cfg->phase_step_y[DPU_SSPP_COMP_2] =
		scale_cfg->phase_step_y[DPU_SSPP_COMP_1_2];

	scale_cfg->phase_step_x[DPU_SSPP_COMP_3] =
		scale_cfg->phase_step_x[DPU_SSPP_COMP_0];
	scale_cfg->phase_step_y[DPU_SSPP_COMP_3] =
		scale_cfg->phase_step_y[DPU_SSPP_COMP_0];

	for (i = 0; i < DPU_MAX_PLANES; i++) {
		scale_cfg->src_width[i] = DECIMATED_DIMENSION(src_w,
				pdpu->pipe_cfg.horz_decimation);
		scale_cfg->src_height[i] = DECIMATED_DIMENSION(src_h,
				pdpu->pipe_cfg.vert_decimation);
		if (i == DPU_SSPP_COMP_1_2 || i == DPU_SSPP_COMP_2) {
			scale_cfg->src_width[i] /= chroma_subsmpl_h;
			scale_cfg->src_height[i] /= chroma_subsmpl_v;
		}
		scale_cfg->preload_x[i] = DPU_QSEED3_DEFAULT_PRELOAD_H;
		scale_cfg->preload_y[i] = DPU_QSEED3_DEFAULT_PRELOAD_V;
		pstate->pixel_ext.num_ext_pxls_top[i] =
			scale_cfg->src_height[i];
		pstate->pixel_ext.num_ext_pxls_left[i] =
			scale_cfg->src_width[i];
	}
	if (!(DPU_FORMAT_IS_YUV(fmt)) && (src_h == dst_h)
		&& (src_w == dst_w))
		return;

	scale_cfg->dst_width = dst_w;
	scale_cfg->dst_height = dst_h;
	scale_cfg->y_rgb_filter_cfg = DPU_SCALE_BIL;
	scale_cfg->uv_filter_cfg = DPU_SCALE_BIL;
	scale_cfg->alpha_filter_cfg = DPU_SCALE_ALPHA_BIL;
	scale_cfg->lut_flag = 0;
	scale_cfg->blend_cfg = 1;
	scale_cfg->enable = 1;
}

/**
 * _dpu_plane_setup_scaler2 - determine default scaler phase steps/filter type
 * @pdpu: Pointer to DPU plane object
 * @src: Source size
 * @dst: Destination size
 * @phase_steps: Pointer to output array for phase steps
 * @filter: Pointer to output array for filter type
 * @fmt: Pointer to format definition
 * @chroma_subsampling: Subsampling amount for chroma channel
 *
 * Returns: 0 on success
 */
static int _dpu_plane_setup_scaler2(struct dpu_plane *pdpu,
		uint32_t src, uint32_t dst, uint32_t *phase_steps,
		enum dpu_hw_filter *filter, const struct dpu_format *fmt,
		uint32_t chroma_subsampling)
{
	if (!pdpu || !phase_steps || !filter || !fmt) {
		DPU_ERROR(
			"invalid arg(s), plane %d phase %d filter %d fmt %d\n",
			pdpu != 0, phase_steps != 0, filter != 0, fmt != 0);
		return -EINVAL;
	}

	/* calculate phase steps, leave init phase as zero */
	phase_steps[DPU_SSPP_COMP_0] =
		mult_frac(1 << PHASE_STEP_SHIFT, src, dst);
	phase_steps[DPU_SSPP_COMP_1_2] =
		phase_steps[DPU_SSPP_COMP_0] / chroma_subsampling;
	phase_steps[DPU_SSPP_COMP_2] = phase_steps[DPU_SSPP_COMP_1_2];
	phase_steps[DPU_SSPP_COMP_3] = phase_steps[DPU_SSPP_COMP_0];

	/* calculate scaler config, if necessary */
	if (DPU_FORMAT_IS_YUV(fmt) || src != dst) {
		filter[DPU_SSPP_COMP_3] =
			(src <= dst) ? DPU_SCALE_FILTER_BIL :
			DPU_SCALE_FILTER_PCMN;

		if (DPU_FORMAT_IS_YUV(fmt)) {
			filter[DPU_SSPP_COMP_0] = DPU_SCALE_FILTER_CA;
			filter[DPU_SSPP_COMP_1_2] = filter[DPU_SSPP_COMP_3];
		} else {
			filter[DPU_SSPP_COMP_0] = filter[DPU_SSPP_COMP_3];
			filter[DPU_SSPP_COMP_1_2] =
				DPU_SCALE_FILTER_NEAREST;
		}
	} else {
		/* disable scaler */
		filter[DPU_SSPP_COMP_0] = DPU_SCALE_FILTER_MAX;
		filter[DPU_SSPP_COMP_1_2] = DPU_SCALE_FILTER_MAX;
		filter[DPU_SSPP_COMP_3] = DPU_SCALE_FILTER_MAX;
	}
	return 0;
}

/**
 * _dpu_plane_setup_pixel_ext - determine default pixel extension values
 * @pdpu: Pointer to DPU plane object
 * @src: Source size
 * @dst: Destination size
 * @decimated_src: Source size after decimation, if any
 * @phase_steps: Pointer to output array for phase steps
 * @out_src: Output array for pixel extension values
 * @out_edge1: Output array for pixel extension first edge
 * @out_edge2: Output array for pixel extension second edge
 * @filter: Pointer to array for filter type
 * @fmt: Pointer to format definition
 * @chroma_subsampling: Subsampling amount for chroma channel
 * @post_compare: Whether to chroma subsampled source size for comparisions
 */
static void _dpu_plane_setup_pixel_ext(struct dpu_plane *pdpu,
		uint32_t src, uint32_t dst, uint32_t decimated_src,
		uint32_t *phase_steps, uint32_t *out_src, int *out_edge1,
		int *out_edge2, enum dpu_hw_filter *filter,
		const struct dpu_format *fmt, uint32_t chroma_subsampling,
		bool post_compare)
{
	int64_t edge1, edge2, caf;
	uint32_t src_work;
	int i, tmp;

	if (pdpu && phase_steps && out_src && out_edge1 &&
			out_edge2 && filter && fmt) {
		/* handle CAF for YUV formats */
		if (DPU_FORMAT_IS_YUV(fmt) && *filter == DPU_SCALE_FILTER_CA)
			caf = PHASE_STEP_UNIT_SCALE;
		else
			caf = 0;

		for (i = 0; i < DPU_MAX_PLANES; i++) {
			src_work = decimated_src;
			if (i == DPU_SSPP_COMP_1_2 || i == DPU_SSPP_COMP_2)
				src_work /= chroma_subsampling;
			if (post_compare)
				src = src_work;
			if (!DPU_FORMAT_IS_YUV(fmt) && (src == dst)) {
				/* unity */
				edge1 = 0;
				edge2 = 0;
			} else if (dst >= src) {
				/* upscale */
				edge1 = (1 << PHASE_RESIDUAL);
				edge1 -= caf;
				edge2 = (1 << PHASE_RESIDUAL);
				edge2 += (dst - 1) * *(phase_steps + i);
				edge2 -= (src_work - 1) * PHASE_STEP_UNIT_SCALE;
				edge2 += caf;
				edge2 = -(edge2);
			} else {
				/* downscale */
				edge1 = 0;
				edge2 = (dst - 1) * *(phase_steps + i);
				edge2 -= (src_work - 1) * PHASE_STEP_UNIT_SCALE;
				edge2 += *(phase_steps + i);
				edge2 = -(edge2);
			}

			/* only enable CAF for luma plane */
			caf = 0;

			/* populate output arrays */
			*(out_src + i) = src_work;

			/* edge updates taken from __pxl_extn_helper */
			if (edge1 >= 0) {
				tmp = (uint32_t)edge1;
				tmp >>= PHASE_STEP_SHIFT;
				*(out_edge1 + i) = -tmp;
			} else {
				tmp = (uint32_t)(-edge1);
				*(out_edge1 + i) =
					(tmp + PHASE_STEP_UNIT_SCALE - 1) >>
					PHASE_STEP_SHIFT;
			}
			if (edge2 >= 0) {
				tmp = (uint32_t)edge2;
				tmp >>= PHASE_STEP_SHIFT;
				*(out_edge2 + i) = -tmp;
			} else {
				tmp = (uint32_t)(-edge2);
				*(out_edge2 + i) =
					(tmp + PHASE_STEP_UNIT_SCALE - 1) >>
					PHASE_STEP_SHIFT;
			}
		}
	}
}

static inline void _dpu_plane_setup_csc(struct dpu_plane *pdpu)
{
	static const struct dpu_csc_cfg dpu_csc_YUV2RGB_601L = {
		{
			/* S15.16 format */
			0x00012A00, 0x00000000, 0x00019880,
			0x00012A00, 0xFFFF9B80, 0xFFFF3000,
			0x00012A00, 0x00020480, 0x00000000,
		},
		/* signed bias */
		{ 0xfff0, 0xff80, 0xff80,},
		{ 0x0, 0x0, 0x0,},
		/* unsigned clamp */
		{ 0x10, 0xeb, 0x10, 0xf0, 0x10, 0xf0,},
		{ 0x00, 0xff, 0x00, 0xff, 0x00, 0xff,},
	};
	static const struct dpu_csc_cfg dpu_csc10_YUV2RGB_601L = {
		{
			/* S15.16 format */
			0x00012A00, 0x00000000, 0x00019880,
			0x00012A00, 0xFFFF9B80, 0xFFFF3000,
			0x00012A00, 0x00020480, 0x00000000,
			},
		/* signed bias */
		{ 0xffc0, 0xfe00, 0xfe00,},
		{ 0x0, 0x0, 0x0,},
		/* unsigned clamp */
		{ 0x40, 0x3ac, 0x40, 0x3c0, 0x40, 0x3c0,},
		{ 0x00, 0x3ff, 0x00, 0x3ff, 0x00, 0x3ff,},
	};

	if (!pdpu) {
		DPU_ERROR("invalid plane\n");
		return;
	}

	/* revert to kernel default if override not available */
	if (pdpu->csc_usr_ptr)
		pdpu->csc_ptr = pdpu->csc_usr_ptr;
	else if (BIT(DPU_SSPP_CSC_10BIT) & pdpu->features)
		pdpu->csc_ptr = (struct dpu_csc_cfg *)&dpu_csc10_YUV2RGB_601L;
	else
		pdpu->csc_ptr = (struct dpu_csc_cfg *)&dpu_csc_YUV2RGB_601L;

	DPU_DEBUG_PLANE(pdpu, "using 0x%X 0x%X 0x%X...\n",
			pdpu->csc_ptr->csc_mv[0],
			pdpu->csc_ptr->csc_mv[1],
			pdpu->csc_ptr->csc_mv[2]);
}

static void dpu_color_process_plane_setup(struct drm_plane *plane)
{
	struct dpu_plane *pdpu;
	struct dpu_plane_state *pstate;
	uint32_t hue, saturation, value, contrast;
	struct drm_msm_memcol *memcol = NULL;
	size_t memcol_sz = 0;

	pdpu = to_dpu_plane(plane);
	pstate = to_dpu_plane_state(plane->state);

	hue = (uint32_t) dpu_plane_get_property(pstate, PLANE_PROP_HUE_ADJUST);
	if (pdpu->pipe_hw->ops.setup_pa_hue)
		pdpu->pipe_hw->ops.setup_pa_hue(pdpu->pipe_hw, &hue);
	saturation = (uint32_t) dpu_plane_get_property(pstate,
		PLANE_PROP_SATURATION_ADJUST);
	if (pdpu->pipe_hw->ops.setup_pa_sat)
		pdpu->pipe_hw->ops.setup_pa_sat(pdpu->pipe_hw, &saturation);
	value = (uint32_t) dpu_plane_get_property(pstate,
		PLANE_PROP_VALUE_ADJUST);
	if (pdpu->pipe_hw->ops.setup_pa_val)
		pdpu->pipe_hw->ops.setup_pa_val(pdpu->pipe_hw, &value);
	contrast = (uint32_t) dpu_plane_get_property(pstate,
		PLANE_PROP_CONTRAST_ADJUST);
	if (pdpu->pipe_hw->ops.setup_pa_cont)
		pdpu->pipe_hw->ops.setup_pa_cont(pdpu->pipe_hw, &contrast);

	if (pdpu->pipe_hw->ops.setup_pa_memcolor) {
		/* Skin memory color setup */
		memcol = msm_property_get_blob(&pdpu->property_info,
					&pstate->property_state,
					&memcol_sz,
					PLANE_PROP_SKIN_COLOR);
		pdpu->pipe_hw->ops.setup_pa_memcolor(pdpu->pipe_hw,
					MEMCOLOR_SKIN, memcol);

		/* Sky memory color setup */
		memcol = msm_property_get_blob(&pdpu->property_info,
					&pstate->property_state,
					&memcol_sz,
					PLANE_PROP_SKY_COLOR);
		pdpu->pipe_hw->ops.setup_pa_memcolor(pdpu->pipe_hw,
					MEMCOLOR_SKY, memcol);

		/* Foliage memory color setup */
		memcol = msm_property_get_blob(&pdpu->property_info,
					&pstate->property_state,
					&memcol_sz,
					PLANE_PROP_FOLIAGE_COLOR);
		pdpu->pipe_hw->ops.setup_pa_memcolor(pdpu->pipe_hw,
					MEMCOLOR_FOLIAGE, memcol);
	}
}

static void _dpu_plane_setup_scaler(struct dpu_plane *pdpu,
		struct dpu_plane_state *pstate,
		const struct dpu_format *fmt, bool color_fill)
{
	struct dpu_hw_pixel_ext *pe;
	uint32_t chroma_subsmpl_h, chroma_subsmpl_v;

	if (!pdpu || !fmt || !pstate) {
		DPU_ERROR("invalid arg(s), plane %d fmt %d state %d\n",
				pdpu != 0, fmt != 0, pstate != 0);
		return;
	}

	pe = &pstate->pixel_ext;

	pdpu->pipe_cfg.horz_decimation =
		dpu_plane_get_property(pstate, PLANE_PROP_H_DECIMATE);
	pdpu->pipe_cfg.vert_decimation =
		dpu_plane_get_property(pstate, PLANE_PROP_V_DECIMATE);

	/* don't chroma subsample if decimating */
	chroma_subsmpl_h = pdpu->pipe_cfg.horz_decimation ? 1 :
		drm_format_horz_chroma_subsampling(fmt->base.pixel_format);
	chroma_subsmpl_v = pdpu->pipe_cfg.vert_decimation ? 1 :
		drm_format_vert_chroma_subsampling(fmt->base.pixel_format);

	/* update scaler */
	if (pdpu->features & BIT(DPU_SSPP_SCALER_QSEED3)) {
		int rc;

		if (!color_fill && !pdpu->debugfs_default_scale)
			rc = _dpu_plane_setup_scaler3_lut(pdpu, pstate);
		else
			rc = -EINVAL;
		if (rc || pstate->scaler_check_state !=
			DPU_PLANE_SCLCHECK_SCALER_V2) {
			/* calculate default config for QSEED3 */
			_dpu_plane_setup_scaler3(pdpu, pstate,
					pdpu->pipe_cfg.src_rect.w,
					pdpu->pipe_cfg.src_rect.h,
					pdpu->pipe_cfg.dst_rect.w,
					pdpu->pipe_cfg.dst_rect.h,
					&pstate->scaler3_cfg, fmt,
					chroma_subsmpl_h, chroma_subsmpl_v);
		}
	} else if (pstate->scaler_check_state != DPU_PLANE_SCLCHECK_SCALER_V1 ||
			color_fill || pdpu->debugfs_default_scale) {
		uint32_t deci_dim, i;

		/* calculate default configuration for QSEED2 */
		memset(pe, 0, sizeof(struct dpu_hw_pixel_ext));

		DPU_DEBUG_PLANE(pdpu, "default config\n");
		deci_dim = DECIMATED_DIMENSION(pdpu->pipe_cfg.src_rect.w,
				pdpu->pipe_cfg.horz_decimation);
		_dpu_plane_setup_scaler2(pdpu,
				deci_dim,
				pdpu->pipe_cfg.dst_rect.w,
				pe->phase_step_x,
				pe->horz_filter, fmt, chroma_subsmpl_h);

		if (DPU_FORMAT_IS_YUV(fmt))
			deci_dim &= ~0x1;
		_dpu_plane_setup_pixel_ext(pdpu, pdpu->pipe_cfg.src_rect.w,
				pdpu->pipe_cfg.dst_rect.w, deci_dim,
				pe->phase_step_x,
				pe->roi_w,
				pe->num_ext_pxls_left,
				pe->num_ext_pxls_right, pe->horz_filter, fmt,
				chroma_subsmpl_h, 0);

		deci_dim = DECIMATED_DIMENSION(pdpu->pipe_cfg.src_rect.h,
				pdpu->pipe_cfg.vert_decimation);
		_dpu_plane_setup_scaler2(pdpu,
				deci_dim,
				pdpu->pipe_cfg.dst_rect.h,
				pe->phase_step_y,
				pe->vert_filter, fmt, chroma_subsmpl_v);
		_dpu_plane_setup_pixel_ext(pdpu, pdpu->pipe_cfg.src_rect.h,
				pdpu->pipe_cfg.dst_rect.h, deci_dim,
				pe->phase_step_y,
				pe->roi_h,
				pe->num_ext_pxls_top,
				pe->num_ext_pxls_btm, pe->vert_filter, fmt,
				chroma_subsmpl_v, 1);

		for (i = 0; i < DPU_MAX_PLANES; i++) {
			if (pe->num_ext_pxls_left[i] >= 0)
				pe->left_rpt[i] = pe->num_ext_pxls_left[i];
			else
				pe->left_ftch[i] = pe->num_ext_pxls_left[i];

			if (pe->num_ext_pxls_right[i] >= 0)
				pe->right_rpt[i] = pe->num_ext_pxls_right[i];
			else
				pe->right_ftch[i] = pe->num_ext_pxls_right[i];

			if (pe->num_ext_pxls_top[i] >= 0)
				pe->top_rpt[i] = pe->num_ext_pxls_top[i];
			else
				pe->top_ftch[i] = pe->num_ext_pxls_top[i];

			if (pe->num_ext_pxls_btm[i] >= 0)
				pe->btm_rpt[i] = pe->num_ext_pxls_btm[i];
			else
				pe->btm_ftch[i] = pe->num_ext_pxls_btm[i];
		}
	}
}

/**
 * _dpu_plane_color_fill - enables color fill on plane
 * @pdpu:   Pointer to DPU plane object
 * @color:  RGB fill color value, [23..16] Blue, [15..8] Green, [7..0] Red
 * @alpha:  8-bit fill alpha value, 255 selects 100% alpha
 * Returns: 0 on success
 */
static int _dpu_plane_color_fill(struct dpu_plane *pdpu,
		uint32_t color, uint32_t alpha)
{
	const struct dpu_format *fmt;
	const struct drm_plane *plane;
	struct dpu_plane_state *pstate;

	if (!pdpu || !pdpu->base.state) {
		DPU_ERROR("invalid plane\n");
		return -EINVAL;
	}

	if (!pdpu->pipe_hw) {
		DPU_ERROR_PLANE(pdpu, "invalid plane h/w pointer\n");
		return -EINVAL;
	}

	plane = &pdpu->base;
	pstate = to_dpu_plane_state(plane->state);

	DPU_DEBUG_PLANE(pdpu, "\n");

	/*
	 * select fill format to match user property expectation,
	 * h/w only supports RGB variants
	 */
	fmt = dpu_get_dpu_format(DRM_FORMAT_ABGR8888);

	/* update sspp */
	if (fmt && pdpu->pipe_hw->ops.setup_solidfill) {
		pdpu->pipe_hw->ops.setup_solidfill(pdpu->pipe_hw,
				(color & 0xFFFFFF) | ((alpha & 0xFF) << 24),
				pstate->multirect_index);

		/* override scaler/decimation if solid fill */
		pdpu->pipe_cfg.src_rect.x = 0;
		pdpu->pipe_cfg.src_rect.y = 0;
		pdpu->pipe_cfg.src_rect.w = pdpu->pipe_cfg.dst_rect.w;
		pdpu->pipe_cfg.src_rect.h = pdpu->pipe_cfg.dst_rect.h;
		_dpu_plane_setup_scaler(pdpu, pstate, fmt, true);

		if (pdpu->pipe_hw->ops.setup_format)
			pdpu->pipe_hw->ops.setup_format(pdpu->pipe_hw,
					fmt, DPU_SSPP_SOLID_FILL,
					pstate->multirect_index);

		if (pdpu->pipe_hw->ops.setup_rects)
			pdpu->pipe_hw->ops.setup_rects(pdpu->pipe_hw,
					&pdpu->pipe_cfg,
					pstate->multirect_index);

		if (pdpu->pipe_hw->ops.setup_pe)
			pdpu->pipe_hw->ops.setup_pe(pdpu->pipe_hw,
					&pstate->pixel_ext);

		if (pdpu->pipe_hw->ops.setup_scaler &&
				pstate->multirect_index != DPU_SSPP_RECT_1)
			pdpu->pipe_hw->ops.setup_scaler(pdpu->pipe_hw,
					&pdpu->pipe_cfg, &pstate->pixel_ext,
					&pstate->scaler3_cfg);
	}

	return 0;
}

/**
 * _dpu_plane_fb_get/put - framebuffer callback for crtc res ops
 */
static void *_dpu_plane_fb_get(void *fb, u32 type, u64 tag)
{
	drm_framebuffer_get(fb);
	return fb;
}
static void _dpu_plane_fb_put(void *fb)
{
	drm_framebuffer_put(fb);
}
static struct dpu_crtc_res_ops fb_res_ops = {
	.put = _dpu_plane_fb_put,
	.get = _dpu_plane_fb_get,
};

/**
 * _dpu_plane_fbo_get/put - framebuffer object callback for crtc res ops
 */
static void *_dpu_plane_fbo_get(void *fbo, u32 type, u64 tag)
{
	dpu_kms_fbo_reference(fbo);
	return fbo;
}
static void _dpu_plane_fbo_put(void *fbo)
{
	dpu_kms_fbo_unreference(fbo);
}
static struct dpu_crtc_res_ops fbo_res_ops = {
	.put = _dpu_plane_fbo_put,
	.get = _dpu_plane_fbo_get,
};

/**
 * dpu_plane_rot_calc_prefill - calculate rotator start prefill
 * @plane: Pointer to drm plane
 * return: prefill time in line
 */
u32 dpu_plane_rot_calc_prefill(struct drm_plane *plane)
{
	struct drm_plane_state *state;
	struct dpu_plane_state *pstate;
	struct dpu_plane_rot_state *rstate;
	struct dpu_kms *dpu_kms;
	u32 blocksize = 128;
	u32 prefill_line = 0;

	if (!plane || !plane->state || !plane->state->fb) {
		DPU_ERROR("invalid parameters\n");
		return 0;
	}

	dpu_kms = _dpu_plane_get_kms(plane);
	state = plane->state;
	pstate = to_dpu_plane_state(state);
	rstate = &pstate->rot;

	if (!dpu_kms || !dpu_kms->catalog) {
		DPU_ERROR("invalid kms\n");
		return 0;
	}

	if (rstate->out_fb_format)
		dpu_format_get_block_size(rstate->out_fb_format,
				&blocksize, &blocksize);

	prefill_line = blocksize + dpu_kms->catalog->sbuf_headroom;
	prefill_line = mult_frac(prefill_line, rstate->out_src_h >> 16,
			state->crtc_h);
	DPU_DEBUG(
		"plane%d.%d blk:%u head:%u vdst/vsrc:%u/%u prefill:%u\n",
			plane->base.id, rstate->sequence_id,
			blocksize, dpu_kms->catalog->sbuf_headroom,
			state->crtc_h, rstate->out_src_h >> 16,
			prefill_line);

	return prefill_line;
}

/**
 * dpu_plane_rot_calc_cfg - calculate rotator/sspp configuration by
 *	enumerating over all planes attached to the same rotator
 * @plane: Pointer to drm plane
 * @state: Pointer to drm state to be updated
 * return: 0 if success; error code otherwise
 */
static int dpu_plane_rot_calc_cfg(struct drm_plane *plane,
		struct drm_plane_state *state)
{
	struct dpu_plane_state *pstate;
	struct dpu_plane_rot_state *rstate;
	struct drm_crtc_state *cstate;
	struct drm_rect *in_rot, *out_rot;
	struct drm_plane *attached_plane;
	u32 dst_x, dst_y, dst_w, dst_h;
	int found = 0;
	int xpos = 0;
	int ret;

	if (!plane || !state || !state->state) {
		DPU_ERROR("invalid parameters\n");
		return -EINVAL;
	}

	cstate = _dpu_plane_get_crtc_state(state);
	if (IS_ERR_OR_NULL(cstate)) {
		ret = PTR_ERR(cstate);
		DPU_ERROR("invalid crtc state %d\n", ret);
		return ret;
	}

	pstate = to_dpu_plane_state(state);
	rstate = &pstate->rot;

	in_rot = &rstate->in_rot_rect;
	*in_rot = drm_plane_state_src(state);

	out_rot = &rstate->out_rot_rect;
	dst_x = dpu_plane_get_property(pstate, PLANE_PROP_ROT_DST_X);
	dst_y = dpu_plane_get_property(pstate, PLANE_PROP_ROT_DST_Y);
	dst_w = dpu_plane_get_property(pstate, PLANE_PROP_ROT_DST_W);
	dst_h = dpu_plane_get_property(pstate, PLANE_PROP_ROT_DST_H);

	if (!dst_w && !dst_h) {
		rstate->out_rot_rect = rstate->in_rot_rect;
		drm_rect_rotate(&rstate->out_rot_rect, state->fb->width << 16,
				state->fb->height << 16, rstate->in_rotation);
	} else {
		out_rot->x1 = dst_x;
		out_rot->y1 = dst_y;
		out_rot->x2 = dst_x + dst_w;
		out_rot->y2 = dst_y + dst_h;
	}

	rstate->out_src_rect = rstate->out_rot_rect;

	/* enumerating over all planes attached to the same rotator */
	drm_atomic_crtc_state_for_each_plane(attached_plane, cstate) {
		struct drm_plane_state *attached_state;
		struct dpu_plane_state *attached_pstate;
		struct dpu_plane_rot_state *attached_rstate;
		struct drm_rect attached_out_rect;

		attached_state = drm_atomic_get_existing_plane_state(
				state->state, attached_plane);

		if (!attached_state)
			continue;

		attached_pstate = to_dpu_plane_state(attached_state);
		attached_rstate = &attached_pstate->rot;

		if (attached_state->fb != state->fb)
			continue;

		if (dpu_plane_get_property(pstate, PLANE_PROP_ROTATION) !=
			dpu_plane_get_property(attached_pstate,
				PLANE_PROP_ROTATION))
			continue;

		found++;

		/* skip itself */
		if (attached_plane == plane)
			continue;

		/* find bounding rotator source roi */
		if (attached_state->src_x < in_rot->x1)
			in_rot->x1 = attached_state->src_x;

		if (attached_state->src_y < in_rot->y1)
			in_rot->y1 = attached_state->src_y;

		if (attached_state->src_x + attached_state->src_w > in_rot->x2)
			in_rot->x2 = attached_state->src_x +
				attached_state->src_w;

		if (attached_state->src_y + attached_state->src_h > in_rot->y2)
			in_rot->y2 = attached_state->src_y +
				attached_state->src_h;

		/* find bounding rotator destination roi */
		dst_x = dpu_plane_get_property(attached_pstate,
				PLANE_PROP_ROT_DST_X);
		dst_y = dpu_plane_get_property(attached_pstate,
				PLANE_PROP_ROT_DST_Y);
		dst_w = dpu_plane_get_property(attached_pstate,
				PLANE_PROP_ROT_DST_W);
		dst_h = dpu_plane_get_property(attached_pstate,
				PLANE_PROP_ROT_DST_H);
		if (!dst_w && !dst_h) {
			attached_out_rect = drm_plane_state_src(attached_state);
			drm_rect_rotate(&attached_out_rect,
					state->fb->width << 16,
					state->fb->height << 16,
					rstate->in_rotation);
		} else {
			attached_out_rect.x1 = dst_x;
			attached_out_rect.y1 = dst_y;
			attached_out_rect.x2 = dst_x + dst_w;
			attached_out_rect.y2 = dst_y + dst_h;
		}

		/* check source split left/right mismatch */
		if (attached_out_rect.y1 != rstate->out_src_rect.y1 ||
			attached_out_rect.y2 != rstate->out_src_rect.y2) {
			DPU_ERROR(
				"plane%d.%u src:%dx%d+%d+%d rot:0x%llx fb:%d plane%d.%u src:%dx%d+%d+%d rot:0x%llx fb:%d mismatch\n",
					plane->base.id,
					rstate->sequence_id,
					state->src_w >> 16,
					state->src_h >> 16,
					state->src_x >> 16,
					state->src_y >> 16,
					dpu_plane_get_property(pstate,
							PLANE_PROP_ROTATION),
					state->fb ?
						state->fb->base.id :
						-1,
					attached_plane->base.id,
					attached_rstate->sequence_id,
					attached_state->src_w >> 16,
					attached_state->src_h >> 16,
					attached_state->src_x >> 16,
					attached_state->src_y >> 16,
					dpu_plane_get_property(attached_pstate,
							PLANE_PROP_ROTATION),
					attached_state->fb ?
						attached_state->fb->base.id :
						-1);
			DPU_ERROR(
				"plane%d.%u sspp:%dx%d+%d+%d plane%d.%u sspp:%dx%d+%d+%d\n",
					plane->base.id,
					rstate->sequence_id,
					(rstate->out_src_rect.x2 -
						rstate->out_src_rect.x1) >> 16,
					(rstate->out_src_rect.y2 -
						rstate->out_src_rect.y1) >> 16,
					rstate->out_src_rect.x1 >> 16,
					rstate->out_src_rect.y1 >> 16,
					attached_plane->base.id,
					attached_rstate->sequence_id,
					(attached_out_rect.x2 -
						attached_out_rect.x1) >> 16,
					(attached_out_rect.y2 -
						attached_out_rect.y1) >> 16,
					attached_out_rect.x1 >> 16,
					attached_out_rect.y1 >> 16);
			DPU_EVT32(DRMID(plane),
					rstate->sequence_id,
					rstate->out_src_rect.x1 >> 16,
					rstate->out_src_rect.y1 >> 16,
					(rstate->out_src_rect.x2 -
						rstate->out_src_rect.x1) >> 16,
					(rstate->out_src_rect.y2 -
						rstate->out_src_rect.y1) >> 16,
					attached_plane->base.id,
					attached_rstate->sequence_id,
					attached_out_rect.x1 >> 16,
					attached_out_rect.y1 >> 16,
					(attached_out_rect.x2 -
						attached_out_rect.x1) >> 16,
					(attached_out_rect.y2 -
						attached_out_rect.y1) >> 16,
					DPU_EVTLOG_ERROR);
			return -EINVAL;
		}

		/* find relative sspp position */
		if (attached_out_rect.x1 < rstate->out_src_rect.x1)
			xpos++;

		if (attached_out_rect.x1 < out_rot->x1)
			out_rot->x1 = attached_out_rect.x1;

		if (attached_out_rect.y1 < out_rot->y1)
			out_rot->y1 = attached_out_rect.y1;

		if (attached_out_rect.x2 > out_rot->x2)
			out_rot->x2 = attached_out_rect.x2;

		if (attached_out_rect.y2 > out_rot->y2)
			out_rot->y2 = attached_out_rect.y2;

		DPU_DEBUG("plane%d.%u src_x:%d sspp:%dx%d+%d+%d/%dx%d+%d+%d\n",
			attached_plane->base.id,
			attached_rstate->sequence_id,
			attached_rstate->out_src_rect.x1 >> 16,
			attached_state->src_w >> 16,
			attached_state->src_h >> 16,
			attached_state->src_x >> 16,
			attached_state->src_y >> 16,
			drm_rect_width(&attached_rstate->out_src_rect) >> 16,
			drm_rect_height(&attached_rstate->out_src_rect) >> 16,
			attached_rstate->out_src_rect.x1 >> 16,
			attached_rstate->out_src_rect.y1 >> 16);
	}

	rstate->out_xpos = xpos;
	rstate->nplane = found;

	DPU_DEBUG("plane%d.%u xpos:%d/%d rot:%dx%d+%d+%d/%dx%d+%d+%d\n",
			plane->base.id, rstate->sequence_id,
			rstate->out_xpos, rstate->nplane,
			drm_rect_width(in_rot) >> 16,
			drm_rect_height(in_rot) >> 16,
			in_rot->x1 >> 16, in_rot->y1 >> 16,
			drm_rect_width(&rstate->out_rot_rect) >> 16,
			drm_rect_height(&rstate->out_rot_rect) >> 16,
			rstate->out_rot_rect.x1 >> 16,
			rstate->out_rot_rect.y1 >> 16);
	DPU_EVT32(DRMID(plane), rstate->sequence_id,
			rstate->out_xpos, rstate->nplane,
			in_rot->x1 >> 16, in_rot->y1 >> 16,
			drm_rect_width(in_rot) >> 16,
			drm_rect_height(in_rot) >> 16,
			rstate->out_rot_rect.x1 >> 16,
			rstate->out_rot_rect.y1 >> 16,
			drm_rect_width(&rstate->out_rot_rect) >> 16,
			drm_rect_height(&rstate->out_rot_rect) >> 16);

	return 0;
}

/**
 * dpu_plane_rot_submit_command - commit given state for the rotator stage
 * @plane: Pointer to drm plane
 * @state: Pointer to the state to be committed
 * @hw_cmd: rotator command type
 * return: 0 if success; error code otherwise
 */
static int dpu_plane_rot_submit_command(struct drm_plane *plane,
		struct drm_plane_state *state, enum dpu_hw_rot_cmd_type hw_cmd)
{
	struct dpu_plane *pdpu = to_dpu_plane(plane);
	struct dpu_plane_state *pstate = to_dpu_plane_state(state);
	struct dpu_plane_rot_state *rstate = &pstate->rot;
	struct dpu_hw_rot_cmd *rot_cmd;
	struct drm_crtc_state *cstate;
	struct dpu_crtc_state *dpu_cstate;
	int ret, i;
	int fb_mode;

	if (!plane || !state || !state->fb || !rstate->rot_hw) {
		DPU_ERROR("invalid parameters\n");
		return -EINVAL;
	}

	cstate = _dpu_plane_get_crtc_state(state);
	if (IS_ERR_OR_NULL(cstate)) {
		DPU_ERROR("invalid crtc state %ld\n", PTR_ERR(cstate));
		return -EINVAL;
	}
	dpu_cstate = to_dpu_crtc_state(cstate);

	rot_cmd = &rstate->rot_cmd;

	rot_cmd->master = (rstate->out_xpos == 0);
	rot_cmd->sequence_id = rstate->sequence_id;
	rot_cmd->fps = pstate->base.crtc && pstate->base.crtc->state ?
		drm_mode_vrefresh(&pstate->base.crtc->state->adjusted_mode) :
		DEFAULT_REFRESH_RATE;
	rot_cmd->rot90 = rstate->rot90;
	rot_cmd->hflip = rstate->hflip;
	rot_cmd->vflip = rstate->vflip;
	fb_mode = dpu_plane_get_property(pstate,
			PLANE_PROP_FB_TRANSLATION_MODE);
	if ((fb_mode == DPU_DRM_FB_SEC) ||
			(fb_mode == DPU_DRM_FB_SEC_DIR_TRANS))
		rot_cmd->secure = true;
	else
		rot_cmd->secure = false;

	rot_cmd->prefill_bw = dpu_crtc_get_property(dpu_cstate,
			CRTC_PROP_ROT_PREFILL_BW);
	rot_cmd->clkrate = dpu_crtc_get_property(dpu_cstate,
			CRTC_PROP_ROT_CLK);
	rot_cmd->dst_writeback = pdpu->sbuf_writeback;

	if (dpu_crtc_get_intf_mode(state->crtc) == INTF_MODE_VIDEO)
		rot_cmd->video_mode = true;
	else
		rot_cmd->video_mode = false;

	rot_cmd->src_pixel_format = state->fb->format->format;
	rot_cmd->src_modifier = state->fb->modifier;
	rot_cmd->src_stride = state->fb->pitches[0];

	rot_cmd->src_format = to_dpu_format(msm_framebuffer_format(state->fb));
	if (!rot_cmd->src_format) {
		DPU_ERROR("failed to get src format\n");
		return -EINVAL;
	}

	rot_cmd->src_width = state->fb->width;
	rot_cmd->src_height = state->fb->height;
	rot_cmd->src_rect_x = rstate->in_rot_rect.x1 >> 16;
	rot_cmd->src_rect_y = rstate->in_rot_rect.y1 >> 16;
	rot_cmd->src_rect_w = drm_rect_width(&rstate->in_rot_rect) >> 16;
	rot_cmd->src_rect_h = drm_rect_height(&rstate->in_rot_rect) >> 16;
	rot_cmd->dst_rect_x = 0;
	rot_cmd->dst_rect_y = 0;
	rot_cmd->dst_rect_w = drm_rect_width(&rstate->out_rot_rect) >> 16;
	rot_cmd->dst_rect_h = drm_rect_height(&rstate->out_rot_rect) >> 16;

	if (hw_cmd == DPU_HW_ROT_CMD_COMMIT) {
		struct dpu_hw_fmt_layout layout;

		memset(&layout, 0, sizeof(struct dpu_hw_fmt_layout));
		dpu_format_populate_layout(pstate->aspace, state->fb,
				&layout);
		for (i = 0; i < ARRAY_SIZE(rot_cmd->src_iova); i++) {
			rot_cmd->src_iova[i] = layout.plane_addr[i];
			rot_cmd->src_len[i] = layout.plane_size[i];
		}
		rot_cmd->src_planes = layout.num_planes;

		memset(&layout, 0, sizeof(struct dpu_hw_fmt_layout));
		dpu_format_populate_layout(pstate->aspace, rstate->out_fb,
				&layout);
		for (i = 0; i < ARRAY_SIZE(rot_cmd->dst_iova); i++) {
			rot_cmd->dst_iova[i] = layout.plane_addr[i];
			rot_cmd->dst_len[i] = layout.plane_size[i];
		}
		rot_cmd->dst_planes = layout.num_planes;

		/* VBIF remapper settings */
		for (i = 0; i < rstate->rot_hw->caps->xin_count; i++) {
			const struct dpu_rot_vbif_cfg *cfg =
					&rstate->rot_hw->caps->vbif_cfg[i];

			_dpu_plane_inline_rot_set_qos_remap(plane, cfg);

			if (cfg->is_read) {
				_dpu_plane_inline_rot_set_ot_limit(plane,
					state->crtc, cfg, rot_cmd->src_rect_w,
					rot_cmd->src_rect_h);
			} else {
				_dpu_plane_inline_rot_set_ot_limit(plane,
					state->crtc, cfg, rot_cmd->dst_rect_w,
					rot_cmd->dst_rect_h);
			}
		}
	}

	ret = rstate->rot_hw->ops.commit(rstate->rot_hw, rot_cmd, hw_cmd);
	if (ret)
		return ret;

	rstate->out_rotation = rstate->in_rotation;
	rstate->out_fb_flags = rot_cmd->dst_modifier ?
			DRM_MODE_FB_MODIFIERS : 0;
	rstate->out_fb_flags |= rot_cmd->secure ? DRM_MODE_FB_SECURE : 0;
	rstate->out_fb_format = rot_cmd->dst_format;
	rstate->out_fb_pixel_format = rot_cmd->dst_pixel_format;

	for (i = 0; i < ARRAY_SIZE(rstate->out_fb_modifier); i++)
		rstate->out_fb_modifier[i] = rot_cmd->dst_modifier;

	rstate->out_fb_width = drm_rect_width(&rstate->out_rot_rect) >> 16;
	rstate->out_fb_height = drm_rect_height(&rstate->out_rot_rect) >> 16;
	rstate->out_src_x = rstate->out_src_rect.x1 - rstate->out_rot_rect.x1;
	rstate->out_src_y = rstate->out_src_rect.y1 - rstate->out_rot_rect.y1;
	rstate->out_src_w = drm_rect_width(&rstate->out_src_rect);
	rstate->out_src_h = drm_rect_height(&rstate->out_src_rect);

	if (rot_cmd->rot90)
		rstate->out_rotation &= ~DRM_MODE_ROTATE_90;

	if (rot_cmd->hflip)
		rstate->out_rotation &= ~DRM_MODE_REFLECT_X;

	if (rot_cmd->vflip)
		rstate->out_rotation &= ~DRM_MODE_REFLECT_Y;

	DPU_DEBUG(
		"plane%d.%d rot:%d/%c%c%c%c/%dx%d/%4.4s/%llx/%dx%d+%d+%d\n",
			plane->base.id, rstate->sequence_id, hw_cmd,
			rot_cmd->rot90 ? 'r' : '_',
			rot_cmd->hflip ? 'h' : '_',
			rot_cmd->vflip ? 'v' : '_',
			rot_cmd->video_mode ? 'V' : 'C',
			state->fb->width, state->fb->height,
			(char *) &state->fb->format->format,
			state->fb->modifier,
			drm_rect_width(&rstate->in_rot_rect) >> 16,
			drm_rect_height(&rstate->in_rot_rect) >> 16,
			rstate->in_rot_rect.x1 >> 16,
			rstate->in_rot_rect.y1 >> 16);

	DPU_DEBUG("plane%d.%d sspp:%d/%x/%dx%d/%4.4s/%llx/%dx%d+%d+%d\n",
			plane->base.id, rstate->sequence_id, hw_cmd,
			rstate->out_rotation,
			rstate->out_fb_width, rstate->out_fb_height,
			(char *) &rstate->out_fb_pixel_format,
			rstate->out_fb_modifier[0],
			rstate->out_src_w >> 16, rstate->out_src_h >> 16,
			rstate->out_src_x >> 16, rstate->out_src_y >> 16);

	return ret;
}

/**
 * _dpu_plane_rot_get_fb - attempt to get previously allocated fb/fbo
 *	If an fb/fbo was already created, either from a previous frame or
 *	from another plane in the current commit cycle, attempt to reuse
 *	it for this commit cycle as well.
 * @plane: Pointer to drm plane
 * @cstate: Pointer to crtc state
 * @rstate: Pointer to rotator plane state
 */
static void _dpu_plane_rot_get_fb(struct drm_plane *plane,
		struct drm_crtc_state *cstate,
		struct dpu_plane_rot_state *rstate)
{
	struct dpu_kms_fbo *fbo;
	struct drm_framebuffer *fb;

	if (!plane || !cstate || !rstate || !rstate->rot_hw)
		return;

	fbo = dpu_crtc_res_get(cstate, DPU_CRTC_RES_ROT_OUT_FBO,
			(u64) &rstate->rot_hw->base);
	fb = dpu_crtc_res_get(cstate, DPU_CRTC_RES_ROT_OUT_FB,
			(u64) &rstate->rot_hw->base);
	if (fb && fbo) {
		DPU_DEBUG("plane%d.%d get fb/fbo\n", plane->base.id,
				rstate->sequence_id);
	} else if (fbo) {
		dpu_crtc_res_put(cstate, DPU_CRTC_RES_ROT_OUT_FBO,
				(u64) &rstate->rot_hw->base);
		fbo = NULL;
	} else if (fb) {
		dpu_crtc_res_put(cstate, DPU_CRTC_RES_ROT_OUT_FB,
				(u64) &rstate->rot_hw->base);
		fb = NULL;
	}

	rstate->out_fbo = fbo;
	rstate->out_fb = fb;
}

/**
 * dpu_plane_rot_prepare_fb - prepare framebuffer of the new state
 *	for rotator (pre-sspp) stage
 * @plane: Pointer to drm plane
 * @new_state: Pointer to new drm plane state
 * return: 0 if success; error code otherwise
 */
static int dpu_plane_rot_prepare_fb(struct drm_plane *plane,
		struct drm_plane_state *new_state)
{
	struct drm_framebuffer *fb = new_state->fb;
	struct dpu_plane_state *new_pstate = to_dpu_plane_state(new_state);
	struct dpu_plane_rot_state *new_rstate = &new_pstate->rot;
	struct drm_crtc_state *cstate;
	int ret;

	DPU_DEBUG("plane%d.%d FB[%u] sbuf:%d rot:%d crtc:%d\n",
			plane->base.id,
			new_rstate->sequence_id, fb ? fb->base.id : 0,
			!!new_rstate->out_sbuf, !!new_rstate->rot_hw,
			dpu_plane_crtc_enabled(new_state));

	if (!new_rstate->out_sbuf || !new_rstate->rot_hw)
		return 0;

	cstate = _dpu_plane_get_crtc_state(new_state);
	if (IS_ERR(cstate)) {
		ret = PTR_ERR(cstate);
		DPU_ERROR("invalid crtc state %d\n", ret);
		return ret;
	}

	/* need to re-calc based on all newly validated plane states */
	ret = dpu_plane_rot_calc_cfg(plane, new_state);
	if (ret)
		return ret;

	/* check if stream buffer is already attached to rotator */
	if (dpu_plane_enabled(new_state) && !new_rstate->out_fb)
		_dpu_plane_rot_get_fb(plane, cstate, new_rstate);

	/* create new stream buffer if it is not available */
	if (dpu_plane_enabled(new_state) && !new_rstate->out_fb) {
		u32 fb_w = drm_rect_width(&new_rstate->out_rot_rect) >> 16;
		u32 fb_h = drm_rect_height(&new_rstate->out_rot_rect) >> 16;

		DPU_DEBUG("plane%d.%d allocate fb/fbo\n", plane->base.id,
				new_rstate->sequence_id);

		/* check if out_fb is already attached to rotator */
		new_rstate->out_fbo = dpu_kms_fbo_alloc(plane->dev, fb_w, fb_h,
				new_rstate->out_fb_pixel_format,
				new_rstate->out_fb_modifier,
				new_rstate->out_fb_flags);
		if (!new_rstate->out_fbo) {
			DPU_ERROR("failed to allocate inline buffer object\n");
			ret = -EINVAL;
			goto error_create_fbo;
		}

		ret = dpu_crtc_res_add(cstate, DPU_CRTC_RES_ROT_OUT_FBO,
				(u64) &new_rstate->rot_hw->base,
				new_rstate->out_fbo, &fbo_res_ops);
		if (ret) {
			DPU_ERROR("failed to add crtc resource\n");
			goto error_create_fbo_res;
		}

		new_rstate->out_fb = dpu_kms_fbo_create_fb(plane->dev,
				new_rstate->out_fbo);
		if (!new_rstate->out_fb) {
			DPU_ERROR("failed to create inline framebuffer\n");
			ret = -EINVAL;
			goto error_create_fb;
		}
		DPU_EVT32_VERBOSE(DRMID(plane), new_rstate->sequence_id,
				new_rstate->out_fb->base.id);

		ret = dpu_crtc_res_add(cstate, DPU_CRTC_RES_ROT_OUT_FB,
				(u64) &new_rstate->rot_hw->base,
				new_rstate->out_fb, &fb_res_ops);
		if (ret) {
			DPU_ERROR("failed to add crtc resource %d\n", ret);
			goto error_create_fb_res;
		}
	}

	if (new_pstate->defer_prepare_fb) {
		DPU_DEBUG(
		    "plane%d, domain not attached, prepare fb handled later\n",
		    plane->base.id);
		return 0;
	}

	/* prepare rotator input buffer */
	ret = msm_framebuffer_prepare(new_state->fb, new_pstate->aspace);
	if (ret) {
		DPU_ERROR("failed to prepare input framebuffer, %d\n", ret);
		goto error_prepare_input_buffer;
	}

	/* prepare rotator output buffer */
	if (dpu_plane_enabled(new_state) && new_rstate->out_fb) {
		DPU_DEBUG("plane%d.%d prepare fb/fbo\n", plane->base.id,
				new_rstate->sequence_id);

		ret = msm_framebuffer_prepare(new_rstate->out_fb,
				new_pstate->aspace);
		if (ret) {
			DPU_ERROR("failed to prepare inline framebuffer, %d\n",
					ret);
			goto error_prepare_output_buffer;
		}
	}

	return 0;

error_prepare_output_buffer:
	msm_framebuffer_cleanup(new_state->fb, new_pstate->aspace);
error_prepare_input_buffer:
	dpu_crtc_res_put(cstate, DPU_CRTC_RES_ROT_OUT_FB,
			(u64) &new_rstate->rot_hw->base);
error_create_fb_res:
	new_rstate->out_fb = NULL;
error_create_fb:
	dpu_crtc_res_put(cstate, DPU_CRTC_RES_ROT_OUT_FBO,
			(u64) &new_rstate->rot_hw->base);
error_create_fbo_res:
	new_rstate->out_fbo = NULL;
error_create_fbo:
	return ret;
}

/**
 * dpu_plane_rot_cleanup_fb - cleanup framebuffer of previous state for the
 *	rotator (pre-sspp) stage
 * @plane: Pointer to drm plane
 * @old_state: Pointer to previous drm plane state
 * return: none
 */
static void dpu_plane_rot_cleanup_fb(struct drm_plane *plane,
		struct drm_plane_state *old_state)
{
	struct dpu_plane_state *old_pstate = to_dpu_plane_state(old_state);
	struct dpu_plane_rot_state *old_rstate = &old_pstate->rot;
	struct dpu_hw_rot_cmd *cmd = &old_rstate->rot_cmd;
	struct drm_crtc_state *cstate;
	int ret;

	DPU_DEBUG("plane%d.%d FB[%u] sbuf:%d rot:%d crtc:%d\n", plane->base.id,
			old_rstate->sequence_id, old_state->fb->base.id,
			!!old_rstate->out_sbuf, !!old_rstate->rot_hw,
			dpu_plane_crtc_enabled(old_state));

	if (!old_rstate->out_sbuf || !old_rstate->rot_hw)
		return;

	cstate = _dpu_plane_get_crtc_state(old_state);
	if (IS_ERR(cstate)) {
		ret = PTR_ERR(cstate);
		DPU_ERROR("invalid crtc state %d\n", ret);
		return;
	}

	if (dpu_plane_crtc_enabled(old_state)) {
		ret = old_rstate->rot_hw->ops.commit(old_rstate->rot_hw, cmd,
				DPU_HW_ROT_CMD_CLEANUP);
		if (ret)
			DPU_ERROR("failed to cleanup rotator buffers\n");
	}

	if (dpu_plane_enabled(old_state)) {
		if (old_rstate->out_fb) {
			msm_framebuffer_cleanup(old_rstate->out_fb,
					old_pstate->aspace);
			dpu_crtc_res_put(cstate, DPU_CRTC_RES_ROT_OUT_FB,
					(u64) &old_rstate->rot_hw->base);
			old_rstate->out_fb = NULL;
			dpu_crtc_res_put(cstate, DPU_CRTC_RES_ROT_OUT_FBO,
					(u64) &old_rstate->rot_hw->base);
			old_rstate->out_fbo = NULL;
		}

		msm_framebuffer_cleanup(old_state->fb, old_pstate->aspace);
	}
}

/**
 * dpu_plane_rot_atomic_check - verify rotator update of the given state
 * @plane: Pointer to drm plane
 * @state: Pointer to drm plane state to be validated
 * return: 0 if success; error code otherwise
 */
static int dpu_plane_rot_atomic_check(struct drm_plane *plane,
		struct drm_plane_state *state)
{
	struct dpu_plane *pdpu;
	struct dpu_plane_state *pstate, *old_pstate;
	struct dpu_plane_rot_state *rstate, *old_rstate;
	struct drm_crtc_state *cstate;
	struct dpu_hw_blk *hw_blk;
	int i, ret = 0;

	if (!plane || !state) {
		DPU_ERROR("invalid plane/state\n");
		return -EINVAL;
	}

	pdpu = to_dpu_plane(plane);
	pstate = to_dpu_plane_state(state);
	old_pstate = to_dpu_plane_state(plane->state);
	rstate = &pstate->rot;
	old_rstate = &old_pstate->rot;

	/* cstate will be null if crtc is disconnected from plane */
	cstate = _dpu_plane_get_crtc_state(state);
	if (IS_ERR(cstate)) {
		ret = PTR_ERR(cstate);
		DPU_ERROR("invalid crtc state %d\n", ret);
		return ret;
	}

	DPU_DEBUG("plane%d.%d FB[%u] sbuf:%d rot:%d crtc:%d\n", plane->base.id,
			rstate->sequence_id, state->fb ? state->fb->base.id : 0,
			!!rstate->out_sbuf, !!rstate->rot_hw,
			dpu_plane_crtc_enabled(state));

	rstate->in_rotation = drm_rotation_simplify(
			dpu_plane_get_property(pstate, PLANE_PROP_ROTATION),
			DRM_MODE_ROTATE_0 | DRM_MODE_ROTATE_90 |
			DRM_MODE_REFLECT_X | DRM_MODE_REFLECT_Y);
	rstate->rot90 = rstate->in_rotation & DRM_MODE_ROTATE_90 ? true : false;
	rstate->hflip = rstate->in_rotation & DRM_MODE_REFLECT_X ? true : false;
	rstate->vflip = rstate->in_rotation & DRM_MODE_REFLECT_Y ? true : false;
	rstate->out_sbuf = pdpu->sbuf_mode || rstate->rot90;

	if (dpu_plane_enabled(state) && rstate->out_sbuf) {
		DPU_DEBUG("plane%d.%d acquire rotator, fb %d\n",
				plane->base.id, rstate->sequence_id,
				state->fb ? state->fb->base.id : -1);

		hw_blk = dpu_crtc_res_get(cstate, DPU_HW_BLK_ROT,
				(u64) state->fb);
		if (!hw_blk) {
			DPU_ERROR("plane%d.%d no available rotator, fb %d\n",
					plane->base.id, rstate->sequence_id,
					state->fb ? state->fb->base.id : -1);
			DPU_EVT32(DRMID(plane), rstate->sequence_id,
					DPU_EVTLOG_ERROR);
			return -EINVAL;
		}

		rstate->rot_hw = to_dpu_hw_rot(hw_blk);

		if (!rstate->rot_hw->ops.commit) {
			DPU_ERROR("plane%d.%d invalid rotator ops\n",
					plane->base.id, rstate->sequence_id);
			dpu_crtc_res_put(cstate,
					DPU_HW_BLK_ROT, (u64) state->fb);
			rstate->rot_hw = NULL;
			return -EINVAL;
		}

		rstate->in_fb = state->fb;
	} else {
		rstate->in_fb = NULL;
		rstate->rot_hw = NULL;
	}

	if (dpu_plane_enabled(state) && rstate->out_sbuf && rstate->rot_hw) {
		uint32_t fb_id;

		fb_id = state->fb ? state->fb->base.id : -1;
		DPU_DEBUG("plane%d.%d use rotator, fb %d\n",
				plane->base.id, rstate->sequence_id, fb_id);

		ret = dpu_plane_rot_calc_cfg(plane, state);
		if (ret)
			return ret;

		ret = dpu_plane_rot_submit_command(plane, state,
				DPU_HW_ROT_CMD_VALIDATE);
		if (ret)
			return ret;

		if (rstate->nplane != old_rstate->nplane ||
				rstate->out_xpos != old_rstate->out_xpos)
			pstate->dirty |= DPU_PLANE_DIRTY_FORMAT |
				DPU_PLANE_DIRTY_RECTS;

		/* check if stream buffer is already attached to rotator */
		_dpu_plane_rot_get_fb(plane, cstate, rstate);

		/* release buffer if output format configuration changes */
		if (rstate->out_fb &&
			((rstate->out_fb_height != rstate->out_fb->height) ||
			(rstate->out_fb_width != rstate->out_fb->width) ||
			(rstate->out_fb_pixel_format !=
					rstate->out_fb->format->format) ||
			(rstate->out_fb_modifier[0] !=
					rstate->out_fb->modifier) ||
			(rstate->out_fb_flags != rstate->out_fb->flags))) {

			DPU_DEBUG("plane%d.%d release fb/fbo\n", plane->base.id,
					rstate->sequence_id);
			DPU_EVT32_VERBOSE(DRMID(plane),
					rstate->sequence_id, fb_id);

			dpu_crtc_res_put(cstate, DPU_CRTC_RES_ROT_OUT_FB,
					(u64) &rstate->rot_hw->base);
			rstate->out_fb = NULL;
			dpu_crtc_res_put(cstate, DPU_CRTC_RES_ROT_OUT_FBO,
					(u64) &rstate->rot_hw->base);
			rstate->out_fbo = NULL;
		}
	} else {

		DPU_DEBUG("plane%d.%d bypass rotator\n", plane->base.id,
				rstate->sequence_id);

		/* bypass rotator - initialize output setting as input */
		for (i = 0; i < ARRAY_SIZE(rstate->out_fb_modifier); i++)
			rstate->out_fb_modifier[i] = state->fb ?
				state->fb->modifier : 0x0;

		if (state->fb) {
			rstate->out_fb_pixel_format = state->fb->format->format;
			rstate->out_fb_flags = state->fb->flags;
			rstate->out_fb_width = state->fb->width;
			rstate->out_fb_height = state->fb->height;
		} else {
			rstate->out_fb_pixel_format = 0x0;
			rstate->out_fb_flags = 0x0;
			rstate->out_fb_width = 0;
			rstate->out_fb_height = 0;
		}

		rstate->out_rotation = rstate->in_rotation;
		rstate->out_src_x = state->src_x;
		rstate->out_src_y = state->src_y;
		rstate->out_src_w = state->src_w;
		rstate->out_src_h = state->src_h;

		rstate->out_fb_format = NULL;
		rstate->out_sbuf = false;
		rstate->out_fb = state->fb;
	}

	return ret;
}

/**
 * dpu_plane_rot_atomic_update - perform atomic update for rotator stage
 * @plane: Pointer to drm plane
 * @old_state: Pointer to previous state
 * return: none
 */
static void dpu_plane_rot_atomic_update(struct drm_plane *plane,
				struct drm_plane_state *old_state)
{
	struct drm_plane_state *state;
	struct dpu_plane_state *pstate;
	struct dpu_plane_rot_state *rstate;
	int ret = 0;

	if (!plane || !plane->state) {
		DPU_ERROR("invalid plane/state\n");
		return;
	}

	state = plane->state;
	pstate = to_dpu_plane_state(state);
	rstate = &pstate->rot;

	DPU_DEBUG("plane%d.%d sbuf:%d rot:%d crtc:%d\n", plane->base.id,
			rstate->sequence_id,
			!!rstate->out_sbuf, !!rstate->rot_hw,
			dpu_plane_crtc_enabled(plane->state));

	if (!dpu_plane_crtc_enabled(state))
		return;

	if (!rstate->out_sbuf || !rstate->rot_hw)
		return;

	/*
	 * framebuffer prepare is deferred for prepare_fb calls that
	 * happen during the transition from secure to non-secure.
	 * Handle the prepare at this point for rotator in such cases.
	 * This can be expected for one or two frames during the transition.
	 */
	if (pstate->aspace && pstate->defer_prepare_fb) {
		/* prepare rotator input buffer */
		ret = msm_framebuffer_prepare(state->fb, pstate->aspace);
		if (ret) {
			DPU_ERROR("p%d failed to prepare input fb %d\n",
							plane->base.id, ret);
			return;
		}

		/* prepare rotator output buffer */
		if (dpu_plane_enabled(state) && rstate->out_fb) {
			ret = msm_framebuffer_prepare(rstate->out_fb,
						pstate->aspace);
			if (ret) {
				DPU_ERROR(
				  "p%d failed to prepare inline fb %d\n",
				  plane->base.id, ret);
				goto error_prepare_output_buffer;
			}
		}
	}

	dpu_plane_rot_submit_command(plane, state, DPU_HW_ROT_CMD_COMMIT);

	return;

error_prepare_output_buffer:
	msm_framebuffer_cleanup(state->fb, pstate->aspace);
}

void dpu_plane_kickoff(struct drm_plane *plane)
{
	struct dpu_plane_state *pstate;

	if (!plane || !plane->state) {
		DPU_ERROR("invalid plane\n");
		return;
	}

	pstate = to_dpu_plane_state(plane->state);

	if (!pstate->rot.rot_hw || !pstate->rot.rot_hw->ops.commit)
		return;

	pstate->rot.rot_hw->ops.commit(pstate->rot.rot_hw,
			&pstate->rot.rot_cmd,
			DPU_HW_ROT_CMD_START);
}

/**
 * dpu_plane_rot_destroy_state - destroy state for rotator stage
 * @plane: Pointer to drm plane
 * @state: Pointer to state to be destroyed
 * return: none
 */
static void dpu_plane_rot_destroy_state(struct drm_plane *plane,
		struct drm_plane_state *state)
{
	struct dpu_plane_state *pstate = to_dpu_plane_state(state);
	struct dpu_plane_rot_state *rstate = &pstate->rot;

	DPU_DEBUG("plane%d.%d sbuf:%d rot:%d crtc:%d\n", plane->base.id,
			rstate->sequence_id,
			!!rstate->out_sbuf, !!rstate->rot_hw,
			dpu_plane_crtc_enabled(state));
}

/**
 * dpu_plane_rot_duplicate_state - duplicate state for rotator stage
 * @plane: Pointer to drm plane
 * @new_state: Pointer to duplicated state
 * return: 0 if success; error code otherwise
 */
static int dpu_plane_rot_duplicate_state(struct drm_plane *plane,
		struct drm_plane_state *new_state)
{
	struct dpu_plane_state *pstate  = to_dpu_plane_state(new_state);
	struct dpu_plane_rot_state *rstate = &pstate->rot;

	rstate->sequence_id++;

	DPU_DEBUG("plane%d.%d sbuf:%d rot:%d\n", plane->base.id,
			rstate->sequence_id,
			!!rstate->out_sbuf, !!rstate->rot_hw);

	rstate->rot_hw = NULL;
	rstate->out_fb = NULL;
	rstate->out_fbo = NULL;

	return 0;
}

/**
 * dpu_plane_rot_install_caps - install plane rotator capabilities
 * @plane: Pointer to drm plane
 * return: none
 */
static void dpu_plane_rot_install_caps(struct drm_plane *plane)
{
	struct dpu_plane *pdpu = to_dpu_plane(plane);
	const struct dpu_format_extended *format_list;
	struct dpu_kms_info *info;
	struct dpu_hw_rot *rot_hw;
	const char *downscale_caps;

	if (!pdpu->catalog || !(pdpu->features & BIT(DPU_SSPP_SBUF)) ||
			!pdpu->catalog->rot_count)
		return;

	if (pdpu->blob_rot_caps)
		return;

	info = kzalloc(sizeof(struct dpu_kms_info), GFP_KERNEL);
	if (!info)
		return;

	rot_hw = dpu_hw_rot_get(NULL);
	if (!rot_hw || !rot_hw->ops.get_format_caps ||
			!rot_hw->ops.get_downscale_caps) {
		DPU_ERROR("invalid rotator hw\n");
		goto error_rot;
	}

	dpu_kms_info_reset(info);

	format_list = rot_hw->ops.get_format_caps(rot_hw);
	if (format_list) {
		dpu_kms_info_start(info, "pixel_formats");
		while (format_list->fourcc_format) {
			dpu_kms_info_append_format(info,
					format_list->fourcc_format,
					format_list->modifier);
			++format_list;
		}
		dpu_kms_info_stop(info);
	}

	downscale_caps = rot_hw->ops.get_downscale_caps(rot_hw);
	if (downscale_caps) {
		dpu_kms_info_start(info, "downscale_ratios");
		dpu_kms_info_append(info, downscale_caps);
		dpu_kms_info_stop(info);
	}

	if (rot_hw->ops.get_cache_size)
		dpu_kms_info_add_keyint(info, "cache_size",
				rot_hw->ops.get_cache_size(rot_hw));

	if (rot_hw->ops.get_maxlinewidth)
		dpu_kms_info_add_keyint(info, "max_linewidth",
				rot_hw->ops.get_maxlinewidth(rot_hw));

	msm_property_set_blob(&pdpu->property_info, &pdpu->blob_rot_caps,
			info->data, DPU_KMS_INFO_DATALEN(info),
			PLANE_PROP_ROT_CAPS_V1);

	dpu_hw_rot_put(rot_hw);
error_rot:
	kfree(info);
}

/**
 * dpu_plane_rot_install_properties - install plane rotator properties
 * @plane: Pointer to drm plane
 * @catalog: Pointer to mdss configuration
 * return: none
 */
static void dpu_plane_rot_install_properties(struct drm_plane *plane,
	struct dpu_mdss_cfg *catalog)
{
	struct dpu_plane *pdpu = to_dpu_plane(plane);
	unsigned long supported_rotations = DRM_MODE_ROTATE_0 |
			DRM_MODE_REFLECT_X | DRM_MODE_REFLECT_Y;

	if (!plane || !pdpu) {
		DPU_ERROR("invalid plane\n");
		return;
	} else if (!catalog) {
		DPU_ERROR("invalid catalog\n");
		return;
	}

	if ((pdpu->features & BIT(DPU_SSPP_SBUF)) && catalog->rot_count)
		supported_rotations |= DRM_MODE_ROTATE_0 | DRM_MODE_ROTATE_90 |
				DRM_MODE_ROTATE_180 | DRM_MODE_ROTATE_270;

	msm_property_install_rotation(&pdpu->property_info, plane,
			DRM_MODE_ROTATE_0, supported_rotations,
			PLANE_PROP_ROTATION);

	if (!(pdpu->features & BIT(DPU_SSPP_SBUF)) || !catalog->rot_count)
		return;

	msm_property_install_range(&pdpu->property_info, "rot_dst_x",
			0, 0, U64_MAX, 0, PLANE_PROP_ROT_DST_X);
	msm_property_install_range(&pdpu->property_info, "rot_dst_y",
			0, 0, U64_MAX, 0, PLANE_PROP_ROT_DST_Y);
	msm_property_install_range(&pdpu->property_info, "rot_dst_w",
			0, 0, U64_MAX, 0, PLANE_PROP_ROT_DST_W);
	msm_property_install_range(&pdpu->property_info, "rot_dst_h",
			0, 0, U64_MAX, 0, PLANE_PROP_ROT_DST_H);
	msm_property_install_blob(&pdpu->property_info, "rot_caps_v1",
		DRM_MODE_PROP_IMMUTABLE, PLANE_PROP_ROT_CAPS_V1);
}

void dpu_plane_clear_multirect(const struct drm_plane_state *drm_state)
{
	struct dpu_plane_state *pstate;

	if (!drm_state)
		return;

	pstate = to_dpu_plane_state(drm_state);

	pstate->multirect_index = DPU_SSPP_RECT_SOLO;
	pstate->multirect_mode = DPU_SSPP_MULTIRECT_NONE;
}

int dpu_plane_validate_multirect_v2(struct dpu_multirect_plane_states *plane)
{
	struct dpu_plane_state *pstate[R_MAX];
	const struct drm_plane_state *drm_state[R_MAX];
	struct dpu_rect src[R_MAX], dst[R_MAX];
	struct dpu_plane *dpu_plane[R_MAX];
	const struct dpu_format *fmt[R_MAX];
	bool q16_data = true;
	int i, buffer_lines;
	unsigned int max_tile_height = 1;
	bool parallel_fetch_qualified = true;
	bool has_tiled_rect = false;

	for (i = 0; i < R_MAX; i++) {
		const struct msm_format *msm_fmt;

		drm_state[i] = i ? plane->r1 : plane->r0;
		msm_fmt = msm_framebuffer_format(drm_state[i]->fb);
		fmt[i] = to_dpu_format(msm_fmt);

		if (DPU_FORMAT_IS_UBWC(fmt[i])) {
			has_tiled_rect = true;
			if (fmt[i]->tile_height > max_tile_height)
				max_tile_height = fmt[i]->tile_height;
		}
	}

	for (i = 0; i < R_MAX; i++) {
		int width_threshold;

		pstate[i] = to_dpu_plane_state(drm_state[i]);
		dpu_plane[i] = to_dpu_plane(drm_state[i]->plane);

		if (pstate[i] == NULL) {
			DPU_ERROR("DPU plane state of plane id %d is NULL\n",
				drm_state[i]->plane->base.id);
			return -EINVAL;
		}

		POPULATE_RECT(&src[i], drm_state[i]->src_x, drm_state[i]->src_y,
			drm_state[i]->src_w, drm_state[i]->src_h, q16_data);
		POPULATE_RECT(&dst[i], drm_state[i]->crtc_x,
				drm_state[i]->crtc_y, drm_state[i]->crtc_w,
				drm_state[i]->crtc_h, !q16_data);

		if (src[i].w != dst[i].w || src[i].h != dst[i].h) {
			DPU_ERROR_PLANE(dpu_plane[i],
				"scaling is not supported in multirect mode\n");
			return -EINVAL;
		}

		if (DPU_FORMAT_IS_YUV(fmt[i])) {
			DPU_ERROR_PLANE(dpu_plane[i],
				"Unsupported format for multirect mode\n");
			return -EINVAL;
		}

		/**
		 * SSPP PD_MEM is split half - one for each RECT.
		 * Tiled formats need 5 lines of buffering while fetching
		 * whereas linear formats need only 2 lines.
		 * So we cannot support more than half of the supported SSPP
		 * width for tiled formats.
		 */
		width_threshold = dpu_plane[i]->pipe_sblk->maxlinewidth;
		if (has_tiled_rect)
			width_threshold /= 2;

		if (parallel_fetch_qualified && src[i].w > width_threshold)
			parallel_fetch_qualified = false;

	}

	/* Validate RECT's and set the mode */

	/* Prefer PARALLEL FETCH Mode over TIME_MX Mode */
	if (parallel_fetch_qualified) {
		pstate[R0]->multirect_mode = DPU_SSPP_MULTIRECT_PARALLEL;
		pstate[R1]->multirect_mode = DPU_SSPP_MULTIRECT_PARALLEL;

		goto done;
	}

	/* TIME_MX Mode */
	buffer_lines = 2 * max_tile_height;

	if ((dst[R1].y >= dst[R0].y + dst[R0].h + buffer_lines) ||
		(dst[R0].y >= dst[R1].y + dst[R1].h + buffer_lines)) {
		pstate[R0]->multirect_mode = DPU_SSPP_MULTIRECT_TIME_MX;
		pstate[R1]->multirect_mode = DPU_SSPP_MULTIRECT_TIME_MX;
	} else {
		DPU_ERROR(
			"No multirect mode possible for the planes (%d - %d)\n",
			drm_state[R0]->plane->base.id,
			drm_state[R1]->plane->base.id);
		return -EINVAL;
	}

done:
	if (dpu_plane[R0]->is_virtual) {
		pstate[R0]->multirect_index = DPU_SSPP_RECT_1;
		pstate[R1]->multirect_index = DPU_SSPP_RECT_0;
	} else {
		pstate[R0]->multirect_index = DPU_SSPP_RECT_0;
		pstate[R1]->multirect_index = DPU_SSPP_RECT_1;
	};

	DPU_DEBUG_PLANE(dpu_plane[R0], "R0: %d - %d\n",
		pstate[R0]->multirect_mode, pstate[R0]->multirect_index);
	DPU_DEBUG_PLANE(dpu_plane[R1], "R1: %d - %d\n",
		pstate[R1]->multirect_mode, pstate[R1]->multirect_index);
	return 0;
}

/**
 * dpu_plane_get_ctl_flush - get control flush for the given plane
 * @plane: Pointer to drm plane structure
 * @ctl: Pointer to hardware control driver
 * @flush_sspp: Pointer to sspp flush control word
 * @flush_rot: Pointer to rotator flush control word
 */
void dpu_plane_get_ctl_flush(struct drm_plane *plane, struct dpu_hw_ctl *ctl,
		u32 *flush_sspp, u32 *flush_rot)
{
	struct dpu_plane_state *pstate;
	struct dpu_plane_rot_state *rstate;

	if (!plane || !flush_sspp) {
		DPU_ERROR("invalid parameters\n");
		return;
	}

	pstate = to_dpu_plane_state(plane->state);
	rstate = &pstate->rot;

	*flush_sspp = ctl->ops.get_bitmask_sspp(ctl, dpu_plane_pipe(plane));

	if (!flush_rot)
		return;

	*flush_rot = 0x0;
	if (rstate && rstate->out_sbuf && rstate->rot_hw &&
			ctl->ops.get_bitmask_rot)
		ctl->ops.get_bitmask_rot(ctl, flush_rot, rstate->rot_hw->idx);
}

static int dpu_plane_prepare_fb(struct drm_plane *plane,
		struct drm_plane_state *new_state)
{
	struct drm_framebuffer *fb = new_state->fb;
	struct dpu_plane *pdpu = to_dpu_plane(plane);
	struct dpu_plane_state *pstate = to_dpu_plane_state(new_state);
	struct dpu_plane_rot_state *new_rstate;
	struct dpu_hw_fmt_layout layout;
	struct msm_gem_address_space *aspace;
	int ret;

	if (!new_state->fb)
		return 0;

	DPU_DEBUG_PLANE(pdpu, "FB[%u]\n", fb->base.id);

	ret = _dpu_plane_get_aspace(pdpu, pstate, &aspace);
	if (ret) {
		DPU_ERROR_PLANE(pdpu, "Failed to get aspace\n");
		return ret;
	}

	/* cache aspace */
	pstate->aspace = aspace;

	/*
	 * when transitioning from secure to non-secure,
	 * plane->prepare_fb happens before the commit. In such case,
	 * defer the prepare_fb and handled it late, during the commit
	 * after attaching the domains as part of the transition
	 */
	pstate->defer_prepare_fb = false;

	ret = dpu_plane_rot_prepare_fb(plane, new_state);
	if (ret) {
		DPU_ERROR("failed to prepare rot framebuffer\n");
		return ret;
	}

	if (pstate->defer_prepare_fb) {
		DPU_DEBUG_PLANE(pdpu,
		    "domain not attached, prepare_fb handled later\n");
		return 0;
	}

	new_rstate = &to_dpu_plane_state(new_state)->rot;

	if (pstate->aspace) {
		ret = msm_framebuffer_prepare(new_rstate->out_fb,
				pstate->aspace);
		if (ret) {
			DPU_ERROR("failed to prepare framebuffer\n");
			return ret;
		}
	}

	/* validate framebuffer layout before commit */
	ret = dpu_format_populate_layout(pstate->aspace,
			new_rstate->out_fb, &layout);
	if (ret) {
		DPU_ERROR_PLANE(pdpu, "failed to get format layout, %d\n", ret);
		return ret;
	}

	return 0;
}

static void dpu_plane_cleanup_fb(struct drm_plane *plane,
		struct drm_plane_state *old_state)
{
	struct dpu_plane *pdpu = to_dpu_plane(plane);
	struct dpu_plane_state *old_pstate;
	struct dpu_plane_rot_state *old_rstate;

	if (!old_state || !old_state->fb)
		return;

	old_pstate = to_dpu_plane_state(old_state);

	DPU_DEBUG_PLANE(pdpu, "FB[%u]\n", old_state->fb->base.id);

	old_rstate = &old_pstate->rot;

	msm_framebuffer_cleanup(old_rstate->out_fb, old_pstate->aspace);

	dpu_plane_rot_cleanup_fb(plane, old_state);
}

static void _dpu_plane_sspp_atomic_check_mode_changed(struct dpu_plane *pdpu,
		struct drm_plane_state *state,
		struct drm_plane_state *old_state)
{
	struct dpu_plane_state *pstate = to_dpu_plane_state(state);
	struct dpu_plane_state *old_pstate = to_dpu_plane_state(old_state);
	struct dpu_plane_rot_state *rstate = &pstate->rot;
	struct dpu_plane_rot_state *old_rstate = &old_pstate->rot;
	struct drm_framebuffer *fb, *old_fb;

	/* no need to check it again */
	if (pstate->dirty == DPU_PLANE_DIRTY_ALL)
		return;

	if (!dpu_plane_enabled(state) || !dpu_plane_enabled(old_state)
			|| pdpu->is_error) {
		DPU_DEBUG_PLANE(pdpu,
			"enabling/disabling full modeset required\n");
		pstate->dirty |= DPU_PLANE_DIRTY_ALL;
	} else if (to_dpu_plane_state(old_state)->pending) {
		DPU_DEBUG_PLANE(pdpu, "still pending\n");
		pstate->dirty |= DPU_PLANE_DIRTY_ALL;
	} else if (pstate->multirect_index != old_pstate->multirect_index ||
			pstate->multirect_mode != old_pstate->multirect_mode) {
		DPU_DEBUG_PLANE(pdpu, "multirect config updated\n");
		pstate->dirty |= DPU_PLANE_DIRTY_ALL;
	} else if (rstate->out_src_w != old_rstate->out_src_w ||
		   rstate->out_src_h != old_rstate->out_src_h ||
		   rstate->out_src_x != old_rstate->out_src_x ||
		   rstate->out_src_y != old_rstate->out_src_y) {
		DPU_DEBUG_PLANE(pdpu, "src rect updated\n");
		pstate->dirty |= DPU_PLANE_DIRTY_RECTS;
	} else if (state->crtc_w != old_state->crtc_w ||
		   state->crtc_h != old_state->crtc_h ||
		   state->crtc_x != old_state->crtc_x ||
		   state->crtc_y != old_state->crtc_y) {
		DPU_DEBUG_PLANE(pdpu, "crtc rect updated\n");
		pstate->dirty |= DPU_PLANE_DIRTY_RECTS;
	} else if (pstate->excl_rect.w != old_pstate->excl_rect.w ||
		   pstate->excl_rect.h != old_pstate->excl_rect.h ||
		   pstate->excl_rect.x != old_pstate->excl_rect.x ||
		   pstate->excl_rect.y != old_pstate->excl_rect.y) {
		DPU_DEBUG_PLANE(pdpu, "excl_rect updated\n");
		pstate->dirty |= DPU_PLANE_DIRTY_RECTS;
	}

	fb = rstate->out_fb;
	old_fb = old_rstate->out_fb;

	if (!fb || !old_fb) {
		DPU_DEBUG_PLANE(pdpu, "can't compare fb handles\n");
	} else if (fb->format->format != old_fb->format->format) {
		DPU_DEBUG_PLANE(pdpu, "format change\n");
		pstate->dirty |= DPU_PLANE_DIRTY_FORMAT | DPU_PLANE_DIRTY_RECTS;
	} else {
		uint64_t new_mod = fb->modifier;
		uint64_t old_mod = old_fb->modifier;
		uint32_t *new_pitches = fb->pitches;
		uint32_t *old_pitches = old_fb->pitches;
		uint32_t *new_offset = fb->offsets;
		uint32_t *old_offset = old_fb->offsets;
		int i;

		if (new_mod != old_mod) {
			DPU_DEBUG_PLANE(pdpu,
				"format modifiers change\"\
				new_mode:%llu old_mode:%llu\n",
				new_mod, old_mod);
			pstate->dirty |= DPU_PLANE_DIRTY_FORMAT |
				DPU_PLANE_DIRTY_RECTS;
		}

		for (i = 0; i < ARRAY_SIZE(fb->pitches); i++) {
			if (new_pitches[i] != old_pitches[i]) {
				DPU_DEBUG_PLANE(pdpu,
					"pitches change plane:%d\"\
					old_pitches:%u new_pitches:%u\n",
					i, old_pitches[i], new_pitches[i]);
				pstate->dirty |= DPU_PLANE_DIRTY_RECTS;
				break;
			}
		}
		for (i = 0; i < ARRAY_SIZE(fb->offsets); i++) {
			if (new_offset[i] != old_offset[i]) {
				DPU_DEBUG_PLANE(pdpu,
					"offset change plane:%d\"\
					old_offset:%u new_offset:%u\n",
					i, old_offset[i], new_offset[i]);
				pstate->dirty |= DPU_PLANE_DIRTY_FORMAT |
					DPU_PLANE_DIRTY_RECTS;
				break;
			}
		}
	}
}

static int _dpu_plane_validate_scaler_v2(struct dpu_plane *pdpu,
		struct dpu_plane_state *pstate,
		const struct dpu_format *fmt,
		uint32_t img_w, uint32_t img_h,
		uint32_t src_w, uint32_t src_h,
		uint32_t deci_w, uint32_t deci_h)
{
	int i;

	if (!pdpu || !pstate || !fmt) {
		DPU_ERROR_PLANE(pdpu, "invalid arguments\n");
		return -EINVAL;
	}

	/* don't run checks unless scaler data was changed */
	if (pstate->scaler_check_state != DPU_PLANE_SCLCHECK_SCALER_V2_CHECK)
		return 0;

	pstate->scaler_check_state = DPU_PLANE_SCLCHECK_INVALID;

	for (i = 0; i < DPU_MAX_PLANES; i++) {
		uint32_t hor_req_pixels, hor_fetch_pixels;
		uint32_t vert_req_pixels, vert_fetch_pixels;
		uint32_t src_w_tmp, src_h_tmp;

		/* re-use color plane 1's config for plane 2 */
		if (i == 2)
			continue;

		src_w_tmp = src_w;
		src_h_tmp = src_h;

		/*
		 * For chroma plane, width is half for the following sub sampled
		 * formats. Except in case of decimation, where hardware avoids
		 * 1 line of decimation instead of downsampling.
		 */
		if (i == 1) {
			if (!deci_w &&
					(fmt->chroma_sample == DPU_CHROMA_420 ||
					 fmt->chroma_sample == DPU_CHROMA_H2V1))
				src_w_tmp >>= 1;
			if (!deci_h &&
					(fmt->chroma_sample == DPU_CHROMA_420 ||
					 fmt->chroma_sample == DPU_CHROMA_H1V2))
				src_h_tmp >>= 1;
		}

		hor_req_pixels = pstate->pixel_ext.roi_w[i];
		vert_req_pixels = pstate->pixel_ext.roi_h[i];

		hor_fetch_pixels = DECIMATED_DIMENSION(src_w_tmp +
			(int8_t)(pstate->pixel_ext.left_ftch[i] & 0xFF) +
			(int8_t)(pstate->pixel_ext.right_ftch[i] & 0xFF),
			deci_w);
		vert_fetch_pixels = DECIMATED_DIMENSION(src_h_tmp +
			(int8_t)(pstate->pixel_ext.top_ftch[i] & 0xFF) +
			(int8_t)(pstate->pixel_ext.btm_ftch[i] & 0xFF),
			deci_h);

		if ((hor_req_pixels != hor_fetch_pixels) ||
			(hor_fetch_pixels > img_w) ||
			(vert_req_pixels != vert_fetch_pixels) ||
			(vert_fetch_pixels > img_h)) {
			DPU_ERROR_PLANE(pdpu,
					"req %d/%d, fetch %d/%d, src %dx%d\n",
					hor_req_pixels, vert_req_pixels,
					hor_fetch_pixels, vert_fetch_pixels,
					img_w, img_h);
			return -EINVAL;
		}

		/*
		 * Alpha plane can only be scaled using bilinear or pixel
		 * repeat/drop, src_width and src_height are only specified
		 * for Y and UV plane
		 */
		if (i != 3 &&
			(hor_req_pixels != pstate->scaler3_cfg.src_width[i] ||
			vert_req_pixels != pstate->scaler3_cfg.src_height[i])) {
			DPU_ERROR_PLANE(pdpu,
				"roi[%d] %d/%d, scaler src %dx%d, src %dx%d\n",
				i, pstate->pixel_ext.roi_w[i],
				pstate->pixel_ext.roi_h[i],
				pstate->scaler3_cfg.src_width[i],
				pstate->scaler3_cfg.src_height[i],
				src_w, src_h);
			return -EINVAL;
		}
	}

	pstate->scaler_check_state = DPU_PLANE_SCLCHECK_SCALER_V2;
	return 0;
}

static int dpu_plane_sspp_atomic_check(struct drm_plane *plane,
		struct drm_plane_state *state)
{
	int ret = 0;
	struct dpu_plane *pdpu;
	struct dpu_plane_state *pstate;
	struct dpu_plane_rot_state *rstate;
	const struct dpu_format *fmt;
	struct dpu_rect src, dst;
	uint32_t deci_w, deci_h, src_deci_w, src_deci_h;
	uint32_t max_upscale, max_downscale, min_src_size, max_linewidth;
	bool q16_data = true;

	if (!plane || !state) {
		DPU_ERROR("invalid arg(s), plane %d state %d\n",
				plane != 0, state != 0);
		ret = -EINVAL;
		goto exit;
	}

	pdpu = to_dpu_plane(plane);
	pstate = to_dpu_plane_state(state);
	rstate = &pstate->rot;

	if (!pdpu->pipe_sblk) {
		DPU_ERROR_PLANE(pdpu, "invalid catalog\n");
		ret = -EINVAL;
		goto exit;
	}

	deci_w = dpu_plane_get_property(pstate, PLANE_PROP_H_DECIMATE);
	deci_h = dpu_plane_get_property(pstate, PLANE_PROP_V_DECIMATE);

	/* src values are in Q16 fixed point, convert to integer */
	POPULATE_RECT(&src, rstate->out_src_x, rstate->out_src_y,
			rstate->out_src_w, rstate->out_src_h, q16_data);
	POPULATE_RECT(&dst, state->crtc_x, state->crtc_y, state->crtc_w,
		state->crtc_h, !q16_data);

	src_deci_w = DECIMATED_DIMENSION(src.w, deci_w);
	src_deci_h = DECIMATED_DIMENSION(src.h, deci_h);

	max_upscale = pdpu->pipe_sblk->maxupscale;
	max_downscale = pdpu->pipe_sblk->maxdwnscale;
	max_linewidth = pdpu->pipe_sblk->maxlinewidth;

	DPU_DEBUG_PLANE(pdpu, "check %d -> %d\n",
		dpu_plane_enabled(plane->state), dpu_plane_enabled(state));

	if (!dpu_plane_enabled(state))
		goto modeset_update;

	DPU_DEBUG(
		"plane%d.%u sspp:%x/%dx%d/%4.4s/%llx/%dx%d+%d+%d crtc:%dx%d+%d+%d\n",
			plane->base.id, rstate->sequence_id,
			rstate->out_rotation,
			rstate->out_fb_width, rstate->out_fb_height,
			(char *) &rstate->out_fb_pixel_format,
			rstate->out_fb_modifier[0],
			rstate->out_src_w >> 16, rstate->out_src_h >> 16,
			rstate->out_src_x >> 16, rstate->out_src_y >> 16,
			state->crtc_w, state->crtc_h,
			state->crtc_x, state->crtc_y);

	fmt = to_dpu_format(msm_framebuffer_format(state->fb));

	min_src_size = DPU_FORMAT_IS_YUV(fmt) ? 2 : 1;

	if (DPU_FORMAT_IS_YUV(fmt) &&
		(!(pdpu->features & DPU_SSPP_SCALER) ||
		 !(pdpu->features & (BIT(DPU_SSPP_CSC)
		 | BIT(DPU_SSPP_CSC_10BIT))))) {
		DPU_ERROR_PLANE(pdpu,
				"plane doesn't have scaler/csc for yuv\n");
		ret = -EINVAL;

	/* check src bounds */
	} else if (rstate->out_fb_width > MAX_IMG_WIDTH ||
		rstate->out_fb_height > MAX_IMG_HEIGHT ||
		src.w < min_src_size || src.h < min_src_size ||
		CHECK_LAYER_BOUNDS(src.x, src.w, rstate->out_fb_width) ||
		CHECK_LAYER_BOUNDS(src.y, src.h, rstate->out_fb_height)) {
		DPU_ERROR_PLANE(pdpu, "invalid source %u, %u, %ux%u\n",
			src.x, src.y, src.w, src.h);
		ret = -E2BIG;

	/* valid yuv image */
	} else if (DPU_FORMAT_IS_YUV(fmt) && ((src.x & 0x1) || (src.y & 0x1) ||
			 (src.w & 0x1) || (src.h & 0x1))) {
		DPU_ERROR_PLANE(pdpu, "invalid yuv source %u, %u, %ux%u\n",
				src.x, src.y, src.w, src.h);
		ret = -EINVAL;

	/* min dst support */
	} else if (dst.w < 0x1 || dst.h < 0x1) {
		DPU_ERROR_PLANE(pdpu, "invalid dest rect %u, %u, %ux%u\n",
				dst.x, dst.y, dst.w, dst.h);
		ret = -EINVAL;

	/* decimation validation */
	} else if (deci_w || deci_h) {
		if ((deci_w > pdpu->pipe_sblk->maxhdeciexp) ||
			(deci_h > pdpu->pipe_sblk->maxvdeciexp)) {
			DPU_ERROR_PLANE(pdpu,
					"too much decimation requested\n");
			ret = -EINVAL;
		} else if (fmt->fetch_mode != DPU_FETCH_LINEAR) {
			DPU_ERROR_PLANE(pdpu,
					"decimation requires linear fetch\n");
			ret = -EINVAL;
		}

	} else if (!(pdpu->features & DPU_SSPP_SCALER) &&
		((src.w != dst.w) || (src.h != dst.h))) {
		DPU_ERROR_PLANE(pdpu,
			"pipe doesn't support scaling %ux%u->%ux%u\n",
			src.w, src.h, dst.w, dst.h);
		ret = -EINVAL;

	/* check decimated source width */
	} else if (src_deci_w > max_linewidth) {
		DPU_ERROR_PLANE(pdpu,
				"invalid src w:%u, deci w:%u, line w:%u\n",
				src.w, src_deci_w, max_linewidth);
		ret = -E2BIG;

	/* check max scaler capability */
	} else if (((src_deci_w * max_upscale) < dst.w) ||
		((src_deci_h * max_upscale) < dst.h) ||
		((dst.w * max_downscale) < src_deci_w) ||
		((dst.h * max_downscale) < src_deci_h)) {
		DPU_ERROR_PLANE(pdpu,
			"too much scaling requested %ux%u->%ux%u\n",
			src_deci_w, src_deci_h, dst.w, dst.h);
		ret = -E2BIG;
	} else if (_dpu_plane_validate_scaler_v2(pdpu, pstate, fmt,
				rstate->out_fb_width,
				rstate->out_fb_height,
				src.w, src.h, deci_w, deci_h)) {
		ret = -EINVAL;
	}

	/* check excl rect configs */
	if (!ret && pstate->excl_rect.w && pstate->excl_rect.h) {
		struct dpu_rect intersect;

		/*
		 * Check exclusion rect against src rect.
		 * it must intersect with source rect.
		 */
		dpu_kms_rect_intersect(&src, &pstate->excl_rect, &intersect);
		if (intersect.w != pstate->excl_rect.w ||
				intersect.h != pstate->excl_rect.h ||
				DPU_FORMAT_IS_YUV(fmt)) {
			DPU_ERROR_PLANE(pdpu,
				"invalid excl_rect:{%d,%d,%d,%d} src:{%d,%d,%d,%d}, fmt: %4.4s\n",
				pstate->excl_rect.x, pstate->excl_rect.y,
				pstate->excl_rect.w, pstate->excl_rect.h,
				src.x, src.y, src.w, src.h,
				(char *)&fmt->base.pixel_format);
			ret = -EINVAL;
		}
		DPU_DEBUG_PLANE(pdpu, "excl_rect: {%d,%d,%d,%d}\n",
				pstate->excl_rect.x, pstate->excl_rect.y,
				pstate->excl_rect.w, pstate->excl_rect.h);
	}

modeset_update:
	if (!ret)
		_dpu_plane_sspp_atomic_check_mode_changed(pdpu,
				state, plane->state);
exit:
	return ret;
}

static int dpu_plane_atomic_check(struct drm_plane *plane,
		struct drm_plane_state *state)
{
	int ret = 0;
	struct dpu_plane *pdpu;
	struct dpu_plane_state *pstate;

	if (!plane || !state) {
		DPU_ERROR("invalid arg(s), plane %d state %d\n",
				plane != 0, state != 0);
		ret = -EINVAL;
		goto exit;
	}

	pdpu = to_dpu_plane(plane);
	pstate = to_dpu_plane_state(state);

	DPU_DEBUG_PLANE(pdpu, "\n");

	ret = dpu_plane_rot_atomic_check(plane, state);
	if (ret)
		goto exit;

	ret = dpu_plane_sspp_atomic_check(plane, state);

exit:
	return ret;
}

void dpu_plane_flush(struct drm_plane *plane)
{
	struct dpu_plane *pdpu;
	struct dpu_plane_state *pstate;

	if (!plane || !plane->state) {
		DPU_ERROR("invalid plane\n");
		return;
	}

	pdpu = to_dpu_plane(plane);
	pstate = to_dpu_plane_state(plane->state);

	/*
	 * These updates have to be done immediately before the plane flush
	 * timing, and may not be moved to the atomic_update/mode_set functions.
	 */
	if (pdpu->is_error)
		/* force white frame with 100% alpha pipe output on error */
		_dpu_plane_color_fill(pdpu, 0xFFFFFF, 0xFF);
	else if (pdpu->color_fill & DPU_PLANE_COLOR_FILL_FLAG)
		/* force 100% alpha */
		_dpu_plane_color_fill(pdpu, pdpu->color_fill, 0xFF);
	else if (pdpu->pipe_hw && pdpu->csc_ptr && pdpu->pipe_hw->ops.setup_csc)
		pdpu->pipe_hw->ops.setup_csc(pdpu->pipe_hw, pdpu->csc_ptr);

	/* force black color fill during suspend */
	if (dpu_kms_is_suspend_state(plane->dev) && suspend_blank)
		_dpu_plane_color_fill(pdpu, 0x0, 0x0);

	/* flag h/w flush complete */
	if (plane->state)
		pstate->pending = false;
}

/**
 * dpu_plane_set_error: enable/disable error condition
 * @plane: pointer to drm_plane structure
 */
void dpu_plane_set_error(struct drm_plane *plane, bool error)
{
	struct dpu_plane *pdpu;

	if (!plane)
		return;

	pdpu = to_dpu_plane(plane);
	pdpu->is_error = error;
}

static int dpu_plane_sspp_atomic_update(struct drm_plane *plane,
				struct drm_plane_state *old_state)
{
	uint32_t nplanes, src_flags;
	struct dpu_plane *pdpu;
	struct drm_plane_state *state;
	struct dpu_plane_state *pstate;
	struct dpu_plane_state *old_pstate;
	struct dpu_plane_rot_state *rstate;
	const struct dpu_format *fmt;
	struct drm_crtc *crtc;
	struct drm_framebuffer *fb;
	struct dpu_rect src, dst;
	const struct dpu_rect *crtc_roi;
	bool q16_data = true;
	int idx;

	if (!plane) {
		DPU_ERROR("invalid plane\n");
		return -EINVAL;
	} else if (!plane->state) {
		DPU_ERROR("invalid plane state\n");
		return -EINVAL;
	} else if (!old_state) {
		DPU_ERROR("invalid old state\n");
		return -EINVAL;
	}

	pdpu = to_dpu_plane(plane);
	state = plane->state;

	pstate = to_dpu_plane_state(state);
	rstate = &pstate->rot;

	old_pstate = to_dpu_plane_state(old_state);

	crtc = state->crtc;
	fb = rstate->out_fb;
	if (!crtc || !fb) {
		DPU_ERROR_PLANE(pdpu, "invalid crtc %d or fb %d\n",
				crtc != 0, fb != 0);
		return -EINVAL;
	}
	fmt = to_dpu_format(msm_framebuffer_format(fb));
	nplanes = fmt->num_planes;

	DPU_DEBUG(
		"plane%d.%d sspp:%dx%d/%4.4s/%llx/%dx%d+%d+%d/%x crtc:%dx%d+%d+%d\n",
			plane->base.id, rstate->sequence_id,
			rstate->out_fb_width, rstate->out_fb_height,
			(char *) &rstate->out_fb_pixel_format,
			rstate->out_fb_modifier[0],
			rstate->out_src_w >> 16, rstate->out_src_h >> 16,
			rstate->out_src_x >> 16, rstate->out_src_y >> 16,
			rstate->out_rotation,
			state->crtc_w, state->crtc_h,
			state->crtc_x, state->crtc_y);

	/* force reprogramming of all the parameters, if the flag is set */
	if (pdpu->revalidate) {
		DPU_DEBUG("plane:%d - reconfigure all the parameters\n",
				plane->base.id);
		pstate->dirty = DPU_PLANE_DIRTY_ALL;
		pdpu->revalidate = false;
	}

	/* determine what needs to be refreshed */
	while ((idx = msm_property_pop_dirty(&pdpu->property_info,
					&pstate->property_state)) >= 0) {
		switch (idx) {
		case PLANE_PROP_SCALER_V1:
		case PLANE_PROP_SCALER_V2:
		case PLANE_PROP_SCALER_LUT_ED:
		case PLANE_PROP_SCALER_LUT_CIR:
		case PLANE_PROP_SCALER_LUT_SEP:
		case PLANE_PROP_H_DECIMATE:
		case PLANE_PROP_V_DECIMATE:
		case PLANE_PROP_SRC_CONFIG:
		case PLANE_PROP_ZPOS:
		case PLANE_PROP_EXCL_RECT_V1:
			pstate->dirty |= DPU_PLANE_DIRTY_RECTS;
			break;
		case PLANE_PROP_CSC_V1:
			pstate->dirty |= DPU_PLANE_DIRTY_FORMAT;
			break;
		case PLANE_PROP_COLOR_FILL:
			/* potentially need to refresh everything */
			pstate->dirty = DPU_PLANE_DIRTY_ALL;
			break;
		case PLANE_PROP_ROTATION:
			pstate->dirty |= DPU_PLANE_DIRTY_FORMAT;
			break;
		case PLANE_PROP_INFO:
		case PLANE_PROP_ALPHA:
		case PLANE_PROP_INPUT_FENCE:
		case PLANE_PROP_BLEND_OP:
			/* no special action required */
			break;
		case PLANE_PROP_FB_TRANSLATION_MODE:
			pstate->dirty |= DPU_PLANE_DIRTY_FB_TRANSLATION_MODE;
			break;
		case PLANE_PROP_PREFILL_SIZE:
		case PLANE_PROP_PREFILL_TIME:
			pstate->dirty |= DPU_PLANE_DIRTY_PERF;
			break;
		case PLANE_PROP_ROT_DST_X:
		case PLANE_PROP_ROT_DST_Y:
		case PLANE_PROP_ROT_DST_W:
		case PLANE_PROP_ROT_DST_H:
			/* handled by rotator atomic update */
			break;
		default:
			/* unknown property, refresh everything */
			pstate->dirty |= DPU_PLANE_DIRTY_ALL;
			DPU_ERROR("executing full mode set, prp_idx %d\n", idx);
			break;
		}
	}

	/**
	 * since plane_atomic_check is invoked before crtc_atomic_check
	 * in the commit sequence, all the parameters for updating the
	 * plane dirty flag will not be available during
	 * plane_atomic_check as some features params are updated
	 * in crtc_atomic_check (eg.:sDMA). So check for mode_change
	 * before sspp update.
	 */
	_dpu_plane_sspp_atomic_check_mode_changed(pdpu, state,
								old_state);

	/* re-program the output rects always in the case of partial update */
	dpu_crtc_get_crtc_roi(crtc->state, &crtc_roi);
	if (!dpu_kms_rect_is_null(crtc_roi))
		pstate->dirty |= DPU_PLANE_DIRTY_RECTS;

	if (pstate->dirty & DPU_PLANE_DIRTY_RECTS)
		memset(&(pdpu->pipe_cfg), 0, sizeof(struct dpu_hw_pipe_cfg));

	_dpu_plane_set_scanout(plane, pstate, &pdpu->pipe_cfg, fb);

	/* early out if nothing dirty */
	if (!pstate->dirty)
		return 0;
	pstate->pending = true;

	pdpu->is_rt_pipe = (dpu_crtc_get_client_type(crtc) != NRT_CLIENT);
	_dpu_plane_set_qos_ctrl(plane, false, DPU_PLANE_QOS_PANIC_CTRL);

	/* update secure session flag */
	if (pstate->dirty & DPU_PLANE_DIRTY_FB_TRANSLATION_MODE) {
		bool enable = false;
		int mode = dpu_plane_get_property(pstate,
				PLANE_PROP_FB_TRANSLATION_MODE);

		if ((mode == DPU_DRM_FB_SEC) ||
				(mode == DPU_DRM_FB_SEC_DIR_TRANS))
			enable = true;
		/* update secure session flag */
		pdpu->pipe_hw->ops.setup_secure_address(pdpu->pipe_hw,
				pstate->multirect_index,
				enable);
	}

	/* update roi config */
	if (pstate->dirty & DPU_PLANE_DIRTY_RECTS) {
		POPULATE_RECT(&src, rstate->out_src_x, rstate->out_src_y,
			rstate->out_src_w, rstate->out_src_h, q16_data);
		POPULATE_RECT(&dst, state->crtc_x, state->crtc_y,
			state->crtc_w, state->crtc_h, !q16_data);

		DPU_DEBUG_PLANE(pdpu,
			"FB[%u] %u,%u,%ux%u->crtc%u %d,%d,%ux%u, %4.4s ubwc %d\n",
				fb->base.id, src.x, src.y, src.w, src.h,
				crtc->base.id, dst.x, dst.y, dst.w, dst.h,
				(char *)&fmt->base.pixel_format,
				DPU_FORMAT_IS_UBWC(fmt));

		if (dpu_plane_get_property(pstate, PLANE_PROP_SRC_CONFIG) &
			BIT(DPU_DRM_DEINTERLACE)) {
			DPU_DEBUG_PLANE(pdpu, "deinterlace\n");
			for (idx = 0; idx < DPU_MAX_PLANES; ++idx)
				pdpu->pipe_cfg.layout.plane_pitch[idx] <<= 1;
			src.h /= 2;
			src.y  = DIV_ROUND_UP(src.y, 2);
			src.y &= ~0x1;
		}

		/*
		 * adjust layer mixer position of the sspp in the presence
		 * of a partial update to the active lm origin
		 */
		dst.x -= crtc_roi->x;
		dst.y -= crtc_roi->y;

		pdpu->pipe_cfg.src_rect = src;
		pdpu->pipe_cfg.dst_rect = dst;

		_dpu_plane_setup_scaler(pdpu, pstate, fmt, false);

		/* check for color fill */
		pdpu->color_fill = (uint32_t)dpu_plane_get_property(pstate,
				PLANE_PROP_COLOR_FILL);
		if (pdpu->color_fill & DPU_PLANE_COLOR_FILL_FLAG) {
			/* skip remaining processing on color fill */
			pstate->dirty = 0x0;
		} else if (pdpu->pipe_hw->ops.setup_rects) {
			pdpu->pipe_hw->ops.setup_rects(pdpu->pipe_hw,
					&pdpu->pipe_cfg,
					pstate->multirect_index);
		}

		if (pdpu->pipe_hw->ops.setup_pe &&
				(pstate->multirect_index != DPU_SSPP_RECT_1))
			pdpu->pipe_hw->ops.setup_pe(pdpu->pipe_hw,
					&pstate->pixel_ext);

		/**
		 * when programmed in multirect mode, scalar block will be
		 * bypassed. Still we need to update alpha and bitwidth
		 * ONLY for RECT0
		 */
		if (pdpu->pipe_hw->ops.setup_scaler &&
				pstate->multirect_index != DPU_SSPP_RECT_1)
			pdpu->pipe_hw->ops.setup_scaler(pdpu->pipe_hw,
					&pdpu->pipe_cfg, &pstate->pixel_ext,
					&pstate->scaler3_cfg);

		/* update excl rect */
		if (pdpu->pipe_hw->ops.setup_excl_rect)
			pdpu->pipe_hw->ops.setup_excl_rect(pdpu->pipe_hw,
					&pstate->excl_rect,
					pstate->multirect_index);

		if (pdpu->pipe_hw->ops.setup_multirect)
			pdpu->pipe_hw->ops.setup_multirect(
					pdpu->pipe_hw,
					pstate->multirect_index,
					pstate->multirect_mode);
	}

	if ((pstate->dirty & DPU_PLANE_DIRTY_FORMAT) &&
			pdpu->pipe_hw->ops.setup_format) {
		src_flags = 0x0;
		DPU_DEBUG_PLANE(pdpu, "rotation 0x%X\n", rstate->out_rotation);
		if (rstate->out_rotation & DRM_MODE_REFLECT_X)
			src_flags |= DPU_SSPP_FLIP_LR;
		if (rstate->out_rotation & DRM_MODE_REFLECT_Y)
			src_flags |= DPU_SSPP_FLIP_UD;

		/* update format */
		pdpu->pipe_hw->ops.setup_format(pdpu->pipe_hw, fmt, src_flags,
				pstate->multirect_index);

		if (pdpu->pipe_hw->ops.setup_cdp) {
			struct dpu_hw_pipe_cdp_cfg *cdp_cfg = &pstate->cdp_cfg;

			memset(cdp_cfg, 0, sizeof(struct dpu_hw_pipe_cdp_cfg));

			cdp_cfg->enable = pdpu->catalog->perf.cdp_cfg
					[DPU_PERF_CDP_USAGE_RT].rd_enable;
			cdp_cfg->ubwc_meta_enable =
					DPU_FORMAT_IS_UBWC(fmt);
			cdp_cfg->tile_amortize_enable =
					DPU_FORMAT_IS_UBWC(fmt) ||
					DPU_FORMAT_IS_TILE(fmt);
			cdp_cfg->preload_ahead = DPU_WB_CDP_PRELOAD_AHEAD_64;

			pdpu->pipe_hw->ops.setup_cdp(pdpu->pipe_hw, cdp_cfg);
		}

		if (pdpu->pipe_hw->ops.setup_sys_cache) {
			if (rstate->out_sbuf && rstate->rot_hw) {
				if (rstate->nplane < 2)
					pstate->sc_cfg.op_mode =
					DPU_PIPE_SC_OP_MODE_INLINE_SINGLE;
				else if (rstate->out_xpos == 0)
					pstate->sc_cfg.op_mode =
						DPU_PIPE_SC_OP_MODE_INLINE_LEFT;
				else
					pstate->sc_cfg.op_mode =
					DPU_PIPE_SC_OP_MODE_INLINE_RIGHT;

				pstate->sc_cfg.rd_en = true;
				pstate->sc_cfg.rd_scid =
						rstate->rot_hw->caps->scid;
				pstate->sc_cfg.rd_noallocate = true;
				pstate->sc_cfg.rd_op_type =
					DPU_PIPE_SC_RD_OP_TYPE_CACHEABLE;
			} else {
				pstate->sc_cfg.op_mode =
						DPU_PIPE_SC_OP_MODE_OFFLINE;
				pstate->sc_cfg.rd_en = false;
				pstate->sc_cfg.rd_scid = 0;
				pstate->sc_cfg.rd_noallocate = true;
				pstate->sc_cfg.rd_op_type =
					DPU_PIPE_SC_RD_OP_TYPE_CACHEABLE;
			}

			pdpu->pipe_hw->ops.setup_sys_cache(
					pdpu->pipe_hw, &pstate->sc_cfg);
		}

		/* update csc */
		if (DPU_FORMAT_IS_YUV(fmt))
			_dpu_plane_setup_csc(pdpu);
		else
			pdpu->csc_ptr = 0;
	}

	dpu_color_process_plane_setup(plane);

	/* update sharpening */
	if ((pstate->dirty & DPU_PLANE_DIRTY_SHARPEN) &&
		pdpu->pipe_hw->ops.setup_sharpening) {
		pdpu->sharp_cfg.strength = SHARP_STRENGTH_DEFAULT;
		pdpu->sharp_cfg.edge_thr = SHARP_EDGE_THR_DEFAULT;
		pdpu->sharp_cfg.smooth_thr = SHARP_SMOOTH_THR_DEFAULT;
		pdpu->sharp_cfg.noise_thr = SHARP_NOISE_THR_DEFAULT;

		pdpu->pipe_hw->ops.setup_sharpening(pdpu->pipe_hw,
				&pdpu->sharp_cfg);
	}

	_dpu_plane_set_qos_lut(plane, fb);
	_dpu_plane_set_danger_lut(plane, fb);

	if (plane->type != DRM_PLANE_TYPE_CURSOR) {
		_dpu_plane_set_qos_ctrl(plane, true, DPU_PLANE_QOS_PANIC_CTRL);
		_dpu_plane_set_ot_limit(plane, crtc);
		if (pstate->dirty & DPU_PLANE_DIRTY_PERF)
			_dpu_plane_set_ts_prefill(plane, pstate);
	}

	_dpu_plane_set_qos_remap(plane);

	/* clear dirty */
	pstate->dirty = 0x0;

	return 0;
}

static void _dpu_plane_atomic_disable(struct drm_plane *plane,
				struct drm_plane_state *old_state)
{
	struct dpu_plane *pdpu;
	struct drm_plane_state *state;
	struct dpu_plane_state *pstate;

	if (!plane) {
		DPU_ERROR("invalid plane\n");
		return;
	} else if (!plane->state) {
		DPU_ERROR("invalid plane state\n");
		return;
	} else if (!old_state) {
		DPU_ERROR("invalid old state\n");
		return;
	}

	pdpu = to_dpu_plane(plane);
	state = plane->state;
	pstate = to_dpu_plane_state(state);

	DPU_EVT32(DRMID(plane), is_dpu_plane_virtual(plane),
			pstate->multirect_mode);

	pstate->pending = true;

	if (is_dpu_plane_virtual(plane) &&
			pdpu->pipe_hw && pdpu->pipe_hw->ops.setup_multirect)
		pdpu->pipe_hw->ops.setup_multirect(pdpu->pipe_hw,
				DPU_SSPP_RECT_SOLO, DPU_SSPP_MULTIRECT_NONE);
}

static void dpu_plane_atomic_update(struct drm_plane *plane,
				struct drm_plane_state *old_state)
{
	struct dpu_plane *pdpu;
	struct drm_plane_state *state;

	if (!plane) {
		DPU_ERROR("invalid plane\n");
		return;
	} else if (!plane->state) {
		DPU_ERROR("invalid plane state\n");
		return;
	}

	pdpu = to_dpu_plane(plane);
	pdpu->is_error = false;
	state = plane->state;

	DPU_DEBUG_PLANE(pdpu, "\n");

	dpu_plane_rot_atomic_update(plane, old_state);

	if (!dpu_plane_sspp_enabled(state)) {
		_dpu_plane_atomic_disable(plane, old_state);
	} else {
		int ret;

		ret = dpu_plane_sspp_atomic_update(plane, old_state);
		/* atomic_check should have ensured that this doesn't fail */
		WARN_ON(ret < 0);
	}
}

void dpu_plane_restore(struct drm_plane *plane)
{
	struct dpu_plane *pdpu;

	if (!plane || !plane->state) {
		DPU_ERROR("invalid plane\n");
		return;
	}

	pdpu = to_dpu_plane(plane);

	/*
	 * Revalidate is only true here if idle PC occurred and
	 * there is no plane state update in current commit cycle.
	 */
	if (!pdpu->revalidate)
		return;

	DPU_DEBUG_PLANE(pdpu, "\n");

	/* last plane state is same as current state */
	dpu_plane_atomic_update(plane, plane->state);
}

/* helper to install properties which are common to planes and crtcs */
static void _dpu_plane_install_properties(struct drm_plane *plane,
	struct dpu_mdss_cfg *catalog, u32 master_plane_id)
{
	static const struct drm_prop_enum_list e_blend_op[] = {
		{DPU_DRM_BLEND_OP_NOT_DEFINED,    "not_defined"},
		{DPU_DRM_BLEND_OP_OPAQUE,         "opaque"},
		{DPU_DRM_BLEND_OP_PREMULTIPLIED,  "premultiplied"},
		{DPU_DRM_BLEND_OP_COVERAGE,       "coverage"}
	};
	static const struct drm_prop_enum_list e_src_config[] = {
		{DPU_DRM_DEINTERLACE, "deinterlace"}
	};
	static const struct drm_prop_enum_list e_fb_translation_mode[] = {
		{DPU_DRM_FB_NON_SEC, "non_sec"},
		{DPU_DRM_FB_SEC, "sec"},
		{DPU_DRM_FB_NON_SEC_DIR_TRANS, "non_sec_direct_translation"},
		{DPU_DRM_FB_SEC_DIR_TRANS, "sec_direct_translation"},
	};
	const struct dpu_format_extended *format_list;
	struct dpu_kms_info *info;
	struct dpu_plane *pdpu = to_dpu_plane(plane);
	int zpos_max = 255;
	int zpos_def = 0;
	char feature_name[256];

	if (!plane || !pdpu) {
		DPU_ERROR("invalid plane\n");
		return;
	} else if (!pdpu->pipe_hw || !pdpu->pipe_sblk) {
		DPU_ERROR("invalid plane, pipe_hw %d pipe_sblk %d\n",
				pdpu->pipe_hw != 0, pdpu->pipe_sblk != 0);
		return;
	} else if (!catalog) {
		DPU_ERROR("invalid catalog\n");
		return;
	}

	pdpu->catalog = catalog;

	if (dpu_is_custom_client()) {
		if (catalog->mixer_count &&
				catalog->mixer[0].sblk->maxblendstages) {
			zpos_max = catalog->mixer[0].sblk->maxblendstages - 1;
			if (zpos_max > DPU_STAGE_MAX - DPU_STAGE_0 - 1)
				zpos_max = DPU_STAGE_MAX - DPU_STAGE_0 - 1;
		}
	} else if (plane->type != DRM_PLANE_TYPE_PRIMARY) {
		/* reserve zpos == 0 for primary planes */
		zpos_def = drm_plane_index(plane) + 1;
	}

	msm_property_install_range(&pdpu->property_info, "zpos",
		0x0, 0, zpos_max, zpos_def, PLANE_PROP_ZPOS);

	msm_property_install_range(&pdpu->property_info, "alpha",
		0x0, 0, 255, 255, PLANE_PROP_ALPHA);

	/* linux default file descriptor range on each process */
	msm_property_install_range(&pdpu->property_info, "input_fence",
		0x0, 0, INR_OPEN_MAX, 0, PLANE_PROP_INPUT_FENCE);

	if (!master_plane_id) {
		if (pdpu->pipe_sblk->maxhdeciexp) {
			msm_property_install_range(&pdpu->property_info,
					"h_decimate", 0x0, 0,
					pdpu->pipe_sblk->maxhdeciexp, 0,
					PLANE_PROP_H_DECIMATE);
		}

		if (pdpu->pipe_sblk->maxvdeciexp) {
			msm_property_install_range(&pdpu->property_info,
					"v_decimate", 0x0, 0,
					pdpu->pipe_sblk->maxvdeciexp, 0,
					PLANE_PROP_V_DECIMATE);
		}

		if (pdpu->features & BIT(DPU_SSPP_SCALER_QSEED3)) {
			msm_property_install_range(
					&pdpu->property_info, "scaler_v2",
					0x0, 0, ~0, 0, PLANE_PROP_SCALER_V2);
			msm_property_install_blob(&pdpu->property_info,
					"lut_ed", 0, PLANE_PROP_SCALER_LUT_ED);
			msm_property_install_blob(&pdpu->property_info,
					"lut_cir", 0,
					PLANE_PROP_SCALER_LUT_CIR);
			msm_property_install_blob(&pdpu->property_info,
					"lut_sep", 0,
					PLANE_PROP_SCALER_LUT_SEP);
		} else if (pdpu->features & DPU_SSPP_SCALER) {
			msm_property_install_range(
					&pdpu->property_info, "scaler_v1", 0x0,
					0, ~0, 0, PLANE_PROP_SCALER_V1);
		}

		if (pdpu->features & BIT(DPU_SSPP_CSC) ||
		    pdpu->features & BIT(DPU_SSPP_CSC_10BIT))
			msm_property_install_volatile_range(
					&pdpu->property_info, "csc_v1", 0x0,
					0, ~0, 0, PLANE_PROP_CSC_V1);

		if (pdpu->features & BIT(DPU_SSPP_HSIC)) {
			snprintf(feature_name, sizeof(feature_name), "%s%d",
				"DPU_SSPP_HUE_V",
				pdpu->pipe_sblk->hsic_blk.version >> 16);
			msm_property_install_range(&pdpu->property_info,
				feature_name, 0, 0, 0xFFFFFFFF, 0,
				PLANE_PROP_HUE_ADJUST);
			snprintf(feature_name, sizeof(feature_name), "%s%d",
				"DPU_SSPP_SATURATION_V",
				pdpu->pipe_sblk->hsic_blk.version >> 16);
			msm_property_install_range(&pdpu->property_info,
				feature_name, 0, 0, 0xFFFFFFFF, 0,
				PLANE_PROP_SATURATION_ADJUST);
			snprintf(feature_name, sizeof(feature_name), "%s%d",
				"DPU_SSPP_VALUE_V",
				pdpu->pipe_sblk->hsic_blk.version >> 16);
			msm_property_install_range(&pdpu->property_info,
				feature_name, 0, 0, 0xFFFFFFFF, 0,
				PLANE_PROP_VALUE_ADJUST);
			snprintf(feature_name, sizeof(feature_name), "%s%d",
				"DPU_SSPP_CONTRAST_V",
				pdpu->pipe_sblk->hsic_blk.version >> 16);
			msm_property_install_range(&pdpu->property_info,
				feature_name, 0, 0, 0xFFFFFFFF, 0,
				PLANE_PROP_CONTRAST_ADJUST);
		}
	}

	if (pdpu->features & BIT(DPU_SSPP_EXCL_RECT))
		msm_property_install_volatile_range(&pdpu->property_info,
			"excl_rect_v1", 0x0, 0, ~0, 0, PLANE_PROP_EXCL_RECT_V1);

	dpu_plane_rot_install_properties(plane, catalog);

	msm_property_install_enum(&pdpu->property_info, "blend_op", 0x0, 0,
		e_blend_op, ARRAY_SIZE(e_blend_op), PLANE_PROP_BLEND_OP);

	msm_property_install_enum(&pdpu->property_info, "src_config", 0x0, 1,
		e_src_config, ARRAY_SIZE(e_src_config), PLANE_PROP_SRC_CONFIG);

	if (pdpu->pipe_hw->ops.setup_solidfill)
		msm_property_install_range(&pdpu->property_info, "color_fill",
				0, 0, 0xFFFFFFFF, 0, PLANE_PROP_COLOR_FILL);

	msm_property_install_range(&pdpu->property_info,
			"prefill_size", 0x0, 0, ~0, 0,
			PLANE_PROP_PREFILL_SIZE);
	msm_property_install_range(&pdpu->property_info,
			"prefill_time", 0x0, 0, ~0, 0,
			PLANE_PROP_PREFILL_TIME);

	info = kzalloc(sizeof(struct dpu_kms_info), GFP_KERNEL);
	if (!info) {
		DPU_ERROR("failed to allocate info memory\n");
		return;
	}

	msm_property_install_blob(&pdpu->property_info, "capabilities",
		DRM_MODE_PROP_IMMUTABLE, PLANE_PROP_INFO);
	dpu_kms_info_reset(info);

	if (!master_plane_id) {
		format_list = pdpu->pipe_sblk->format_list;
	} else {
		format_list = pdpu->pipe_sblk->virt_format_list;
		dpu_kms_info_add_keyint(info, "primary_smart_plane_id",
						master_plane_id);
	}

	if (format_list) {
		dpu_kms_info_start(info, "pixel_formats");
		while (format_list->fourcc_format) {
			dpu_kms_info_append_format(info,
					format_list->fourcc_format,
					format_list->modifier);
			++format_list;
		}
		dpu_kms_info_stop(info);
	}

	if (pdpu->pipe_hw && pdpu->pipe_hw->ops.get_scaler_ver)
		dpu_kms_info_add_keyint(info, "scaler_step_ver",
			pdpu->pipe_hw->ops.get_scaler_ver(pdpu->pipe_hw));

	dpu_kms_info_add_keyint(info, "max_linewidth",
			pdpu->pipe_sblk->maxlinewidth);
	dpu_kms_info_add_keyint(info, "max_upscale",
			pdpu->pipe_sblk->maxupscale);
	dpu_kms_info_add_keyint(info, "max_downscale",
			pdpu->pipe_sblk->maxdwnscale);
	dpu_kms_info_add_keyint(info, "max_horizontal_deci",
			pdpu->pipe_sblk->maxhdeciexp);
	dpu_kms_info_add_keyint(info, "max_vertical_deci",
			pdpu->pipe_sblk->maxvdeciexp);
	dpu_kms_info_add_keyint(info, "max_per_pipe_bw",
			pdpu->pipe_sblk->max_per_pipe_bw * 1000LL);
	msm_property_set_blob(&pdpu->property_info, &pdpu->blob_info,
			info->data, DPU_KMS_INFO_DATALEN(info),
			PLANE_PROP_INFO);

	kfree(info);

	if (pdpu->features & BIT(DPU_SSPP_MEMCOLOR)) {
		snprintf(feature_name, sizeof(feature_name), "%s%d",
			"DPU_SSPP_SKIN_COLOR_V",
			pdpu->pipe_sblk->memcolor_blk.version >> 16);
		msm_property_install_blob(&pdpu->property_info, feature_name, 0,
			PLANE_PROP_SKIN_COLOR);
		snprintf(feature_name, sizeof(feature_name), "%s%d",
			"DPU_SSPP_SKY_COLOR_V",
			pdpu->pipe_sblk->memcolor_blk.version >> 16);
		msm_property_install_blob(&pdpu->property_info, feature_name, 0,
			PLANE_PROP_SKY_COLOR);
		snprintf(feature_name, sizeof(feature_name), "%s%d",
			"DPU_SSPP_FOLIAGE_COLOR_V",
			pdpu->pipe_sblk->memcolor_blk.version >> 16);
		msm_property_install_blob(&pdpu->property_info, feature_name, 0,
			PLANE_PROP_FOLIAGE_COLOR);
	}

	msm_property_install_enum(&pdpu->property_info, "fb_translation_mode",
			0x0,
			0, e_fb_translation_mode,
			ARRAY_SIZE(e_fb_translation_mode),
			PLANE_PROP_FB_TRANSLATION_MODE);
}

static inline void _dpu_plane_set_csc_v1(struct dpu_plane *pdpu, void *usr_ptr)
{
	struct dpu_drm_csc_v1 csc_v1;
	int i;

	if (!pdpu) {
		DPU_ERROR("invalid plane\n");
		return;
	}

	pdpu->csc_usr_ptr = NULL;
	if (!usr_ptr) {
		DPU_DEBUG_PLANE(pdpu, "csc data removed\n");
		return;
	}

	if (copy_from_user(&csc_v1, usr_ptr, sizeof(csc_v1))) {
		DPU_ERROR_PLANE(pdpu, "failed to copy csc data\n");
		return;
	}

	/* populate from user space */
	for (i = 0; i < DPU_CSC_MATRIX_COEFF_SIZE; ++i)
		pdpu->csc_cfg.csc_mv[i] = csc_v1.ctm_coeff[i] >> 16;
	for (i = 0; i < DPU_CSC_BIAS_SIZE; ++i) {
		pdpu->csc_cfg.csc_pre_bv[i] = csc_v1.pre_bias[i];
		pdpu->csc_cfg.csc_post_bv[i] = csc_v1.post_bias[i];
	}
	for (i = 0; i < DPU_CSC_CLAMP_SIZE; ++i) {
		pdpu->csc_cfg.csc_pre_lv[i] = csc_v1.pre_clamp[i];
		pdpu->csc_cfg.csc_post_lv[i] = csc_v1.post_clamp[i];
	}
	pdpu->csc_usr_ptr = &pdpu->csc_cfg;
}

static inline void _dpu_plane_set_scaler_v1(struct dpu_plane *pdpu,
		struct dpu_plane_state *pstate, void *usr)
{
	struct dpu_drm_scaler_v1 scale_v1;
	struct dpu_hw_pixel_ext *pe;
	int i;

	if (!pdpu || !pstate) {
		DPU_ERROR("invalid argument(s)\n");
		return;
	}

	pstate->scaler_check_state = DPU_PLANE_SCLCHECK_NONE;
	if (!usr) {
		DPU_DEBUG_PLANE(pdpu, "scale data removed\n");
		return;
	}

	if (copy_from_user(&scale_v1, usr, sizeof(scale_v1))) {
		DPU_ERROR_PLANE(pdpu, "failed to copy scale data\n");
		return;
	}

	/* force property to be dirty, even if the pointer didn't change */
	msm_property_set_dirty(&pdpu->property_info,
			&pstate->property_state, PLANE_PROP_SCALER_V1);

	/* populate from user space */
	pe = &pstate->pixel_ext;
	memset(pe, 0, sizeof(struct dpu_hw_pixel_ext));
	for (i = 0; i < DPU_MAX_PLANES; i++) {
		pe->init_phase_x[i] = scale_v1.init_phase_x[i];
		pe->phase_step_x[i] = scale_v1.phase_step_x[i];
		pe->init_phase_y[i] = scale_v1.init_phase_y[i];
		pe->phase_step_y[i] = scale_v1.phase_step_y[i];

		pe->horz_filter[i] = scale_v1.horz_filter[i];
		pe->vert_filter[i] = scale_v1.vert_filter[i];
	}
	for (i = 0; i < DPU_MAX_PLANES; i++) {
		pe->left_ftch[i] = scale_v1.pe.left_ftch[i];
		pe->right_ftch[i] = scale_v1.pe.right_ftch[i];
		pe->left_rpt[i] = scale_v1.pe.left_rpt[i];
		pe->right_rpt[i] = scale_v1.pe.right_rpt[i];
		pe->roi_w[i] = scale_v1.pe.num_ext_pxls_lr[i];

		pe->top_ftch[i] = scale_v1.pe.top_ftch[i];
		pe->btm_ftch[i] = scale_v1.pe.btm_ftch[i];
		pe->top_rpt[i] = scale_v1.pe.top_rpt[i];
		pe->btm_rpt[i] = scale_v1.pe.btm_rpt[i];
		pe->roi_h[i] = scale_v1.pe.num_ext_pxls_tb[i];
	}

	pstate->scaler_check_state = DPU_PLANE_SCLCHECK_SCALER_V1;

	DPU_EVT32_VERBOSE(DRMID(&pdpu->base));
	DPU_DEBUG_PLANE(pdpu, "user property data copied\n");
}

static inline void _dpu_plane_set_scaler_v2(struct dpu_plane *pdpu,
		struct dpu_plane_state *pstate, void *usr)
{
	struct dpu_drm_scaler_v2 scale_v2;
	struct dpu_hw_pixel_ext *pe;
	int i;
	struct dpu_hw_scaler3_cfg *cfg;

	if (!pdpu || !pstate) {
		DPU_ERROR("invalid argument(s)\n");
		return;
	}

	cfg = &pstate->scaler3_cfg;
	pstate->scaler_check_state = DPU_PLANE_SCLCHECK_NONE;
	if (!usr) {
		DPU_DEBUG_PLANE(pdpu, "scale data removed\n");
		return;
	}

	if (copy_from_user(&scale_v2, usr, sizeof(scale_v2))) {
		DPU_ERROR_PLANE(pdpu, "failed to copy scale data\n");
		return;
	}

	/* detach/ignore user data if 'disabled' */
	if (!scale_v2.enable) {
		DPU_DEBUG_PLANE(pdpu, "scale data removed\n");
		return;
	}

	/* force property to be dirty, even if the pointer didn't change */
	msm_property_set_dirty(&pdpu->property_info,
			&pstate->property_state, PLANE_PROP_SCALER_V2);

	/* populate from user space */
	dpu_set_scaler_v2(cfg, &scale_v2);

	pe = &pstate->pixel_ext;
	memset(pe, 0, sizeof(struct dpu_hw_pixel_ext));

	for (i = 0; i < DPU_MAX_PLANES; i++) {
		pe->left_ftch[i] = scale_v2.pe.left_ftch[i];
		pe->right_ftch[i] = scale_v2.pe.right_ftch[i];
		pe->left_rpt[i] = scale_v2.pe.left_rpt[i];
		pe->right_rpt[i] = scale_v2.pe.right_rpt[i];
		pe->roi_w[i] = scale_v2.pe.num_ext_pxls_lr[i];

		pe->top_ftch[i] = scale_v2.pe.top_ftch[i];
		pe->btm_ftch[i] = scale_v2.pe.btm_ftch[i];
		pe->top_rpt[i] = scale_v2.pe.top_rpt[i];
		pe->btm_rpt[i] = scale_v2.pe.btm_rpt[i];
		pe->roi_h[i] = scale_v2.pe.num_ext_pxls_tb[i];
	}
	pstate->scaler_check_state = DPU_PLANE_SCLCHECK_SCALER_V2_CHECK;

	DPU_EVT32_VERBOSE(DRMID(&pdpu->base), cfg->enable, cfg->de.enable,
			cfg->src_width[0], cfg->src_height[0],
			cfg->dst_width, cfg->dst_height);
	DPU_DEBUG_PLANE(pdpu, "user property data copied\n");
}

static void _dpu_plane_set_excl_rect_v1(struct dpu_plane *pdpu,
		struct dpu_plane_state *pstate, void *usr_ptr)
{
	struct drm_clip_rect excl_rect_v1;

	if (!pdpu) {
		DPU_ERROR("invalid plane\n");
		return;
	}

	if (!usr_ptr) {
		DPU_DEBUG_PLANE(pdpu, "invalid  excl_rect user data\n");
		return;
	}

	if (copy_from_user(&excl_rect_v1, usr_ptr, sizeof(excl_rect_v1))) {
		DPU_ERROR_PLANE(pdpu, "failed to copy excl_rect data\n");
		return;
	}

	/* populate from user space */
	pstate->excl_rect.x = excl_rect_v1.x1;
	pstate->excl_rect.y = excl_rect_v1.y1;
	pstate->excl_rect.w = excl_rect_v1.x2 - excl_rect_v1.x1;
	pstate->excl_rect.h = excl_rect_v1.y2 - excl_rect_v1.y1;

	DPU_DEBUG_PLANE(pdpu, "excl_rect: {%d,%d,%d,%d}\n",
			pstate->excl_rect.x, pstate->excl_rect.y,
			pstate->excl_rect.w, pstate->excl_rect.h);
}

static int dpu_plane_atomic_set_property(struct drm_plane *plane,
		struct drm_plane_state *state, struct drm_property *property,
		uint64_t val)
{
	struct dpu_plane *pdpu = plane ? to_dpu_plane(plane) : NULL;
	struct dpu_plane_state *pstate;
	int idx, ret = -EINVAL;

	DPU_DEBUG_PLANE(pdpu, "\n");

	if (!plane) {
		DPU_ERROR("invalid plane\n");
	} else if (!state) {
		DPU_ERROR_PLANE(pdpu, "invalid state\n");
	} else {
		pstate = to_dpu_plane_state(state);
		ret = msm_property_atomic_set(&pdpu->property_info,
				&pstate->property_state, property, val);
		if (!ret) {
			idx = msm_property_index(&pdpu->property_info,
					property);
			switch (idx) {
			case PLANE_PROP_INPUT_FENCE:
				_dpu_plane_set_input_fence(pdpu, pstate, val);
				break;
			case PLANE_PROP_CSC_V1:
				_dpu_plane_set_csc_v1(pdpu, (void *)val);
				break;
			case PLANE_PROP_SCALER_V1:
				_dpu_plane_set_scaler_v1(pdpu, pstate,
						(void *)val);
				break;
			case PLANE_PROP_SCALER_V2:
				_dpu_plane_set_scaler_v2(pdpu, pstate,
						(void *)val);
				break;
			case PLANE_PROP_EXCL_RECT_V1:
				_dpu_plane_set_excl_rect_v1(pdpu, pstate,
						(void *)val);
				break;
			default:
				/* nothing to do */
				break;
			}
		}
	}

	DPU_DEBUG_PLANE(pdpu, "%s[%d] <= 0x%llx ret=%d\n",
			property->name, property->base.id, val, ret);

	return ret;
}

static int dpu_plane_set_property(struct drm_plane *plane,
		struct drm_property *property, uint64_t val)
{
	DPU_DEBUG("\n");

	return dpu_plane_atomic_set_property(plane,
			plane->state, property, val);
}

static int dpu_plane_atomic_get_property(struct drm_plane *plane,
		const struct drm_plane_state *state,
		struct drm_property *property, uint64_t *val)
{
	struct dpu_plane *pdpu = plane ? to_dpu_plane(plane) : NULL;
	struct dpu_plane_state *pstate;
	int ret = -EINVAL;

	if (!plane) {
		DPU_ERROR("invalid plane\n");
	} else if (!state) {
		DPU_ERROR("invalid state\n");
	} else {
		DPU_DEBUG_PLANE(pdpu, "\n");
		pstate = to_dpu_plane_state(state);
#ifdef CONFIG_QCOM_DPU_ROT
		dpu_plane_rot_install_caps(plane);
#endif
		ret = msm_property_atomic_get(&pdpu->property_info,
				&pstate->property_state, property, val);
	}

	return ret;
}

static void dpu_plane_destroy(struct drm_plane *plane)
{
	struct dpu_plane *pdpu = plane ? to_dpu_plane(plane) : NULL;

	DPU_DEBUG_PLANE(pdpu, "\n");

	if (pdpu) {
		_dpu_plane_set_qos_ctrl(plane, false, DPU_PLANE_QOS_PANIC_CTRL);

		if (pdpu->blob_info)
			drm_property_blob_put(pdpu->blob_info);
		msm_property_destroy(&pdpu->property_info);
		mutex_destroy(&pdpu->lock);

		drm_plane_helper_disable(plane);

		/* this will destroy the states as well */
		drm_plane_cleanup(plane);

		if (pdpu->pipe_hw)
			dpu_hw_sspp_destroy(pdpu->pipe_hw);

		kfree(pdpu);
	}
}

static void dpu_plane_destroy_state(struct drm_plane *plane,
		struct drm_plane_state *state)
{
	struct dpu_plane *pdpu;
	struct dpu_plane_state *pstate;

	if (!plane || !state) {
		DPU_ERROR("invalid arg(s), plane %d state %d\n",
				plane != 0, state != 0);
		return;
	}

	pdpu = to_dpu_plane(plane);
	pstate = to_dpu_plane_state(state);

	DPU_DEBUG_PLANE(pdpu, "\n");

	dpu_plane_rot_destroy_state(plane, &pstate->base);

	/* remove ref count for frame buffers */
	if (state->fb)
		drm_framebuffer_put(state->fb);

	/* remove ref count for fence */
	if (pstate->input_fence)
		dpu_sync_put(pstate->input_fence);

	/* destroy value helper */
	msm_property_destroy_state(&pdpu->property_info, pstate,
			&pstate->property_state);
}

static struct drm_plane_state *
dpu_plane_duplicate_state(struct drm_plane *plane)
{
	struct dpu_plane *pdpu;
	struct dpu_plane_state *pstate;
	struct dpu_plane_state *old_state;
	struct drm_property *drm_prop;
	uint64_t input_fence_default;

	if (!plane) {
		DPU_ERROR("invalid plane\n");
		return NULL;
	} else if (!plane->state) {
		DPU_ERROR("invalid plane state\n");
		return NULL;
	}

	old_state = to_dpu_plane_state(plane->state);
	pdpu = to_dpu_plane(plane);
	pstate = msm_property_alloc_state(&pdpu->property_info);
	if (!pstate) {
		DPU_ERROR_PLANE(pdpu, "failed to allocate state\n");
		return NULL;
	}

	DPU_DEBUG_PLANE(pdpu, "\n");

	/* duplicate value helper */
	msm_property_duplicate_state(&pdpu->property_info, old_state, pstate,
			&pstate->property_state, pstate->property_values);

	/* clear out any input fence */
	pstate->input_fence = 0;
	input_fence_default = msm_property_get_default(
			&pdpu->property_info, PLANE_PROP_INPUT_FENCE);
	drm_prop = msm_property_index_to_drm_property(
				&pdpu->property_info, PLANE_PROP_INPUT_FENCE);
	if (msm_property_atomic_set(&pdpu->property_info,
				&pstate->property_state, drm_prop,
				input_fence_default))
		DPU_DEBUG_PLANE(pdpu,
				"error clearing duplicated input fence\n");

	pstate->dirty = 0x0;
	pstate->pending = false;

	__drm_atomic_helper_plane_duplicate_state(plane, &pstate->base);

	dpu_plane_rot_duplicate_state(plane, &pstate->base);

	return &pstate->base;
}

static void dpu_plane_reset(struct drm_plane *plane)
{
	struct dpu_plane *pdpu;
	struct dpu_plane_state *pstate;

	if (!plane) {
		DPU_ERROR("invalid plane\n");
		return;
	}

	pdpu = to_dpu_plane(plane);
	DPU_DEBUG_PLANE(pdpu, "\n");

	/* remove previous state, if present */
	if (plane->state) {
		dpu_plane_destroy_state(plane, plane->state);
		plane->state = 0;
	}

	pstate = msm_property_alloc_state(&pdpu->property_info);
	if (!pstate) {
		DPU_ERROR_PLANE(pdpu, "failed to allocate state\n");
		return;
	}

	/* reset value helper */
	msm_property_reset_state(&pdpu->property_info, pstate,
			&pstate->property_state,
			pstate->property_values);

	pstate->base.plane = plane;

	plane->state = &pstate->base;
}

#ifdef CONFIG_DEBUG_FS
static ssize_t _dpu_plane_danger_read(struct file *file,
			char __user *buff, size_t count, loff_t *ppos)
{
	struct dpu_kms *kms = file->private_data;
	struct dpu_mdss_cfg *cfg = kms->catalog;
	int len = 0;
	char buf[40] = {'\0'};

	if (!cfg)
		return -ENODEV;

	if (*ppos)
		return 0; /* the end */

	len = snprintf(buf, sizeof(buf), "%d\n", !kms->has_danger_ctrl);
	if (len < 0 || len >= sizeof(buf))
		return 0;

	if ((count < sizeof(buf)) || copy_to_user(buff, buf, len))
		return -EFAULT;

	*ppos += len;   /* increase offset */

	return len;
}

static void _dpu_plane_set_danger_state(struct dpu_kms *kms, bool enable)
{
	struct drm_plane *plane;

	drm_for_each_plane(plane, kms->dev) {
		if (plane->fb && plane->state) {
			dpu_plane_danger_signal_ctrl(plane, enable);
			DPU_DEBUG("plane:%d img:%dx%d ",
				plane->base.id, plane->fb->width,
				plane->fb->height);
			DPU_DEBUG("src[%d,%d,%d,%d] dst[%d,%d,%d,%d]\n",
				plane->state->src_x >> 16,
				plane->state->src_y >> 16,
				plane->state->src_w >> 16,
				plane->state->src_h >> 16,
				plane->state->crtc_x, plane->state->crtc_y,
				plane->state->crtc_w, plane->state->crtc_h);
		} else {
			DPU_DEBUG("Inactive plane:%d\n", plane->base.id);
		}
	}
}

static ssize_t _dpu_plane_danger_write(struct file *file,
		    const char __user *user_buf, size_t count, loff_t *ppos)
{
	struct dpu_kms *kms = file->private_data;
	struct dpu_mdss_cfg *cfg = kms->catalog;
	int disable_panic;
	char buf[10];

	if (!cfg)
		return -EFAULT;

	if (count >= sizeof(buf))
		return -EFAULT;

	if (copy_from_user(buf, user_buf, count))
		return -EFAULT;

	buf[count] = 0;	/* end of string */

	if (kstrtoint(buf, 0, &disable_panic))
		return -EFAULT;

	if (disable_panic) {
		/* Disable panic signal for all active pipes */
		DPU_DEBUG("Disabling danger:\n");
		_dpu_plane_set_danger_state(kms, false);
		kms->has_danger_ctrl = false;
	} else {
		/* Enable panic signal for all active pipes */
		DPU_DEBUG("Enabling danger:\n");
		kms->has_danger_ctrl = true;
		_dpu_plane_set_danger_state(kms, true);
	}

	return count;
}

static const struct file_operations dpu_plane_danger_enable = {
	.open = simple_open,
	.read = _dpu_plane_danger_read,
	.write = _dpu_plane_danger_write,
};

static int _dpu_plane_init_debugfs(struct drm_plane *plane)
{
	struct dpu_plane *pdpu;
	struct dpu_kms *kms;
	struct msm_drm_private *priv;
	const struct dpu_sspp_sub_blks *sblk = 0;
	const struct dpu_sspp_cfg *cfg = 0;

	if (!plane || !plane->dev) {
		DPU_ERROR("invalid arguments\n");
		return -EINVAL;
	}

	priv = plane->dev->dev_private;
	if (!priv || !priv->kms) {
		DPU_ERROR("invalid KMS reference\n");
		return -EINVAL;
	}

	kms = to_dpu_kms(priv->kms);
	pdpu = to_dpu_plane(plane);

	if (pdpu && pdpu->pipe_hw)
		cfg = pdpu->pipe_hw->cap;
	if (cfg)
		sblk = cfg->sblk;

	if (!sblk)
		return 0;

	/* create overall sub-directory for the pipe */
	pdpu->debugfs_root =
		debugfs_create_dir(pdpu->pipe_name,
				plane->dev->primary->debugfs_root);

	if (!pdpu->debugfs_root)
		return -ENOMEM;

	/* don't error check these */
	debugfs_create_x32("features", 0600,
			pdpu->debugfs_root, &pdpu->features);

	/* add register dump support */
	dpu_debugfs_setup_regset32(&pdpu->debugfs_src,
			sblk->src_blk.base + cfg->base,
			sblk->src_blk.len,
			kms);
	dpu_debugfs_create_regset32("src_blk", 0400,
			pdpu->debugfs_root, &pdpu->debugfs_src);

	if (cfg->features & BIT(DPU_SSPP_SCALER_QSEED3) ||
			cfg->features & BIT(DPU_SSPP_SCALER_QSEED2)) {
		dpu_debugfs_setup_regset32(&pdpu->debugfs_scaler,
				sblk->scaler_blk.base + cfg->base,
				sblk->scaler_blk.len,
				kms);
		dpu_debugfs_create_regset32("scaler_blk", 0400,
				pdpu->debugfs_root,
				&pdpu->debugfs_scaler);
		debugfs_create_bool("default_scaling",
				0600,
				pdpu->debugfs_root,
				&pdpu->debugfs_default_scale);
	}

	if (cfg->features & BIT(DPU_SSPP_CSC) ||
			cfg->features & BIT(DPU_SSPP_CSC_10BIT)) {
		dpu_debugfs_setup_regset32(&pdpu->debugfs_csc,
				sblk->csc_blk.base + cfg->base,
				sblk->csc_blk.len,
				kms);
		dpu_debugfs_create_regset32("csc_blk", 0400,
				pdpu->debugfs_root, &pdpu->debugfs_csc);
	}

	debugfs_create_u32("xin_id",
			0400,
			pdpu->debugfs_root,
			(u32 *) &cfg->xin_id);
	debugfs_create_u32("clk_ctrl",
			0400,
			pdpu->debugfs_root,
			(u32 *) &cfg->clk_ctrl);
	debugfs_create_x32("creq_vblank",
			0600,
			pdpu->debugfs_root,
			(u32 *) &sblk->creq_vblank);
	debugfs_create_x32("danger_vblank",
			0600,
			pdpu->debugfs_root,
			(u32 *) &sblk->danger_vblank);

	debugfs_create_file("disable_danger",
			0600,
			pdpu->debugfs_root,
			kms, &dpu_plane_danger_enable);
	debugfs_create_u32("sbuf_mode",
			0600,
			pdpu->debugfs_root, &pdpu->sbuf_mode);
	debugfs_create_u32("sbuf_writeback",
			0600,
			pdpu->debugfs_root,
			&pdpu->sbuf_writeback);

	return 0;
}

static void _dpu_plane_destroy_debugfs(struct drm_plane *plane)
{
	struct dpu_plane *pdpu;

	if (!plane)
		return;
	pdpu = to_dpu_plane(plane);

	debugfs_remove_recursive(pdpu->debugfs_root);
}
#else
static int _dpu_plane_init_debugfs(struct drm_plane *plane)
{
	return 0;
}
static void _dpu_plane_destroy_debugfs(struct drm_plane *plane)
{
}
#endif

static int dpu_plane_late_register(struct drm_plane *plane)
{
	return _dpu_plane_init_debugfs(plane);
}

static void dpu_plane_early_unregister(struct drm_plane *plane)
{
	_dpu_plane_destroy_debugfs(plane);
}

static const struct drm_plane_funcs dpu_plane_funcs = {
		.update_plane = drm_atomic_helper_update_plane,
		.disable_plane = drm_atomic_helper_disable_plane,
		.destroy = dpu_plane_destroy,
		.atomic_set_property = dpu_plane_atomic_set_property,
		.atomic_get_property = dpu_plane_atomic_get_property,
		.reset = dpu_plane_reset,
		.atomic_duplicate_state = dpu_plane_duplicate_state,
		.atomic_destroy_state = dpu_plane_destroy_state,
		.late_register = dpu_plane_late_register,
		.early_unregister = dpu_plane_early_unregister,
};

static const struct drm_plane_helper_funcs dpu_plane_helper_funcs = {
		.prepare_fb = dpu_plane_prepare_fb,
		.cleanup_fb = dpu_plane_cleanup_fb,
		.atomic_check = dpu_plane_atomic_check,
		.atomic_update = dpu_plane_atomic_update,
};

enum dpu_sspp dpu_plane_pipe(struct drm_plane *plane)
{
	return plane ? to_dpu_plane(plane)->pipe : SSPP_NONE;
}

bool is_dpu_plane_virtual(struct drm_plane *plane)
{
	return plane ? to_dpu_plane(plane)->is_virtual : false;
}

/* initialize plane */
struct drm_plane *dpu_plane_init(struct drm_device *dev,
		uint32_t pipe, bool primary_plane,
		unsigned long possible_crtcs, u32 master_plane_id)
{
	struct drm_plane *plane = NULL, *master_plane = NULL;
	const struct dpu_format_extended *format_list;
	struct dpu_plane *pdpu;
	struct msm_drm_private *priv;
	struct dpu_kms *kms;
	enum drm_plane_type type;
	int ret = -EINVAL;

	if (!dev) {
		DPU_ERROR("[%u]device is NULL\n", pipe);
		goto exit;
	}

	priv = dev->dev_private;
	if (!priv) {
		DPU_ERROR("[%u]private data is NULL\n", pipe);
		goto exit;
	}

	if (!priv->kms) {
		DPU_ERROR("[%u]invalid KMS reference\n", pipe);
		goto exit;
	}
	kms = to_dpu_kms(priv->kms);

	if (!kms->catalog) {
		DPU_ERROR("[%u]invalid catalog reference\n", pipe);
		goto exit;
	}

	/* create and zero local structure */
	pdpu = kzalloc(sizeof(*pdpu), GFP_KERNEL);
	if (!pdpu) {
		DPU_ERROR("[%u]failed to allocate local plane struct\n", pipe);
		ret = -ENOMEM;
		goto exit;
	}

	/* cache local stuff for later */
	plane = &pdpu->base;
	pdpu->pipe = pipe;
	pdpu->is_virtual = (master_plane_id != 0);
	INIT_LIST_HEAD(&pdpu->mplane_list);
	master_plane = drm_plane_find(dev, NULL, master_plane_id);
	if (master_plane) {
		struct dpu_plane *mpdpu = to_dpu_plane(master_plane);

		list_add_tail(&pdpu->mplane_list, &mpdpu->mplane_list);
	}

	/* initialize underlying h/w driver */
	pdpu->pipe_hw = dpu_hw_sspp_init(pipe, kms->mmio, kms->catalog,
							master_plane_id != 0);
	if (IS_ERR(pdpu->pipe_hw)) {
		DPU_ERROR("[%u]SSPP init failed\n", pipe);
		ret = PTR_ERR(pdpu->pipe_hw);
		goto clean_plane;
	} else if (!pdpu->pipe_hw->cap || !pdpu->pipe_hw->cap->sblk) {
		DPU_ERROR("[%u]SSPP init returned invalid cfg\n", pipe);
		goto clean_sspp;
	}

	/* cache features mask for later */
	pdpu->features = pdpu->pipe_hw->cap->features;
	pdpu->pipe_sblk = pdpu->pipe_hw->cap->sblk;
	if (!pdpu->pipe_sblk) {
		DPU_ERROR("[%u]invalid sblk\n", pipe);
		goto clean_sspp;
	}

	if (!master_plane_id)
		format_list = pdpu->pipe_sblk->format_list;
	else
		format_list = pdpu->pipe_sblk->virt_format_list;

	pdpu->nformats = dpu_populate_formats(format_list,
				pdpu->formats,
				0,
				ARRAY_SIZE(pdpu->formats));

	if (!pdpu->nformats) {
		DPU_ERROR("[%u]no valid formats for plane\n", pipe);
		goto clean_sspp;
	}

	if (pdpu->features & BIT(DPU_SSPP_CURSOR))
		type = DRM_PLANE_TYPE_CURSOR;
	else if (primary_plane)
		type = DRM_PLANE_TYPE_PRIMARY;
	else
		type = DRM_PLANE_TYPE_OVERLAY;
	ret = drm_universal_plane_init(dev, plane, 0xff, &dpu_plane_funcs,
				pdpu->formats, pdpu->nformats,
				NULL, type, NULL);
	if (ret)
		goto clean_sspp;

	/* success! finalize initialization */
	drm_plane_helper_add(plane, &dpu_plane_helper_funcs);

	msm_property_init(&pdpu->property_info, &plane->base, dev,
			priv->plane_property, pdpu->property_data,
			PLANE_PROP_COUNT, PLANE_PROP_BLOBCOUNT,
			sizeof(struct dpu_plane_state));

	_dpu_plane_install_properties(plane, kms->catalog, master_plane_id);

	/* save user friendly pipe name for later */
	snprintf(pdpu->pipe_name, DPU_NAME_SIZE, "plane%u", plane->base.id);

	mutex_init(&pdpu->lock);

	DPU_DEBUG("%s created for pipe:%u id:%u virtual:%u\n", pdpu->pipe_name,
					pipe, plane->base.id, master_plane_id);
	return plane;

clean_sspp:
	if (pdpu && pdpu->pipe_hw)
		dpu_hw_sspp_destroy(pdpu->pipe_hw);
clean_plane:
	kfree(pdpu);
exit:
	return ERR_PTR(ret);
}
