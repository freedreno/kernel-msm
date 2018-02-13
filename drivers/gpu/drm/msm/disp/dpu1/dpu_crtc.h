/*
 * Copyright (c) 2015-2018 The Linux Foundation. All rights reserved.
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

#ifndef _DPU_CRTC_H_
#define _DPU_CRTC_H_

#include <linux/kthread.h>
#include <drm/drm_crtc.h>
#include "msm_prop.h"
#include "dpu_fence.h"
#include "dpu_kms.h"
#include "dpu_core_perf.h"
#include "dpu_hw_blk.h"
#include "dpu_hw_ds.h"

#define DPU_CRTC_NAME_SIZE	12

/* define the maximum number of in-flight frame events */
#define DPU_CRTC_FRAME_EVENT_SIZE	4

/**
 * enum dpu_crtc_client_type: crtc client type
 * @RT_CLIENT:	RealTime client like video/cmd mode display
 *              voting through apps rsc
 * @NRT_CLIENT:	Non-RealTime client like WB display
 *              voting through apps rsc
 * @RT_RSC_CLIENT:	Realtime display RSC voting client
 */
enum dpu_crtc_client_type {
	RT_CLIENT,
	NRT_CLIENT,
	RT_RSC_CLIENT,
};

/**
 * enum dpu_crtc_smmu_state:	smmu state
 * @ATTACHED:	 all the context banks are attached.
 * @DETACHED:	 all the context banks are detached.
 * @DETACHED_SEC:	 secure context bank is detached.
 * @ATTACH_ALL_REQ:	 transient state of attaching context banks.
 * @DETACH_ALL_REQ:	 transient state of detaching context banks.
 * @DETACH_SEC_REQ:	 tranisent state of secure context bank is detached
 * @ATTACH_SEC_REQ:	 transient state of attaching secure context bank.
 */
enum dpu_crtc_smmu_state {
	ATTACHED = 0,
	DETACHED,
	DETACHED_SEC,
	ATTACH_ALL_REQ,
	DETACH_ALL_REQ,
	DETACH_SEC_REQ,
	ATTACH_SEC_REQ,
};

/**
 * enum dpu_crtc_smmu_state_transition_type: state transition type
 * @NONE: no pending state transitions
 * @PRE_COMMIT: state transitions should be done before processing the commit
 * @POST_COMMIT: state transitions to be done after processing the commit.
 */
enum dpu_crtc_smmu_state_transition_type {
	NONE,
	PRE_COMMIT,
	POST_COMMIT
};

/**
 * struct dpu_crtc_smmu_state_data: stores the smmu state and transition type
 * @state: current state of smmu context banks
 * @transition_type: transition request type
 * @transition_error: whether there is error while transitioning the state
 */
struct dpu_crtc_smmu_state_data {
	uint32_t state;
	uint32_t transition_type;
	uint32_t transition_error;
};

/**
 * @connectors    : Currently associated drm connectors for retire event
 * @num_connectors: Number of associated drm connectors for retire event
 * @list:	event list
 */
struct dpu_crtc_retire_event {
	struct drm_connector *connectors[MAX_CONNECTORS];
	int num_connectors;
	struct list_head list;
};

/**
 * struct dpu_crtc_mixer: stores the map for each virtual pipeline in the CRTC
 * @hw_lm:	LM HW Driver context
 * @hw_ctl:	CTL Path HW driver context
 * @hw_dspp:	DSPP HW driver context
 * @hw_ds:	DS HW driver context
 * @encoder:	Encoder attached to this lm & ctl
 * @mixer_op_mode:	mixer blending operation mode
 * @flush_mask:	mixer flush mask for ctl, mixer and pipe
 */
struct dpu_crtc_mixer {
	struct dpu_hw_mixer *hw_lm;
	struct dpu_hw_ctl *hw_ctl;
	struct dpu_hw_dspp *hw_dspp;
	struct dpu_hw_ds *hw_ds;
	struct drm_encoder *encoder;
	u32 mixer_op_mode;
	u32 flush_mask;
};

/**
 * struct dpu_crtc_frame_event: stores crtc frame event for crtc processing
 * @work:	base work structure
 * @crtc:	Pointer to crtc handling this event
 * @list:	event list
 * @ts:		timestamp at queue entry
 * @event:	event identifier
 */
struct dpu_crtc_frame_event {
	struct kthread_work work;
	struct drm_crtc *crtc;
	struct list_head list;
	ktime_t ts;
	u32 event;
};

/**
 * struct dpu_crtc_event - event callback tracking structure
 * @list:     Linked list tracking node
 * @kt_work:  Kthread worker structure
 * @dpu_crtc: Pointer to associated dpu_crtc structure
 * @cb_func:  Pointer to callback function
 * @usr:      Pointer to user data to be provided to the callback
 */
struct dpu_crtc_event {
	struct list_head list;
	struct kthread_work kt_work;
	void *dpu_crtc;

	void (*cb_func)(struct drm_crtc *crtc, void *usr);
	void *usr;
};

/*
 * Maximum number of free event structures to cache
 */
#define DPU_CRTC_MAX_EVENT_COUNT	16

/**
 * struct dpu_crtc - virtualized CRTC data structure
 * @base          : Base drm crtc structure
 * @name          : ASCII description of this crtc
 * @num_ctls      : Number of ctl paths in use
 * @num_mixers    : Number of mixers in use
 * @mixers_swapped: Whether the mixers have been swapped for left/right update
 *                  especially in the case of DSC Merge.
 * @mixers        : List of active mixers
 * @event         : Pointer to last received drm vblank event. If there is a
 *                  pending vblank event, this will be non-null.
 * @vsync_count   : Running count of received vsync events
 * @drm_requested_vblank : Whether vblanks have been enabled in the encoder
 * @property_info : Opaque structure for generic property support
 * @property_defaults : Array of default values for generic property support
 * @output_fence  : output release fence context
 * @stage_cfg     : H/w mixer stage configuration
 * @debugfs_root  : Parent of debugfs node
 * @vblank_cb_count : count of vblank callback since last reset
 * @play_count    : frame count between crtc enable and disable
 * @vblank_cb_time  : ktime at vblank count reset
 * @vblank_requested : whether the user has requested vblank events
 * @suspend         : whether or not a suspend operation is in progress
 * @enabled       : whether the DPU CRTC is currently enabled. updated in the
 *                  commit-thread, not state-swap time which is earlier, so
 *                  safe to make decisions on during VBLANK on/off work
 * @feature_list  : list of color processing features supported on a crtc
 * @active_list   : list of color processing features are active
 * @dirty_list    : list of color processing features are dirty
 * @ad_dirty: list containing ad properties that are dirty
 * @ad_active: list containing ad properties that are active
 * @crtc_lock     : crtc lock around create, destroy and access.
 * @frame_pending : Whether or not an update is pending
 * @frame_events  : static allocation of in-flight frame events
 * @frame_event_list : available frame event list
 * @spin_lock     : spin lock for frame event, transaction status, etc...
 * @retire_events  : static allocation of retire fence connector
 * @retire_event_list : available retire fence connector list
 * @frame_done_comp    : for frame_event_done synchronization
 * @event_thread  : Pointer to event handler thread
 * @event_worker  : Event worker queue
 * @event_cache   : Local cache of event worker structures
 * @event_free_list : List of available event structures
 * @event_lock    : Spinlock around event handling code
 * @misr_enable   : boolean entry indicates misr enable/disable status.
 * @misr_frame_count  : misr frame count provided by client
 * @misr_data     : store misr data before turning off the clocks.
 * @sbuf_flush_mask: flush mask for inline rotator
 * @sbuf_flush_mask_old: inline rotator flush mask for previous commit
 * @power_event   : registered power event handle
 * @cur_perf      : current performance committed to clock/bandwidth driver
 * @rp_lock       : serialization lock for resource pool
 * @rp_head       : list of active resource pool
 * @scl3_cfg_lut  : qseed3 lut config
 */
struct dpu_crtc {
	struct drm_crtc base;
	char name[DPU_CRTC_NAME_SIZE];

	/* HW Resources reserved for the crtc */
	u32 num_ctls;
	u32 num_mixers;
	bool mixers_swapped;
	struct dpu_crtc_mixer mixers[CRTC_DUAL_MIXERS];
	struct dpu_hw_scaler3_lut_cfg *scl3_lut_cfg;

	struct drm_pending_vblank_event *event;
	u32 vsync_count;

	struct msm_property_info property_info;
	struct msm_property_data property_data[CRTC_PROP_COUNT];
	struct drm_property_blob *blob_info;

	/* output fence support */
	struct dpu_fence_context output_fence;

	struct dpu_hw_stage_cfg stage_cfg;
	struct dentry *debugfs_root;

	u32 vblank_cb_count;
	u64 play_count;
	ktime_t vblank_cb_time;
	bool vblank_requested;
	bool suspend;
	bool enabled;

	struct list_head feature_list;
	struct list_head active_list;
	struct list_head dirty_list;
	struct list_head ad_dirty;
	struct list_head ad_active;
	struct list_head user_event_list;

	struct mutex crtc_lock;

	atomic_t frame_pending;
	struct dpu_crtc_frame_event frame_events[DPU_CRTC_FRAME_EVENT_SIZE];
	struct list_head frame_event_list;
	spinlock_t spin_lock;
	struct dpu_crtc_retire_event retire_events[DPU_CRTC_FRAME_EVENT_SIZE];
	struct list_head retire_event_list;
	struct completion frame_done_comp;

	/* for handling internal event thread */
	struct dpu_crtc_event event_cache[DPU_CRTC_MAX_EVENT_COUNT];
	struct list_head event_free_list;
	spinlock_t event_lock;
	bool misr_enable;
	u32 misr_frame_count;
	u32 misr_data[CRTC_DUAL_MIXERS];

	u32 sbuf_flush_mask;
	u32 sbuf_flush_mask_old;

	struct dpu_power_event *power_event;

	struct dpu_core_perf_params cur_perf;

	struct mutex rp_lock;
	struct list_head rp_head;

	struct dpu_crtc_smmu_state_data smmu_state;
};

#define to_dpu_crtc(x) container_of(x, struct dpu_crtc, base)

/**
 * struct dpu_crtc_res_ops - common operations for crtc resources
 * @get: get given resource
 * @put: put given resource
 */
struct dpu_crtc_res_ops {
	void *(*get)(void *val, u32 type, u64 tag);
	void (*put)(void *val);
};

/* crtc resource type (0x0-0xffff reserved for hw block type */
#define DPU_CRTC_RES_ROT_OUT_FBO	0x10000
#define DPU_CRTC_RES_ROT_OUT_FB		0x10001
#define DPU_CRTC_RES_ROT_PLANE		0x10002
#define DPU_CRTC_RES_ROT_IN_FB		0x10003

#define DPU_CRTC_RES_FLAG_FREE		BIT(0)

/**
 * struct dpu_crtc_res - definition of crtc resources
 * @list: list of crtc resource
 * @type: crtc resource type
 * @tag: unique identifier per type
 * @refcount: reference/usage count
 * @ops: callback operations
 * @val: resource handle associated with type/tag
 * @flags: customization flags
 */
struct dpu_crtc_res {
	struct list_head list;
	u32 type;
	u64 tag;
	atomic_t refcount;
	struct dpu_crtc_res_ops ops;
	void *val;
	u32 flags;
};

/**
 * dpu_crtc_respool - crtc resource pool
 * @rp_lock: pointer to serialization lock
 * @rp_head: pointer to head of active resource pools of this crtc
 * @rp_list: list of crtc resource pool
 * @sequence_id: sequence identifier, incremented per state duplication
 * @res_list: list of resource managed by this resource pool
 * @ops: resource operations for parent resource pool
 */
struct dpu_crtc_respool {
	struct mutex *rp_lock;
	struct list_head *rp_head;
	struct list_head rp_list;
	u32 sequence_id;
	struct list_head res_list;
	struct dpu_crtc_res_ops ops;
};

/**
 * struct dpu_crtc_state - dpu container for atomic crtc state
 * @base: Base drm crtc state structure
 * @connectors    : Currently associated drm connectors
 * @num_connectors: Number of associated drm connectors
 * @rsc_client    : dpu rsc client when mode is valid
 * @is_ppsplit    : Whether current topology requires PPSplit special handling
 * @bw_control    : true if bw/clk controlled by core bw/clk properties
 * @bw_split_vote : true if bw controlled by llcc/dram bw properties
 * @crtc_roi      : Current CRTC ROI. Possibly sub-rectangle of mode.
 *                  Origin top left of CRTC.
 * @lm_bounds     : LM boundaries based on current mode full resolution, no ROI.
 *                  Origin top left of CRTC.
 * @lm_roi        : Current LM ROI, possibly sub-rectangle of mode.
 *                  Origin top left of CRTC.
 * @user_roi_list : List of user's requested ROIs as from set property
 * @property_state: Local storage for msm_prop properties
 * @property_values: Current crtc property values
 * @input_fence_timeout_ns : Cached input fence timeout, in ns
 * @num_dim_layers: Number of dim layers
 * @dim_layer: Dim layer configs
 * @num_ds: Number of destination scalers to be configured
 * @num_ds_enabled: Number of destination scalers enabled
 * @ds_dirty: Boolean to indicate if dirty or not
 * @ds_cfg: Destination scaler config
 * @new_perf: new performance state being requested
 * @sbuf_cfg: stream buffer configuration
 * @sbuf_prefill_line: number of line for inline rotator prefetch
 */
struct dpu_crtc_state {
	struct drm_crtc_state base;

	struct drm_connector *connectors[MAX_CONNECTORS];
	int num_connectors;
	struct dpu_rsc_client *rsc_client;
	bool rsc_update;
	bool bw_control;
	bool bw_split_vote;

	bool is_ppsplit;
	struct dpu_rect crtc_roi;
	struct dpu_rect lm_bounds[CRTC_DUAL_MIXERS];
	struct dpu_rect lm_roi[CRTC_DUAL_MIXERS];
	struct msm_roi_list user_roi_list;

	struct msm_property_state property_state;
	struct msm_property_value property_values[CRTC_PROP_COUNT];
	uint64_t input_fence_timeout_ns;
	uint32_t num_dim_layers;
	struct dpu_hw_dim_layer dim_layer[DPU_MAX_DIM_LAYERS];
	uint32_t num_ds;
	uint32_t num_ds_enabled;
	bool ds_dirty;
	struct dpu_hw_ds_cfg ds_cfg[DPU_MAX_DS_COUNT];

	struct dpu_core_perf_params new_perf;
	struct dpu_ctl_sbuf_cfg sbuf_cfg;
	u32 sbuf_prefill_line;

	struct dpu_crtc_respool rp;
};

#define to_dpu_crtc_state(x) \
	container_of(x, struct dpu_crtc_state, base)

/**
 * dpu_crtc_get_property - query integer value of crtc property
 * @S: Pointer to crtc state
 * @X: Property index, from enum msm_mdp_crtc_property
 * Returns: Integer value of requested property
 */
#define dpu_crtc_get_property(S, X) \
	((S) && ((X) < CRTC_PROP_COUNT) ? ((S)->property_values[(X)].value) : 0)

/**
 * dpu_crtc_get_mixer_width - get the mixer width
 * Mixer width will be same as panel width(/2 for split)
 * unless destination scaler feature is enabled
 */
static inline int dpu_crtc_get_mixer_width(struct dpu_crtc *dpu_crtc,
	struct dpu_crtc_state *cstate, struct drm_display_mode *mode)
{
	u32 mixer_width;

	if (!dpu_crtc || !cstate || !mode)
		return 0;

	if (cstate->num_ds_enabled)
		mixer_width = cstate->ds_cfg[0].lm_width;
	else
		mixer_width = (dpu_crtc->num_mixers == CRTC_DUAL_MIXERS ?
			mode->hdisplay / CRTC_DUAL_MIXERS : mode->hdisplay);

	return mixer_width;
}

/**
 * dpu_crtc_get_mixer_height - get the mixer height
 * Mixer height will be same as panel height unless
 * destination scaler feature is enabled
 */
static inline int dpu_crtc_get_mixer_height(struct dpu_crtc *dpu_crtc,
		struct dpu_crtc_state *cstate, struct drm_display_mode *mode)
{
	if (!dpu_crtc || !cstate || !mode)
		return 0;

	return (cstate->num_ds_enabled ?
			cstate->ds_cfg[0].lm_height : mode->vdisplay);
}

/**
 * dpu_crtc_frame_pending - retun the number of pending frames
 * @crtc: Pointer to drm crtc object
 */
static inline int dpu_crtc_frame_pending(struct drm_crtc *crtc)
{
	struct dpu_crtc *dpu_crtc;

	if (!crtc)
		return -EINVAL;

	dpu_crtc = to_dpu_crtc(crtc);
	return atomic_read(&dpu_crtc->frame_pending);
}

/**
 * dpu_crtc_vblank - enable or disable vblanks for this crtc
 * @crtc: Pointer to drm crtc object
 * @en: true to enable vblanks, false to disable
 */
int dpu_crtc_vblank(struct drm_crtc *crtc, bool en);

/**
 * dpu_crtc_commit_kickoff - trigger kickoff of the commit for this crtc
 * @crtc: Pointer to drm crtc object
 */
void dpu_crtc_commit_kickoff(struct drm_crtc *crtc);

/**
 * dpu_crtc_prepare_commit - callback to prepare for output fences
 * @crtc: Pointer to drm crtc object
 * @old_state: Pointer to drm crtc old state object
 */
void dpu_crtc_prepare_commit(struct drm_crtc *crtc,
		struct drm_crtc_state *old_state);

/**
 * dpu_crtc_complete_commit - callback signalling completion of current commit
 * @crtc: Pointer to drm crtc object
 * @old_state: Pointer to drm crtc old state object
 */
void dpu_crtc_complete_commit(struct drm_crtc *crtc,
		struct drm_crtc_state *old_state);

/**
 * dpu_crtc_init - create a new crtc object
 * @dev: dpu device
 * @plane: base plane
 * @Return: new crtc object or error
 */
struct drm_crtc *dpu_crtc_init(struct drm_device *dev, struct drm_plane *plane);

/**
 * dpu_crtc_cancel_pending_flip - complete flip for clients on lastclose
 * @crtc: Pointer to drm crtc object
 * @file: client to cancel's file handle
 */
void dpu_crtc_cancel_pending_flip(struct drm_crtc *crtc, struct drm_file *file);

/**
 * dpu_crtc_register_custom_event - api for enabling/disabling crtc event
 * @kms: Pointer to dpu_kms
 * @crtc_drm: Pointer to crtc object
 * @event: Event that client is interested
 * @en: Flag to enable/disable the event
 */
int dpu_crtc_register_custom_event(struct dpu_kms *kms,
		struct drm_crtc *crtc_drm, u32 event, bool en);

/**
 * dpu_crtc_get_intf_mode - get interface mode of the given crtc
 * @crtc: Pointert to crtc
 */
enum dpu_intf_mode dpu_crtc_get_intf_mode(struct drm_crtc *crtc);

/**
 * dpu_crtc_get_client_type - check the crtc type- rt, nrt, rsc, etc.
 * @crtc: Pointer to crtc
 */
static inline enum dpu_crtc_client_type dpu_crtc_get_client_type(
						struct drm_crtc *crtc)
{
	struct dpu_crtc_state *cstate =
			crtc ? to_dpu_crtc_state(crtc->state) : NULL;

	if (!cstate)
		return NRT_CLIENT;

	return dpu_crtc_get_intf_mode(crtc) == INTF_MODE_WB_LINE ? NRT_CLIENT :
			(cstate->rsc_client ? RT_RSC_CLIENT : RT_CLIENT);
}

/**
 * dpu_crtc_is_enabled - check if dpu crtc is enabled or not
 * @crtc: Pointer to crtc
 */
static inline bool dpu_crtc_is_enabled(struct drm_crtc *crtc)
{
	return crtc ? crtc->enabled : false;
}

/**
 * dpu_crtc_get_inline_prefill - get current inline rotation prefill
 * @crtc: Pointer to crtc
 * return: number of prefill lines
 */
static inline u32 dpu_crtc_get_inline_prefill(struct drm_crtc *crtc)
{
	struct dpu_crtc_state *cstate;

	if (!crtc || !crtc->state)
		return 0;

	cstate = to_dpu_crtc_state(crtc->state);
	return cstate->sbuf_cfg.rot_op_mode != DPU_CTL_ROT_OP_MODE_OFFLINE ?
		cstate->sbuf_prefill_line : 0;
}

/**
 * dpu_crtc_event_queue - request event callback
 * @crtc: Pointer to drm crtc structure
 * @func: Pointer to callback function
 * @usr: Pointer to user data to be passed to callback
 * Returns: Zero on success
 */
int dpu_crtc_event_queue(struct drm_crtc *crtc,
		void (*func)(struct drm_crtc *crtc, void *usr), void *usr);

/**
 * dpu_crtc_res_add - add given resource to resource pool in crtc state
 * @state: Pointer to drm crtc state
 * @type: Resource type
 * @tag: Search tag for given resource
 * @val: Resource handle
 * @ops: Resource callback operations
 * return: 0 if success; error code otherwise
 */
int dpu_crtc_res_add(struct drm_crtc_state *state, u32 type, u64 tag,
		void *val, struct dpu_crtc_res_ops *ops);

/**
 * dpu_crtc_res_get - get given resource from resource pool in crtc state
 * @state: Pointer to drm crtc state
 * @type: Resource type
 * @tag: Search tag for given resource
 * return: Resource handle if success; pointer error or null otherwise
 */
void *dpu_crtc_res_get(struct drm_crtc_state *state, u32 type, u64 tag);

/**
 * dpu_crtc_res_put - return given resource to resource pool in crtc state
 * @state: Pointer to drm crtc state
 * @type: Resource type
 * @tag: Search tag for given resource
 * return: None
 */
void dpu_crtc_res_put(struct drm_crtc_state *state, u32 type, u64 tag);

/**
 * dpu_crtc_get_crtc_roi - retrieve the crtc_roi from the given state object
 *	used to allow the planes to adjust their final lm out_xy value in the
 *	case of partial update
 * @crtc_state: Pointer to crtc state
 * @crtc_roi: Output pointer to crtc roi in the given state
 */
void dpu_crtc_get_crtc_roi(struct drm_crtc_state *state,
		const struct dpu_rect **crtc_roi);

/** dpu_crt_get_secure_level - retrieve the secure level from the give state
 *	object, this is used to determine the secure state of the crtc
 * @crtc : Pointer to drm crtc structure
 * @usr: Pointer to drm crtc state
 * return: secure_level
 */
static inline int dpu_crtc_get_secure_level(struct drm_crtc *crtc,
		struct drm_crtc_state *state)
{
	if (!crtc || !state)
		return -EINVAL;

	return dpu_crtc_get_property(to_dpu_crtc_state(state),
			CRTC_PROP_SECURITY_LEVEL);
}

/**
 * dpu_crtc_get_secure_transition - determines the operations to be
 * performed before transitioning to secure state
 * This function should be called after swapping the new state
 * @crtc: Pointer to drm crtc structure
 * @old_crtc_state: Poniter to previous CRTC state
 * Returns the bitmask of operations need to be performed, -Error in
 * case of error cases
 */
int dpu_crtc_get_secure_transition_ops(struct drm_crtc *crtc,
		struct drm_crtc_state *old_crtc_state,
		bool old_valid_fb);

/**
 * dpu_crtc_secure_ctrl - Initiates the transition between secure and
 *                          non-secure world
 * @crtc: Pointer to crtc
 * @post_commit: if this operation is triggered after commit
 */
int dpu_crtc_secure_ctrl(struct drm_crtc *crtc, bool post_commit);

#endif /* _DPU_CRTC_H_ */
