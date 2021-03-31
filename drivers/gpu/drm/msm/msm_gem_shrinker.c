// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016 Red Hat
 * Author: Rob Clark <robdclark@gmail.com>
 */

#include "msm_drv.h"
#include "msm_gem.h"
#include "msm_gpu.h"
#include "msm_gpu_trace.h"

static unsigned long
msm_gem_shrinker_count(struct shrinker *shrinker, struct shrink_control *sc)
{
	struct msm_drm_private *priv =
		container_of(shrinker, struct msm_drm_private, shrinker);
	return priv->shrinkable_count + priv->evictable_count;
}

static bool
purge(struct msm_gem_object *msm_obj)
{
	if (!is_purgeable(msm_obj))
		return false;

	/*
	 * This will move the obj out of still_in_list to
	 * the purged list
	 */
	msm_gem_purge(&msm_obj->base);

	return true;
}

static bool
evict(struct msm_gem_object *msm_obj)
{
	if (is_unevictable(msm_obj))
		return false;

	// TODO maybe rename s/evict/unpin/??
	msm_gem_evict(&msm_obj->base);

	return true;
}

static unsigned long
scan(struct msm_drm_private *priv, struct shrink_control *sc, unsigned long freed,
		bool (*shrink)(struct msm_gem_object *msm_obj),
		struct list_head *list)
{
	struct list_head still_in_list;

	INIT_LIST_HEAD(&still_in_list);

	mutex_lock(&priv->mm_lock);

	while (freed < sc->nr_to_scan) {
		struct msm_gem_object *msm_obj = list_first_entry_or_null(
				list, typeof(*msm_obj), mm_list);

		if (!msm_obj)
			break;

		list_move_tail(&msm_obj->mm_list, &still_in_list);

		/*
		 * If it is in the process of being freed, msm_gem_free_object
		 * can be blocked on mm_lock waiting to remove it.  So just
		 * skip it.
		 */
		if (!kref_get_unless_zero(&msm_obj->base.refcount))
			continue;

		/*
		 * Now that we own a reference, we can drop mm_lock for the
		 * rest of the loop body, to reduce contention with the
		 * retire_submit path (which could make more objects purgable)
		 */

		mutex_unlock(&priv->mm_lock);

		/*
		 * Note that this still needs to be trylock, since we can
		 * hit shrinker in response to trying to get backing pages
		 * for this obj (ie. while it's lock is already held)
		 */
		if (!msm_gem_trylock(&msm_obj->base))
			goto tail;

		if (shrink(msm_obj))
			freed += msm_obj->base.size >> PAGE_SHIFT;

		msm_gem_unlock(&msm_obj->base);

tail:
		drm_gem_object_put(&msm_obj->base);
		mutex_lock(&priv->mm_lock);
	}

	list_splice_tail(&still_in_list, list);
	mutex_unlock(&priv->mm_lock);

	return freed;
}

static unsigned long
msm_gem_shrinker_scan(struct shrinker *shrinker, struct shrink_control *sc)
{
	struct msm_drm_private *priv =
		container_of(shrinker, struct msm_drm_private, shrinker);
	unsigned long freed = 0;

	freed = scan(priv, sc, freed, purge, &priv->inactive_dontneed);

	if (freed > 0)
		trace_msm_gem_purge(freed << PAGE_SHIFT);

	if (freed < sc->nr_to_scan) {
		int evicted = scan(priv, sc, freed, evict, &priv->inactive_willneed);

		// TODO tracepoint..

		freed += evicted;
	}

	return (freed > 0) ? freed : SHRINK_STOP;
}

/* since we don't know any better, lets bail after a few
 * and if necessary the shrinker will be invoked again.
 * Seems better than unmapping *everything*
 */
static const int vmap_shrink_limit = 15;

static unsigned
vmap_shrink(struct list_head *mm_list)
{
	struct msm_gem_object *msm_obj;
	unsigned unmapped = 0;

	list_for_each_entry(msm_obj, mm_list, mm_list) {
		/* Use trylock, because we cannot block on a obj that
		 * might be trying to acquire mm_lock
		 */
		if (!msm_gem_trylock(&msm_obj->base))
			continue;
		if (is_vunmapable(msm_obj)) {
			msm_gem_vunmap(&msm_obj->base);
			unmapped++;
		}
		msm_gem_unlock(&msm_obj->base);

		if (++unmapped >= vmap_shrink_limit)
			break;
	}

	return unmapped;
}

static int
msm_gem_shrinker_vmap(struct notifier_block *nb, unsigned long event, void *ptr)
{
	struct msm_drm_private *priv =
		container_of(nb, struct msm_drm_private, vmap_notifier);
	struct list_head *mm_lists[] = {
		&priv->inactive_dontneed,
		&priv->inactive_willneed,
		priv->gpu ? &priv->gpu->active_list : NULL,
		NULL,
	};
	unsigned idx, unmapped = 0;

	mutex_lock(&priv->mm_lock);

	for (idx = 0; mm_lists[idx]; idx++) {
		unmapped += vmap_shrink(mm_lists[idx]);

		if (unmapped >= vmap_shrink_limit)
			break;
	}

	mutex_unlock(&priv->mm_lock);

	*(unsigned long *)ptr += unmapped;

	if (unmapped > 0)
		trace_msm_gem_purge_vmaps(unmapped);

	return NOTIFY_DONE;
}

/**
 * msm_gem_shrinker_init - Initialize msm shrinker
 * @dev: drm device
 *
 * This function registers and sets up the msm shrinker.
 */
void msm_gem_shrinker_init(struct drm_device *dev)
{
	struct msm_drm_private *priv = dev->dev_private;
	priv->shrinker.count_objects = msm_gem_shrinker_count;
	priv->shrinker.scan_objects = msm_gem_shrinker_scan;
	priv->shrinker.seeks = DEFAULT_SEEKS;
	WARN_ON(register_shrinker(&priv->shrinker));

	priv->vmap_notifier.notifier_call = msm_gem_shrinker_vmap;
	WARN_ON(register_vmap_purge_notifier(&priv->vmap_notifier));
}

/**
 * msm_gem_shrinker_cleanup - Clean up msm shrinker
 * @dev: drm device
 *
 * This function unregisters the msm shrinker.
 */
void msm_gem_shrinker_cleanup(struct drm_device *dev)
{
	struct msm_drm_private *priv = dev->dev_private;

	if (priv->shrinker.nr_deferred) {
		WARN_ON(unregister_vmap_purge_notifier(&priv->vmap_notifier));
		unregister_shrinker(&priv->shrinker);
	}
}
