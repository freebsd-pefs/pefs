/*-
 * Copyright (c) 2009 Gleb Kurtsou <gleb@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/namei.h>
#include <sys/dirent.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/sx.h>
#include <sys/uio.h>
#include <sys/taskqueue.h>
#include <sys/vnode.h>

#include <fs/pefs/pefs.h>
#include <fs/pefs/pefs_dircache.h>

#define	DIRCACHE_SIZE_ENV	"vfs.pefs.dircache.buckets"
#define	DIRCACHE_SIZE_MIN	512
#define	DIRCACHE_SIZE_DEFAULT	(desiredvnodes / 8)

#define	DIRCACHE_GLOBAL_ENV	"vfs.pefs.dircache.global"

#define DIRCACHE_TBL(pool, hash) \
	(&(pool)->pdp_tbl[(hash) & dircache_hashmask])
#define DIRCACHE_ENCTBL(pool, hash) \
	(&(pool)->pdp_enctbl[(hash) & dircache_hashmask])
#define DIRCACHE_MTX(hash) \
	(&dircache_mtxs[(hash) % MAXCPU])

struct pefs_dircache_pool
{
	struct pefs_dircache_listhead	*pdp_tbl;
	struct pefs_dircache_listhead	*pdp_enctbl;
};

static struct pefs_dircache_pool dircache_global;

static u_long			dircache_hashmask;

#if __FreeBSD_version < 1000500
#define mtx_padalign		mtx
#endif

static struct mtx_padalign	dircache_mtxs[MAXCPU];

static uma_zone_t		dircache_zone;
static uma_zone_t		dircache_entry_zone;

SYSCTL_NODE(_vfs_pefs, OID_AUTO, dircache, CTLFLAG_RW, 0,
    "PEFS directory cache");

int		pefs_dircache_enable = 1;
SYSCTL_INT(_vfs_pefs_dircache, OID_AUTO, enable, CTLFLAG_RW,
    &pefs_dircache_enable, 0, "Enable dircache");

static int	dircache_global_enable = 1;
SYSCTL_INT(_vfs_pefs_dircache, OID_AUTO, global, CTLFLAG_RD,
    &dircache_global_enable, 0, "Global dircache hash table");

static u_long	dircache_buckets = 0;
SYSCTL_ULONG(_vfs_pefs_dircache, OID_AUTO, buckets, CTLFLAG_RD,
    &dircache_buckets, 0, "Number of dircache hash table buckets");

static u_long	dircache_entries = 0;
SYSCTL_ULONG(_vfs_pefs_dircache, OID_AUTO, entries, CTLFLAG_RD,
    &dircache_entries, 0, "Entries in dircache");

static void	pefs_dircache_pool_init(struct pefs_dircache_pool *pdp);
static void	pefs_dircache_pool_uninit(struct pefs_dircache_pool *pdp);

void
pefs_dircache_init(void)
{
	u_int i;

	TUNABLE_ULONG_FETCH(DIRCACHE_SIZE_ENV, &dircache_buckets);
	TUNABLE_INT_FETCH(DIRCACHE_GLOBAL_ENV, &dircache_global_enable);

	if (dircache_buckets < DIRCACHE_SIZE_MIN)
		dircache_buckets = DIRCACHE_SIZE_DEFAULT;
	dircache_hashmask = (1ULL << flsl(dircache_buckets)) - 1;
	dircache_global_enable = !!dircache_global_enable;

	for (i = 0; i < MAXCPU; i++) {
		mtx_init(&dircache_mtxs[i], "dircache_mtx", NULL, MTX_DEF);
	}

	dircache_zone = uma_zcreate("pefs_dircache",
	    sizeof(struct pefs_dircache), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	dircache_entry_zone = uma_zcreate("pefs_dircache_entry",
	    sizeof(struct pefs_dircache_entry), NULL, NULL, NULL,
	    pefs_zone_fini_bzero, UMA_ALIGN_PTR, 0);

	if (dircache_global_enable != 0) {
		pefs_dircache_pool_init(&dircache_global);
	}
}

void
pefs_dircache_uninit(void)
{
	u_int i;

	if (dircache_global_enable != 0) {
		pefs_dircache_pool_uninit(&dircache_global);
	}

	uma_zdestroy(dircache_zone);
	uma_zdestroy(dircache_entry_zone);

	for (i = 0; i < MAXCPU; i++) {
		mtx_destroy(&dircache_mtxs[i]);
	}
}

static void
pefs_dircache_pool_init(struct pefs_dircache_pool *pdp)
{
	u_long tbl_size = dircache_hashmask + 1;
	u_long i;

	pdp->pdp_tbl = malloc(tbl_size * sizeof(pdp->pdp_tbl[0]),
	    M_PEFSHASH, M_WAITOK);
	pdp->pdp_enctbl = malloc(tbl_size * sizeof(pdp->pdp_enctbl[0]),
	    M_PEFSHASH, M_WAITOK);
	for (i = 0; i < tbl_size; i++) {
		LIST_INIT(&pdp->pdp_tbl[i]);
		LIST_INIT(&pdp->pdp_enctbl[i]);
	}
}

static void
pefs_dircache_pool_uninit(struct pefs_dircache_pool *pdp)
{
	free(pdp->pdp_tbl, M_PEFSHASH);
	free(pdp->pdp_enctbl, M_PEFSHASH);
	pdp->pdp_tbl = NULL;
	pdp->pdp_enctbl = NULL;
}

struct pefs_dircache_pool *
pefs_dircache_pool_create(void)
{
	struct pefs_dircache_pool *pdp;

	if (dircache_global_enable != 0)
		return (&dircache_global);

	pdp = malloc(sizeof(*pdp), M_PEFSHASH, M_WAITOK);
	pefs_dircache_pool_init(pdp);
	return (pdp);
}

void
pefs_dircache_pool_free(struct pefs_dircache_pool *pdp)
{
	if (dircache_global_enable != 0)
		return;

	pefs_dircache_pool_uninit(pdp);
	free(pdp, M_PEFSHASH);
}

static __inline uint32_t
dircache_hashname(struct pefs_dircache *pd, char const *buf, size_t len)
{
	uint32_t h;

	h = pefs_hash_mixptr(pd);
	h ^= hash32_buf(buf, len, HASHINIT * len);
	return (h);
}

static void
dircache_entry_free(struct pefs_dircache_entry *pde)
{
	PEFSDEBUG("dircache_entry_free: %p %s -> %s\n",
	    pde, pde->pde_name, pde->pde_encname);

	pefs_key_release(pde->pde_tkey.ptk_key);
	LIST_REMOVE(pde, pde_dir_entry);

	atomic_subtract_long(&dircache_entries, 1);
	uma_zfree(dircache_entry_zone, pde);
}

static void
dircache_gc_locked(struct pefs_dircache *pd)
{
	struct pefs_dircache_entry *pde, *tmp;

	// ASSERT_VOP_ELOCKED
	LIST_FOREACH_SAFE(pde, &pd->pd_stalehead, pde_dir_entry, tmp) {
		dircache_entry_free(pde);
	}
}

static void
dircache_entry_expire_locked(struct pefs_dircache_entry *pde)
{
	struct pefs_dircache *pd;
	struct mtx_padalign *bucket_mtx;

	pd = pde->pde_dircache;
	pde->pde_dircache = NULL;

	LIST_REMOVE(pde, pde_dir_entry);
	LIST_INSERT_HEAD(&pd->pd_stalehead, pde, pde_dir_entry);

	bucket_mtx = DIRCACHE_MTX(pde->pde_namehash);
	mtx_lock(bucket_mtx);
	LIST_REMOVE(pde, pde_hash_entry);
	mtx_unlock(bucket_mtx);

	bucket_mtx = DIRCACHE_MTX(pde->pde_encnamehash);
	mtx_lock(bucket_mtx);
	LIST_REMOVE(pde, pde_enchash_entry);
	mtx_unlock(bucket_mtx);
}

static __inline int
dircache_cmp_name(struct pefs_dircache_entry *pde, uint32_t h,
    char const *name, size_t name_len)
{
	if (pde->pde_namehash == h &&
	    pde->pde_namelen == name_len &&
	    memcmp(pde->pde_name, name, name_len) == 0)
		return 1;
	return 0;
}

static __inline int
dircache_cmp_encname(struct pefs_dircache_entry *pde, uint32_t h,
    char const *encname, size_t encname_len)
{
	if (pde->pde_encnamehash == h &&
	    pde->pde_encnamelen == encname_len &&
	    memcmp(pde->pde_encname, encname, encname_len) == 0)
		return 1;
	return 0;
}

static __inline void
dircache_retry_set(struct pefs_dircache *pd, struct pefs_dircache_entry *pde)
{
	uint32_t h;

	h = (pde->pde_encnamehash & PEFS_DIRCACHE_RETRY_MASK);
	atomic_store_rel_ptr((volatile uintptr_t *)&pd->pd_retry[h],
	    (uintptr_t)pde);
}

static __inline void
dircache_retry_clear(struct pefs_dircache *pd)
{
	u_int i;

	for (i = 0; i < PEFS_DIRCACHE_RETRY_COUNT; i++)
		atomic_store_rel_ptr((volatile uintptr_t *)&pd->pd_retry[i], 0);
}

struct pefs_dircache *
pefs_dircache_create(struct pefs_dircache_pool *pdp)
{
	struct pefs_dircache *pd;

	pd = uma_zalloc(dircache_zone, M_WAITOK | M_ZERO);
	mtx_init(&pd->pd_mtx, "pefs_dircache_mtx", NULL, MTX_DEF);
	pd->pd_pool = pdp;
	LIST_INIT(&pd->pd_activehead);
	LIST_INIT(&pd->pd_stalehead);

	return (pd);
}

void
pefs_dircache_purge(struct pefs_dircache *pd)
{
	struct pefs_dircache_entry *pde, *tmp;

	if (pd == NULL)
		return;

	// ASSERT_VOP_ELOCKED
	mtx_lock(&pd->pd_mtx);
	atomic_store_rel_long(&pd->pd_gen, 0);
	atomic_store_rel_64(&pd->pd_filerev, 0);
	LIST_FOREACH_SAFE(pde, &pd->pd_activehead, pde_dir_entry, tmp) {
		dircache_entry_expire_locked(pde);
	}
	mtx_unlock(&pd->pd_mtx);

	pefs_dircache_gc(pd);
}

void
pefs_dircache_expire(struct pefs_dircache_entry *pde, u_int dflags)
{
	struct pefs_dircache *pd;

	pd = pde->pde_dircache;
	if (pd == NULL)
		return;
	mtx_lock(&pd->pd_mtx);
	atomic_store_rel_long(&pd->pd_gen, 0);
	atomic_store_rel_64(&pd->pd_filerev, 0);
	dircache_retry_clear(pd);
	if (pde->pde_dircache != NULL) {
		dircache_entry_expire_locked(pde);
		if ((dflags & PEFS_DF_FORCE_GC) != 0)
			dircache_gc_locked(pd);

	}
	mtx_unlock(&pd->pd_mtx);
}

void
pefs_dircache_expire_encname(struct pefs_dircache *pd,
    const char *encname, size_t encname_len, u_int dflags)
{
	struct pefs_dircache_entry *pde;

	PEFSDEBUG("dircache_expire_encname: %.*s\n",
	    (int)encname_len, encname);
	pde = pefs_dircache_enclookup_retry(pd, encname, encname_len);
	if (pde == NULL)
		pde = pefs_dircache_enclookup(pd, encname, encname_len);
	if (pde != NULL)
		pefs_dircache_expire(pde, dflags);
}

void
pefs_dircache_gc(struct pefs_dircache *pd)
{
	if (pd == NULL)
		return;

	mtx_lock(&pd->pd_mtx);
	dircache_retry_clear(pd);
	dircache_gc_locked(pd);
	mtx_unlock(&pd->pd_mtx);
}

void
pefs_dircache_free(struct pefs_dircache *pd)
{
	if (pd == NULL)
		return;

	pefs_dircache_purge(pd);
	mtx_destroy(&pd->pd_mtx);
	uma_zfree(dircache_zone, pd);
}

struct pefs_dircache_entry *
pefs_dircache_insert(struct pefs_dircache *pd, struct pefs_tkey *ptk,
    char const *name, size_t name_len,
    char const *encname, size_t encname_len)
{
	struct pefs_dircache_pool *pdp;
	struct pefs_dircache_listhead *bucket;
	struct pefs_dircache_entry *pde, *xpde;
	struct mtx_padalign *bucket_mtx;

	MPASS(ptk->ptk_key != NULL);

	if (name_len == 0 || name_len >= sizeof(pde->pde_name) ||
	    encname_len == 0 || encname_len >= sizeof(pde->pde_encname))
		panic("pefs: invalid file name length: %zd/%zd",
		    name_len, encname_len);

	pde = uma_zalloc(dircache_entry_zone, M_WAITOK | M_ZERO);
	pde->pde_dircache = pd;

	pde->pde_tkey = *ptk;
	pefs_key_ref(pde->pde_tkey.ptk_key);

	pde->pde_namelen = name_len;
	memcpy(pde->pde_name, name, name_len);
	pde->pde_name[name_len] = '\0';
	pde->pde_namehash = dircache_hashname(pd, pde->pde_name,
	    pde->pde_namelen);

	pde->pde_encnamelen = encname_len;
	memcpy(pde->pde_encname, encname, encname_len);
	pde->pde_encname[encname_len] = '\0';
	pde->pde_encnamehash = dircache_hashname(pd, pde->pde_encname,
	    pde->pde_encnamelen);

	/* Insert into list and set pge_gen */
	pdp = pd->pd_pool;

	mtx_lock(&pd->pd_mtx);

	bucket = DIRCACHE_ENCTBL(pdp, pde->pde_encnamehash);
	bucket_mtx = DIRCACHE_MTX(pde->pde_encnamehash);
	mtx_lock(bucket_mtx);
	LIST_FOREACH(xpde, bucket, pde_enchash_entry) {
		if (xpde->pde_dircache == pd &&
		    dircache_cmp_encname(xpde, pde->pde_encnamehash,
		    encname, encname_len) != 0) {
			mtx_unlock(bucket_mtx);
			mtx_unlock(&pd->pd_mtx);
			PEFSDEBUG("pefs_dircache_insert: collision %s\n",
			    pde->pde_name);
			pefs_key_release(pde->pde_tkey.ptk_key);
			uma_zfree(dircache_entry_zone, pde);
			return (xpde);
		}
	}
	LIST_INSERT_HEAD(bucket, pde, pde_enchash_entry);
	mtx_unlock(bucket_mtx);

	bucket = DIRCACHE_TBL(pdp, pde->pde_namehash);
	bucket_mtx = DIRCACHE_MTX(pde->pde_namehash);
	mtx_lock(bucket_mtx);
	LIST_INSERT_HEAD(bucket, pde, pde_hash_entry);
	mtx_unlock(bucket_mtx);

	LIST_INSERT_HEAD(&pd->pd_activehead, pde, pde_dir_entry);
	mtx_unlock(&pd->pd_mtx);

	atomic_add_long(&dircache_entries, 1);

	PEFSDEBUG("pefs_dircache_insert: %p %s -> %s\n",
	    pde, pde->pde_name, pde->pde_encname);

	return (pde);
}

struct pefs_dircache_entry *
pefs_dircache_lookup(struct pefs_dircache *pd, char const *name,
    size_t name_len)
{
	struct pefs_dircache_entry *pde;
	struct pefs_dircache_listhead *bucket;
	struct mtx_padalign *bucket_mtx;
	uint32_t h;

	MPASS(pd != NULL);

	h = dircache_hashname(pd, name, name_len);
	bucket = DIRCACHE_TBL(pd->pd_pool, h);
	bucket_mtx = DIRCACHE_MTX(h);
	mtx_lock(bucket_mtx);
	LIST_FOREACH(pde, bucket, pde_hash_entry) {
		if (pde->pde_dircache == pd &&
		    dircache_cmp_name(pde, h, name, name_len) != 0) {
			mtx_unlock(bucket_mtx);
			PEFSDEBUG("pefs_dircache_lookup: found %s -> %s\n",
			    pde->pde_name, pde->pde_encname);
			dircache_retry_set(pd, pde);
			return (pde);
		}
	}
	mtx_unlock(bucket_mtx);
	PEFSDEBUG("pefs_dircache_lookup: not found %s\n", name);
	return (NULL);
}

struct pefs_dircache_entry *
pefs_dircache_enclookup(struct pefs_dircache *pd, char const *encname,
    size_t encname_len)
{
	struct pefs_dircache_entry *pde;
	struct pefs_dircache_listhead *bucket;
	struct mtx_padalign *bucket_mtx;
	uint32_t h;

	h = dircache_hashname(pd, encname, encname_len);
	bucket = DIRCACHE_ENCTBL(pd->pd_pool, h);
	bucket_mtx = DIRCACHE_MTX(h);
	mtx_lock(bucket_mtx);
	LIST_FOREACH(pde, bucket, pde_enchash_entry) {
		if (pde->pde_dircache == pd &&
		    dircache_cmp_encname(pde, h, encname, encname_len) != 0) {
			mtx_unlock(bucket_mtx);
			PEFSDEBUG("pefs_dircache_enclookup: found %s -> %s\n",
			    pde->pde_name, pde->pde_encname);
			dircache_retry_set(pd, pde);
			return (pde);
		}
	}
	mtx_unlock(bucket_mtx);
	PEFSDEBUG("pefs_dircache_enclookup: not found %s\n", encname);
	return (NULL);
}

struct pefs_dircache_entry *
pefs_dircache_lookup_retry(struct pefs_dircache *pd, char const *name,
    size_t name_len)
{
	struct pefs_dircache_entry *pde;
	u_int i;

	for (i = 0; i < PEFS_DIRCACHE_RETRY_COUNT; i++) {
		pde = (void *)atomic_load_acq_ptr(
		    (volatile uintptr_t *)&pd->pd_retry[i]);
		if (pde != NULL && pde->pde_dircache == pd &&
		    pde->pde_namelen == name_len &&
		    memcmp(pde->pde_name, name, name_len) == 0)
			return (pde);
	}
	return (NULL);
}

struct pefs_dircache_entry *
pefs_dircache_enclookup_retry(struct pefs_dircache *pd, char const *encname,
    size_t encname_len)
{
	struct pefs_dircache_entry *pde;
	u_int i;

	for (i = 0; i < PEFS_DIRCACHE_RETRY_COUNT; i++) {
		pde = (void *)atomic_load_acq_ptr(
		    (volatile uintptr_t *)&pd->pd_retry[i]);
		if (pde != NULL && pde->pde_dircache == pd &&
		    pde->pde_encnamelen == encname_len &&
		    memcmp(pde->pde_encname, encname, encname_len) == 0)
			return (pde);
	}
	return (NULL);
}
