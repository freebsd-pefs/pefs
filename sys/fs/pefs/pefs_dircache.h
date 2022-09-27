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
 *
 * $FreeBSD$
 */


#define	PEFS_CACHENAME_MAXLEN		PEFS_NAME_PTON_SIZE(MAXNAMLEN)

#define	PEFS_DIRCACHE_RETRY_COUNT	4
#define	PEFS_DIRCACHE_RETRY_MASK	(PEFS_DIRCACHE_RETRY_COUNT - 1)

#define	PEFS_DF_FORCE_GC		0x0001

struct pefs_dircache_pool;
struct pefs_dircache_entry;
LIST_HEAD(pefs_dircache_listhead, pefs_dircache_entry);

struct pefs_dircache {
	struct mtx			pd_mtx;
	struct pefs_dircache_listhead	pd_activehead;
	struct pefs_dircache_listhead	pd_stalehead;
	volatile u_quad_t               pd_filerev;
	struct pefs_dircache_pool	*pd_pool;
	struct pefs_dircache_entry	*pd_retry[PEFS_DIRCACHE_RETRY_COUNT];
};

struct pefs_dircache_entry {
	LIST_ENTRY(pefs_dircache_entry) pde_dir_entry;
	LIST_ENTRY(pefs_dircache_entry) pde_hash_entry;
	LIST_ENTRY(pefs_dircache_entry) pde_enchash_entry;
	struct pefs_dircache	*pde_dircache;
	struct pefs_tkey	pde_tkey;
	uint32_t		pde_namehash;
	uint32_t		pde_encnamehash;
	uint16_t		pde_namelen;
	uint16_t		pde_encnamelen;
	char			pde_name[PEFS_CACHENAME_MAXLEN + 1];
	char			pde_encname[MAXNAMLEN + 1];
};

extern int			pefs_dircache_enable;

void	pefs_dircache_init(void);
void	pefs_dircache_uninit(void);

struct pefs_dircache_pool *pefs_dircache_pool_create(void);
void	pefs_dircache_pool_free(struct pefs_dircache_pool *);

struct pefs_dircache	*pefs_dircache_create(struct pefs_dircache_pool *pdp);
void	pefs_dircache_purge(struct pefs_dircache *pd);
void	pefs_dircache_free(struct pefs_dircache *pd);
struct pefs_dircache_entry *pefs_dircache_lookup(struct pefs_dircache *pd,
	    char const *name, size_t name_len);
struct pefs_dircache_entry *pefs_dircache_lookup_retry(struct pefs_dircache *pd,
	    char const *name, size_t name_len);
struct pefs_dircache_entry *pefs_dircache_enclookup(struct pefs_dircache *pd,
	    char const *encname, size_t encname_len);
struct pefs_dircache_entry *pefs_dircache_enclookup_retry(
	    struct pefs_dircache *pd, char const *encname, size_t encname_len);
struct pefs_dircache_entry *pefs_dircache_insert(struct pefs_dircache *pd,
	    struct pefs_tkey *ptk, char const *name, size_t name_len,
	    char const *encname, size_t encname_len);
void	pefs_dircache_expire(struct pefs_dircache_entry *pde, u_int dflags);
void	pefs_dircache_expire_encname(struct pefs_dircache *pd,
	    char const *encname, size_t encname_len, u_int dflags);
void	pefs_dircache_gc(struct pefs_dircache *pd);

static __inline int
pefs_dircache_valid(struct pefs_dircache *pd, u_quad_t filerev)
{
	u_quad_t pd_filerev;

	if (filerev == 0)
		return 0;
	pd_filerev = atomic_load_acq_long(&pd->pd_filerev);
	return (filerev == pd_filerev);
}

static __inline void
pefs_dircache_beginupdate(struct pefs_dircache *pd)
{
}

static __inline void
pefs_dircache_endupdate(struct pefs_dircache *pd, u_quad_t filerev)
{
	atomic_store_rel_long(&pd->pd_filerev, filerev);
}

static __inline void
pefs_dircache_abortupdate(struct pefs_dircache *pd)
{
}
