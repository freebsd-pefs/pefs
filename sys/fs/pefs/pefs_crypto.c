/*-
 * Copyright (c) 2009 Gleb Kurtsou <gk@FreeBSD.org>
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
#include <sys/dirent.h>
#include <sys/endian.h>
#include <sys/lock.h>
#include <sys/libkern.h>
#include <sys/limits.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/refcount.h>
#include <sys/queue.h>
#include <sys/vnode.h>

#include <vm/uma.h>

#include <crypto/camellia/camellia.h>
#include <crypto/hmac/hmac_sha512.h>
#include <crypto/rijndael/rijndael.h>

#include <fs/pefs/pefs.h>
#include <fs/pefs/vmac.h>

#define PEFS_CTR_BLOCK_SIZE		16

CTASSERT(PEFS_KEY_SIZE <= SHA512_DIGEST_LENGTH);
CTASSERT(PEFS_TWEAK_SIZE == 64/8);
CTASSERT(PEFS_NAME_CSUM_SIZE <= sizeof(uint64_t));
CTASSERT(MAXNAMLEN >= PEFS_NAME_PTON_SIZE(MAXNAMLEN) + PEFS_NAME_BLOCK_SIZE);
CTASSERT(CAMELLIA_BLOCK_SIZE == PEFS_CTR_BLOCK_SIZE);

static const char magic_keyinfo[] = "PEFSKEY";

typedef void algop_keysetup_t(struct pefs_ctx *ctx, const uint8_t *key,
    uint32_t keybits);
typedef void algop_ivsetup_t(struct pefs_ctx *ctx, const uint8_t *iv,
    uint64_t offset);
typedef void algop_crypt_t(struct pefs_ctx *ctx, const uint8_t *plaintext,
    uint8_t *ciphertext, uint32_t len);
typedef void algop_cryptblock_t(struct pefs_ctx *ctx, uint8_t *data);

struct pefs_alg {
	int pa_id;
	algop_keysetup_t *pa_keysetup;
	algop_ivsetup_t *pa_ivsetup;
	algop_crypt_t *pa_crypt;
};

struct pefs_ctr {
	uint64_t pctr_offset;
	uint32_t pctr_pos;
	char pctr_tweak[PEFS_TWEAK_SIZE];
	char pctr_block[PEFS_CTR_BLOCK_SIZE];
} ;

struct pefs_ctx {
	off_t pctx_offset;
	struct pefs_ctr pctx_ctr;
	union {
		camellia_ctx pctx_camellia;
		rijndael_ctx pctx_aes;
		struct hmac_sha512_ctx pctx_hmac;
		vmac_ctx_t pctx_vmac;
	} o;
};

static algop_ivsetup_t pefs_ctr_ivsetup;
static algop_keysetup_t pefs_aes_keysetup;
static algop_crypt_t pefs_aes_crypt;
static algop_keysetup_t pefs_camellia_keysetup;
static algop_crypt_t pefs_camellia_crypt;

static const struct pefs_alg pefs_alg_aes = {
	PEFS_ALG_AES_CTR,
	pefs_aes_keysetup,
	pefs_ctr_ivsetup,
	pefs_aes_crypt
};

static const struct pefs_alg pefs_alg_camellia = {
	PEFS_ALG_CAMELLIA_CTR,
	pefs_camellia_keysetup,
	pefs_ctr_ivsetup,
	pefs_camellia_crypt
};

static uma_zone_t pefs_ctx_zone;
static uma_zone_t pefs_key_zone;

void
pefs_crypto_init(void)
{
	pefs_ctx_zone = uma_zcreate("pefs_ctx", sizeof(struct pefs_ctx),
	    NULL, NULL, NULL, (uma_fini)bzero, UMA_ALIGN_PTR, 0);
	pefs_key_zone = uma_zcreate("pefs_key", sizeof(struct pefs_key),
	    NULL, NULL, NULL, (uma_fini)bzero, UMA_ALIGN_PTR, 0);
}

void
pefs_crypto_uninit(void)
{
	uma_zdestroy(pefs_ctx_zone);
	uma_zdestroy(pefs_key_zone);
}

struct pefs_ctx *
pefs_ctx_get(void)
{
	struct pefs_ctx *ctx;

	ctx = uma_zalloc(pefs_ctx_zone, M_WAITOK);
	ctx->pctx_offset = OFF_MAX;
	return (ctx);
}

void
pefs_ctx_free(struct pefs_ctx *ctx)
{
	uma_zfree(pefs_ctx_zone, ctx);
}

static inline void
pefs_ctx_cpy(struct pefs_ctx *dst, struct pefs_ctx *src)
{
	*dst = *src;
}

/*
 * Use HKDF-Expand() to derive keys, key parameter is supposed to be
 * cryptographically strong.
 * http://tools.ietf.org/html/draft-krawczyk-hkdf-00
 */
static void
pefs_key_generate(struct pefs_key *pk, const char *masterkey)
{
	struct pefs_ctx *ctx;
	char key[PEFS_KEY_SIZE];
	char idx;

	/* Properly initialize contexts as they are used to compare keys. */
	bzero(pk->pk_name_ctx, sizeof(struct pefs_ctx));
	bzero(pk->pk_name_csum_ctx, sizeof(struct pefs_ctx));
	bzero(pk->pk_data_ctx, sizeof(struct pefs_ctx));

	ctx = pefs_ctx_get();

	idx = 1;
	bzero(key, PEFS_KEY_SIZE);
	hmac_sha512_init(&ctx->o.pctx_hmac, masterkey, PEFS_KEY_SIZE);
	hmac_sha512_update(&ctx->o.pctx_hmac, key, PEFS_KEY_SIZE);
	hmac_sha512_update(&ctx->o.pctx_hmac, magic_keyinfo,
	    sizeof(magic_keyinfo));
	hmac_sha512_update(&ctx->o.pctx_hmac, &idx, sizeof(idx));
	hmac_sha512_final(&ctx->o.pctx_hmac, key, PEFS_KEY_SIZE);
	pk->pk_alg->pa_keysetup(pk->pk_data_ctx, key, pk->pk_keybits);

	idx = 2;
	hmac_sha512_init(&ctx->o.pctx_hmac, masterkey, PEFS_KEY_SIZE);
	hmac_sha512_update(&ctx->o.pctx_hmac, key, PEFS_KEY_SIZE);
	hmac_sha512_update(&ctx->o.pctx_hmac, magic_keyinfo,
	    sizeof(magic_keyinfo));
	hmac_sha512_update(&ctx->o.pctx_hmac, &idx, sizeof(idx));
	hmac_sha512_final(&ctx->o.pctx_hmac, key, PEFS_KEY_SIZE);
	pefs_aes_keysetup(pk->pk_name_ctx, key, 128);

	idx = 3;
	hmac_sha512_init(&ctx->o.pctx_hmac, masterkey, PEFS_KEY_SIZE);
	hmac_sha512_update(&ctx->o.pctx_hmac, key, PEFS_KEY_SIZE);
	hmac_sha512_update(&ctx->o.pctx_hmac, magic_keyinfo,
	    sizeof(magic_keyinfo));
	hmac_sha512_update(&ctx->o.pctx_hmac, &idx, sizeof(idx));
	hmac_sha512_final(&ctx->o.pctx_hmac, key, PEFS_KEY_SIZE);
	vmac_set_key(key, &pk->pk_name_csum_ctx->o.pctx_vmac);

	bzero(key, PEFS_KEY_SIZE);
	pefs_ctx_free(ctx);

}

struct pefs_key *
pefs_key_get(int alg, int keybits, const char *key, const char *keyid)
{
	struct pefs_key *pk;

	pk = uma_zalloc(pefs_key_zone, M_WAITOK | M_ZERO);

	switch (alg) {
	case PEFS_ALG_AES_CTR:
		pk->pk_alg = &pefs_alg_aes;
		if (keybits == 128 || keybits == 192 || keybits == 256)
			pk->pk_keybits = keybits;
		break;
	case PEFS_ALG_CAMELLIA_CTR:
		pk->pk_alg = &pefs_alg_camellia;
		if (keybits == 128 || keybits == 192 || keybits == 256)
			pk->pk_keybits = keybits;
		break;
	default:
		uma_zfree(pefs_key_zone, pk);
		printf("pefs: unknown algorithm %d\n", alg);
		return (NULL);
	}
	if (pk->pk_keybits == 0) {
		uma_zfree(pefs_key_zone, pk);
		printf("pefs: invalid key size %d for algorithm %d\n",
		    keybits, alg);
		return (NULL);
	}
	pk->pk_algid = alg;

	refcount_init(&pk->pk_refcnt, 1);
	memcpy(pk->pk_keyid, keyid, PEFS_KEYID_SIZE);

	pk->pk_name_ctx = pefs_ctx_get();
	pk->pk_name_csum_ctx = pefs_ctx_get();
	pk->pk_data_ctx = pefs_ctx_get();

	pefs_key_generate(pk, key);

	return (pk);
}

struct pefs_key *
pefs_key_ref(struct pefs_key *pk)
{
	refcount_acquire(&pk->pk_refcnt);
	return (pk);
}

void
pefs_key_release(struct pefs_key *pk)
{
	if (pk == NULL)
		return;
	if (refcount_release(&pk->pk_refcnt)) {
		PEFSDEBUG("pefs_key_release: free pk=%p\n", pk);
		pefs_ctx_free(pk->pk_name_ctx);
		pefs_ctx_free(pk->pk_name_csum_ctx);
		pefs_ctx_free(pk->pk_data_ctx);
		uma_zfree(pefs_key_zone, pk);
	}
}

struct pefs_key *
pefs_key_lookup(struct pefs_mount *pm, char *keyid)
{
	struct pefs_key *pk;

	mtx_assert(&pm->pm_keys_lock, MA_OWNED);
	TAILQ_FOREACH(pk, &pm->pm_keys, pk_entry) {
		if (memcmp(pk->pk_keyid, keyid, PEFS_KEYID_SIZE) == 0) {
			return (pk);
		}
	}

	return (NULL);
}

int
pefs_key_add(struct pefs_mount *pm, int index, struct pefs_key *pk)
{
	struct pefs_key *i, *pk_pos;
	int pos;

	mtx_lock(&pm->pm_keys_lock);
	if (index == 0 && !TAILQ_EMPTY(&pm->pm_keys)) {
		mtx_unlock(&pm->pm_keys_lock);
		return (EEXIST);
	}
	pk_pos = NULL;
	pos = 0;
	TAILQ_FOREACH(i, &pm->pm_keys, pk_entry) {
		if (memcmp(pk->pk_keyid, i->pk_keyid, PEFS_KEYID_SIZE) == 0 ||
		    memcmp(pk->pk_data_ctx, i->pk_data_ctx,
		    sizeof(struct pefs_ctx)) == 0) {
			mtx_unlock(&pm->pm_keys_lock);
			return (EEXIST);
		}
		if (index == pos + 1) {
			pk_pos = i;
		}
	}
	pk->pk_entry_lock = &pm->pm_keys_lock;
	if (TAILQ_EMPTY(&pm->pm_keys)) {
		TAILQ_INSERT_HEAD(&pm->pm_keys, pk, pk_entry);
		PEFSDEBUG("pefs_key_add: root key added: %p\n", pk);
	} else if (pk_pos == NULL) {
		TAILQ_INSERT_TAIL(&pm->pm_keys, pk, pk_entry);
		PEFSDEBUG("pefs_key_add: tail key added: %p\n", pk);
	} else {
		TAILQ_INSERT_AFTER(&pm->pm_keys, pk_pos, pk, pk_entry);
		PEFSDEBUG("pefs_key_add: key added at pos=%d: %p\n", pos, pk);
	}
	mtx_unlock(&pm->pm_keys_lock);

	return (0);
}

void
pefs_key_remove(struct pefs_mount *pm, struct pefs_key *pk)
{
	mtx_assert(&pm->pm_keys_lock, MA_OWNED);
	MPASS(pk->pk_entry_lock != NULL);
	TAILQ_REMOVE(&pm->pm_keys, pk, pk_entry);
	pk->pk_entry_lock = NULL;
	PEFSDEBUG("pefs_key_remove: pk=%p\n", pk);
	pefs_key_release(pk);
}

int
pefs_key_remove_all(struct pefs_mount *pm)
{
	int n = 0;

	mtx_lock(&pm->pm_keys_lock);
	while (!TAILQ_EMPTY(&pm->pm_keys)) {
		pefs_key_remove(pm, TAILQ_FIRST(&pm->pm_keys));
		n++;
	}
	mtx_unlock(&pm->pm_keys_lock);

	return (n);
}

void
pefs_data_encrypt_setup(struct pefs_ctx *ctx, struct pefs_tkey *ptk,
    off_t offset)
{
	MPASS(ctx != NULL);
	MPASS(ptk->ptk_key != NULL);

	pefs_ctx_cpy(ctx, ptk->ptk_key->pk_data_ctx);
	ptk->ptk_key->pk_alg->pa_ivsetup(ctx, ptk->ptk_tweak, offset);
	ctx->pctx_offset = offset;
}

static void
pefs_data_encrypt_update(struct pefs_ctx *ctx, struct pefs_tkey *ptk,
    struct pefs_chunk *pc)
{
	MPASS(ctx != NULL);
	MPASS(ptk->ptk_key != NULL);
	MPASS((ctx->pctx_offset & PAGE_MASK) == 0);

	ptk->ptk_key->pk_alg->pa_crypt(ctx, pc->pc_base, pc->pc_base,
	    pc->pc_size);
	ctx->pctx_offset += pc->pc_size;
}

void
pefs_data_encrypt(struct pefs_ctx *ctx, struct pefs_tkey *ptk, off_t offset,
    struct pefs_chunk *pc)
{
	int free_ctx = 0;

	if (ctx == NULL) {
		ctx = pefs_ctx_get();
		free_ctx = 1;
	}

	if (offset != ctx->pctx_offset)
		pefs_data_encrypt_setup(ctx, ptk, offset);
	pefs_data_encrypt_update(ctx, ptk, pc);

	if (free_ctx)
		pefs_ctx_free(ctx);
}

void
pefs_data_decrypt_setup(struct pefs_ctx *ctx, struct pefs_tkey *ptk,
    off_t offset)
{
	pefs_data_encrypt_setup(ctx, ptk, offset);
}

static void
pefs_data_decrypt_update(struct pefs_ctx *ctx, struct pefs_tkey *ptk,
    struct pefs_chunk *pc)
{
	off_t offset;
	ssize_t resid;
	long *p;
	char *buf, *end;

	MPASS(ctx != NULL);
	MPASS(ptk->ptk_key != NULL);
	MPASS((ctx->pctx_offset & PAGE_MASK) == 0);

	offset = ctx->pctx_offset;
	buf = (char *)pc->pc_base;
	end = buf + pc->pc_size;
	while (buf < end) {
		if ((end - buf) >= PAGE_SIZE) {
			p = (long *)buf;
			resid = PAGE_SIZE / sizeof(long);
			for (; resid > 0; resid--)
				if (*(p++) != 0)
					break;
			if (resid == 0) {
				bzero(buf, PAGE_SIZE);
				offset += PAGE_SIZE;
				buf += PAGE_SIZE;
				continue;
			}
			resid = PAGE_SIZE;
		} else
			resid = end - buf;
		if (offset != ctx->pctx_offset)
			pefs_data_decrypt_setup(ctx, ptk, offset);
		ptk->ptk_key->pk_alg->pa_crypt(ctx, buf, buf, resid);
		buf += resid;
		offset += resid;
		ctx->pctx_offset += resid;
	}
}

void
pefs_data_decrypt(struct pefs_ctx *ctx, struct pefs_tkey *ptk, off_t offset,
    struct pefs_chunk *pc)
{
	int free_ctx = 0;

	if (ctx == NULL) {
		ctx = pefs_ctx_get();
		free_ctx = 1;
	}

	if (offset != ctx->pctx_offset)
		pefs_data_decrypt_setup(ctx, ptk, offset);
	pefs_data_decrypt_update(ctx, ptk, pc);

	if (free_ctx)
		pefs_ctx_free(ctx);
}

/*
 * File name layout: [checksum] [tweak] [name]
 * File name is padded with zeros to 16 byte boundary
 */
static inline size_t
pefs_name_padsize(size_t size)
{
	size_t psize;

	psize = size - PEFS_NAME_CSUM_SIZE;
	psize = PEFS_NAME_CSUM_SIZE +
	    roundup2(psize, PEFS_NAME_BLOCK_SIZE);

	return (psize);
}

static inline size_t
pefs_name_pad(char *name, size_t size, size_t maxsize)
{
	size_t psize;

	MPASS(size > PEFS_NAME_CSUM_SIZE && size <= MAXNAMLEN);
	psize = pefs_name_padsize(size);
	MPASS(psize <= MAXNAMLEN);
	if (psize != size) {
		if (maxsize < psize)
			panic("pefs_name_pad: buffer is too small");
		bzero(name + size, psize - size);
	}

	return (psize);
}

static inline void
pefs_name_checksum(struct pefs_ctx *ctx, struct pefs_key *pk, char *csum,
    char *name, size_t size)
{
	uint64_t buf[howmany(MAXNAMLEN + 1, sizeof(uint64_t))];
	uint64_t nonce[2];
	uint64_t csum_int;
	char *data;

	MPASS(size >= PEFS_NAME_CSUM_SIZE + (PEFS_TWEAK_SIZE * 2) &&
	    size <= MAXNAMLEN &&
	    (size - PEFS_NAME_CSUM_SIZE) % PEFS_NAME_BLOCK_SIZE == 0);

	/*
	 * First block of encrypted name contains 64bit random tweak.
	 * Considering AES strong cipher reuse it as a nonce. It's rather far
	 * from what VMAC specification suggests, but storing additional random
	 * data in file name is too expensive and decrypting before running vmac
	 * degrades performance dramatically.
	 * Use separate key for name checksum.
	 */
	memcpy(nonce, name + PEFS_NAME_CSUM_SIZE, PEFS_TWEAK_SIZE * 2);
	((char *)nonce)[15] &= 0xfe; /* VMAC requirement */

	size -= PEFS_NAME_CSUM_SIZE;
	data = name + PEFS_NAME_CSUM_SIZE;
	if (((uintptr_t)data & (__alignof__(uint64_t) - 1)) != 0) {
		memcpy(buf, data, size);
		data = (char *)buf;
	}

	pefs_ctx_cpy(ctx, pk->pk_name_csum_ctx);
	csum_int = vmac(data, size, (char *)nonce, NULL, &ctx->o.pctx_vmac);
	memcpy(csum, &csum_int, PEFS_NAME_CSUM_SIZE);
}

static inline void
pefs_name_enccbc(struct pefs_ctx *ctx, struct pefs_key *pk,
    u_char *data, ssize_t size)
{
	u_char *prev;
	int i;

	size -= PEFS_NAME_CSUM_SIZE;
	data += PEFS_NAME_CSUM_SIZE;
	MPASS(size > 0 && size % PEFS_NAME_BLOCK_SIZE == 0);

	pefs_ctx_cpy(ctx, pk->pk_name_ctx);

	/* Start with zero iv */
	while (1) {
		rijndael_encrypt(&ctx->o.pctx_aes, data, data);
		prev = data;
		data += PEFS_NAME_BLOCK_SIZE;
		size -= PEFS_NAME_BLOCK_SIZE;
		if (size == 0)
			break;
		for (i = 0; i < PEFS_NAME_BLOCK_SIZE; i++)
			data[i] ^= prev[i];
	}
}

static inline void
pefs_name_deccbc(struct pefs_ctx *ctx, struct pefs_key *pk,
    u_char *data, ssize_t size)
{
	u_char tmp[PEFS_NAME_BLOCK_SIZE], iv[PEFS_NAME_BLOCK_SIZE];
	int i;

	size -= PEFS_NAME_CSUM_SIZE;
	data += PEFS_NAME_CSUM_SIZE;
	MPASS(size > 0 && size % PEFS_NAME_BLOCK_SIZE == 0);

	pefs_ctx_cpy(ctx, pk->pk_name_ctx);

	bzero(iv, PEFS_NAME_BLOCK_SIZE);
	while (size > 0) {
		memcpy(tmp, data, PEFS_NAME_BLOCK_SIZE);
		rijndael_decrypt(&ctx->o.pctx_aes, data, data);
		for (i = 0; i < PEFS_NAME_BLOCK_SIZE; i++)
			data[i] ^= iv[i];
		memcpy(iv, tmp, PEFS_NAME_BLOCK_SIZE);
		data += PEFS_NAME_BLOCK_SIZE;
		size -= PEFS_NAME_BLOCK_SIZE;
	}
}

int
pefs_name_encrypt(struct pefs_ctx *ctx, struct pefs_tkey *ptk,
    const char *plain, size_t plain_len, char *enc, size_t enc_size)
{
	char buf[MAXNAMLEN + 1];
	size_t size;
	int free_ctx = 0;
	int r;

	KASSERT(ptk != NULL && ptk->ptk_key != NULL,
	    ("pefs_name_encrypt: key is null"));

	size = PEFS_NAME_CSUM_SIZE + PEFS_TWEAK_SIZE + plain_len;
	/* Resulting name size, count '.' prepended to name */
	r = PEFS_NAME_NTOP_SIZE(pefs_name_padsize(size)) + 1;
	if (r > MAXNAMLEN) {
		return (-ENAMETOOLONG);
	}
	if (enc_size < r) {
		printf("pefs: name encryption buffer is too small: length %jd, required %d\n",
		    (intmax_t)enc_size, r);
		return (-EOVERFLOW);
	}

	if (ctx == NULL) {
		ctx = pefs_ctx_get();
		free_ctx = 1;
	}

	memcpy(buf + PEFS_NAME_CSUM_SIZE, ptk->ptk_tweak, PEFS_TWEAK_SIZE);
	memcpy(buf + PEFS_NAME_CSUM_SIZE + PEFS_TWEAK_SIZE, plain, plain_len);

	size = pefs_name_pad(buf, size, sizeof(buf));
	pefs_name_enccbc(ctx, ptk->ptk_key, buf, size);
	pefs_name_checksum(ctx, ptk->ptk_key, buf, buf, size);

	if (free_ctx)
		pefs_ctx_free(ctx);

	enc[0] = '.';
	r = pefs_name_ntop(buf, size, enc + 1, enc_size - 1);
	if (r <= 0)
		return (r);
	r++;

	return (r);
}

int
pefs_name_decrypt(struct pefs_ctx *ctx, struct pefs_key *pk,
    struct pefs_tkey *ptk, const char *enc, size_t enc_len,
    char *plain, size_t plain_size)
{
	struct pefs_key *ki;
	char csum[PEFS_NAME_CSUM_SIZE];
	int free_ctx = 0;
	int r, ki_rev;

	KASSERT(enc != plain, ("pefs_name_decrypt: ciphertext and plaintext buffers should differ"));
	MPASS(enc_len > 0 && enc_len <= MAXNAMLEN);

	if (enc[0] != '.' || enc_len <= 1)
		return (-EINVAL);
	enc++;
	enc_len--;

	r = PEFS_NAME_PTON_SIZE(enc_len);
	if (r <= PEFS_TWEAK_SIZE + PEFS_NAME_CSUM_SIZE ||
	    (r - PEFS_NAME_CSUM_SIZE) % PEFS_NAME_BLOCK_SIZE != 0)
		return (-EINVAL);
	if (plain_size < r) {
		printf("pefs: name decryption buffer is too small: length %jd, required %d\n",
		    (intmax_t)plain_size, r);
		return (-EOVERFLOW);
	}

	r = pefs_name_pton(enc, enc_len, plain, plain_size);
	if (r <= 0) {
		PEFSDEBUG("pefs_name_decrypt: error: r=%d\n", r);
		return (-EINVAL);
	}

	if (ctx == NULL) {
		ctx = pefs_ctx_get();
		free_ctx = 1;
	}

	ki = pk;
	ki_rev = 0;
	do {
		pefs_name_checksum(ctx, ki, csum, plain, r);
		if (memcmp(csum, plain, PEFS_NAME_CSUM_SIZE) == 0)
			break;

		if (!ki_rev) {
			ki = TAILQ_NEXT(ki, pk_entry);
			if (ki == NULL) {
				ki_rev = 1;
				ki = pk;
			}
		}
		if (ki_rev) {
			ki = TAILQ_PREV(ki, pefs_key_head, pk_entry);
		}
	} while (ki != NULL);

	if (free_ctx)
		pefs_ctx_free(ctx);

	if (ki == NULL)
		return (-EINVAL);

	pefs_name_deccbc(ctx, ki, plain, r);

	if (ptk) {
		ptk->ptk_key = ki;
		memcpy(ptk->ptk_tweak, plain + PEFS_NAME_CSUM_SIZE,
		    PEFS_TWEAK_SIZE);
	}

	r -= PEFS_TWEAK_SIZE + PEFS_NAME_CSUM_SIZE;
	memcpy(plain, plain + PEFS_NAME_CSUM_SIZE + PEFS_TWEAK_SIZE, r);
	plain[r] = '\0';
	/* Remove encryption zero padding */
	while (r > 0 && plain[r - 1] == '\0')
		r--;
	MPASS(r > 0 && strlen(plain) == r);

	return (r);
}

static void
pefs_ctr_ivsetup(struct pefs_ctx *ctx, const uint8_t *iv, uint64_t offset)
{
	ctx->pctx_ctr.pctr_offset = offset / PEFS_CTR_BLOCK_SIZE;
	ctx->pctx_ctr.pctr_pos = offset % PEFS_CTR_BLOCK_SIZE;
	memcpy(ctx->pctx_ctr.pctr_tweak, iv, PEFS_TWEAK_SIZE);
}

static inline void
pefs_ctr_crypt(struct pefs_ctx *ctx, algop_cryptblock_t *cryptblock,
    const uint8_t *plaintext, uint8_t *ciphertext, uint32_t len)
{
	struct pefs_ctr *c = &ctx->pctx_ctr;
	uint64_t le_offset;
	uint32_t pos, l, i;

	pos = c->pctr_pos;
	while (len) {
		l = pos + len > PEFS_CTR_BLOCK_SIZE ?
		    PEFS_CTR_BLOCK_SIZE - pos : len;
		le_offset = htole64(c->pctr_offset);
		memcpy(c->pctr_block + PEFS_TWEAK_SIZE, &le_offset,
		    sizeof(uint64_t));
		memcpy(c->pctr_block, c->pctr_tweak, PEFS_TWEAK_SIZE);

		cryptblock(ctx, c->pctr_block);
		for (i = 0; i < l; i++) {
			*(ciphertext++) = c->pctr_block[pos + i] ^
			    *(plaintext++);
		}
		pos = (pos + l) & (PEFS_CTR_BLOCK_SIZE - 1);
		if (!pos)
			c->pctr_offset++;
		len -= l;
	}
	c->pctr_pos = pos;
}

static void
pefs_camellia_keysetup(struct pefs_ctx *ctx, const uint8_t *key,
    uint32_t keybits)
{
	camellia_set_key(&ctx->o.pctx_camellia, key, keybits);
}

static void
pefs_camellia_cryptblock(struct pefs_ctx *ctx, uint8_t *data)
{
	camellia_encrypt(&ctx->o.pctx_camellia, data, data);
}

static void
pefs_camellia_crypt(struct pefs_ctx *ctx, const uint8_t *plaintext,
    uint8_t *ciphertext, uint32_t len)
{
	pefs_ctr_crypt(ctx, pefs_camellia_cryptblock,
	    plaintext, ciphertext, len);
}

static void
pefs_aes_keysetup(struct pefs_ctx *ctx, const uint8_t *key, uint32_t keybits)
{
	rijndael_set_key(&ctx->o.pctx_aes, key, keybits);
}

static void
pefs_aes_cryptblock(struct pefs_ctx *ctx, uint8_t *data)
{
	rijndael_encrypt(&ctx->o.pctx_aes, data, data);
}

static void
pefs_aes_crypt(struct pefs_ctx *ctx, const uint8_t *plaintext,
    uint8_t *ciphertext, uint32_t len)
{
	pefs_ctr_crypt(ctx, pefs_aes_cryptblock,
	    plaintext, ciphertext, len);
}

