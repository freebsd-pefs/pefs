/*-
 * Copyright (c) 2005 Pawel Jakub Dawidek <pjd@FreeBSD.org>
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
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
#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <strings.h>
#endif

#include <crypto/hmac/hmac_sha512.h>

void
hmac_sha512_init(struct hmac_sha512_ctx *ctx, const uint8_t *hkey,
    size_t hkeylen)
{
	u_int i;

	bzero(ctx->k_opad, SHA512_BLOCK_LENGTH);
	if (hkeylen == 0)
		; /* do nothing */
	else if (hkeylen <= SHA512_BLOCK_LENGTH)
		bcopy(hkey, ctx->k_opad, hkeylen);
	else {
		/*
		 * If key is longer than SHA512_BLOCK_LENGTH bytes
		 * reset it to key = SHA512(key).
		 */
		SHA512_Init(&ctx->shactx);
		SHA512_Update(&ctx->shactx, hkey, hkeylen);
		SHA512_Final(ctx->k_opad, &ctx->shactx);
	}

	/* Perform inner SHA512. */
	SHA512_Init(&ctx->shactx);
	/* XOR key ipad value. */
	for (i = 0; i < SHA512_BLOCK_LENGTH; i++) {
		ctx->k_opad[i] ^= 0x36;
	}
	SHA512_Update(&ctx->shactx, ctx->k_opad, SHA512_BLOCK_LENGTH);
	/* XOR key opad value. */
	for (i = 0; i < SHA512_BLOCK_LENGTH; i++) {
		ctx->k_opad[i] ^= 0x36 ^ 0x5c;
	}
}

void
hmac_sha512_update(struct hmac_sha512_ctx *ctx, const uint8_t *data,
    size_t datasize)
{

	SHA512_Update(&ctx->shactx, data, datasize);
}

void
hmac_sha512_final(struct hmac_sha512_ctx *ctx, uint8_t *md, size_t mdsize)
{
	u_char digest[SHA512_DIGEST_LENGTH];

	SHA512_Final(digest, &ctx->shactx);
	/* Perform outer SHA512. */
	SHA512_Init(&ctx->shactx);
	SHA512_Update(&ctx->shactx, ctx->k_opad, SHA512_BLOCK_LENGTH);
	SHA512_Update(&ctx->shactx, digest, sizeof(digest));
	SHA512_Final(digest, &ctx->shactx);
	bzero(ctx, sizeof(*ctx));

	/* mdsize == 0 means "Give me the whole hash!" */
	if (mdsize == 0)
		mdsize = SHA512_DIGEST_LENGTH;
	bcopy(digest, md, mdsize);
}

void
hmac_sha512(const uint8_t *hkey, size_t hkeysize, const uint8_t *data,
    size_t datasize, uint8_t *md, size_t mdsize)
{
	struct hmac_sha512_ctx ctx;

	hmac_sha512_init(&ctx, hkey, hkeysize);
	hmac_sha512_update(&ctx, data, datasize);
	hmac_sha512_final(&ctx, md, mdsize);
}
