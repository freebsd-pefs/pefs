/*-
 * Copyright (c) 2009 Gleb Kurtsou
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

struct pefs_ctx;

typedef void algop_keysetup_t(struct pefs_ctx *ctx, const uint8_t *key,
    uint32_t keybits);
typedef void algop_crypt_t(const struct pefs_ctx *ctx, const uint8_t *in,
    uint8_t *out);

struct pefs_alg {
	int pa_id;
	algop_keysetup_t *pa_keysetup;
	algop_crypt_t *pa_encrypt;
	algop_crypt_t *pa_decrypt;
};

void pefs_xts_block_encrypt(const struct pefs_alg *alg,
    const struct pefs_ctx *tweak_ctx, const struct pefs_ctx *data_ctx,
    uint64_t sector, const uint8_t *xtweak, int len,
    const uint8_t *src, uint8_t *dst);

void pefs_xts_block_decrypt(const struct pefs_alg *alg,
    const struct pefs_ctx *tweak_ctx, const struct pefs_ctx *data_ctx,
    uint64_t sector, const uint8_t *xtweak, int len,
    const uint8_t *src, uint8_t *dst);
