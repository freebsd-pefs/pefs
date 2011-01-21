/*-
 * Copyright (c) 2010 Konstantin Belousov <kib@FreeBSD.org>
 * Copyright (c) 2010 Pawel Jakub Dawidek <pjd@FreeBSD.org>
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
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/systm.h>

#include <fs/pefs/pefs_crypto.h>
#include <fs/pefs/pefs_aesni.h>

#define	AESNI_ENABLE_ENV	"vfs.pefs.aesni_enable"

static void
pefs_aesni_keysetup(struct pefs_ctx *xctx, const uint8_t *key, uint32_t keybits)
{
	struct pefs_aesni_ctx *ctx = (struct pefs_aesni_ctx *)xctx;

	switch (keybits) {
	case 128:
		ctx->rounds = AES128_ROUNDS;
		break;
	case 192:
		ctx->rounds = AES192_ROUNDS;
		break;
	case 256:
		ctx->rounds = AES256_ROUNDS;
		break;
	default:
		panic("pefs_aesni: invalid key length: %d", keybits);
	}

	aesni_set_enckey(key, ctx->enc_schedule, ctx->rounds);
	aesni_set_deckey(ctx->enc_schedule, ctx->dec_schedule, ctx->rounds);
}

static void
pefs_aesni_encrypt(const struct pefs_ctx *xctx, const uint8_t *in, uint8_t *out)
{
	const struct pefs_aesni_ctx *ctx = (const struct pefs_aesni_ctx *)xctx;

	aesni_enc(ctx->rounds - 1, ctx->enc_schedule, in, out, NULL);
}

static void
pefs_aesni_decrypt(const struct pefs_ctx *xctx, const uint8_t *in, uint8_t *out)
{
	const struct pefs_aesni_ctx *ctx = (const struct pefs_aesni_ctx *)xctx;

	aesni_dec(ctx->rounds - 1, ctx->dec_schedule, in, out, NULL);
}

static void
pefs_aesni_enter(struct pefs_session *xses)
{
	struct pefs_aesni_ses *ses = (struct pefs_aesni_ses *)xses;
	int error;
	
	ses->td = curthread;
	if (!is_fpu_kern_thread(0)) {
		error = fpu_kern_enter(ses->td, &ses->fpu_ctx, FPU_KERN_NORMAL);
		MPASS(error == 0);
		ses->fpu_saved = 1;
	} else
		ses->fpu_saved = 0;
}

static void
pefs_aesni_leave(struct pefs_session *xses)
{
	struct pefs_aesni_ses *ses = (struct pefs_aesni_ses *)xses;

	if (ses->fpu_saved)
		fpu_kern_leave(ses->td, &ses->fpu_ctx);
}

void
pefs_aesni_init(struct pefs_alg *pa)
{
	u_long enable = 1;

	TUNABLE_ULONG_FETCH(AESNI_ENABLE_ENV, &enable);

	if (enable != 0 && (cpu_feature2 & CPUID2_AESNI) != 0) {
		printf("pefs: AESNI hardware acceleration enabled\n");
		pa->pa_enter = pefs_aesni_enter;
		pa->pa_leave = pefs_aesni_leave;
		pa->pa_keysetup = pefs_aesni_keysetup;
		pa->pa_encrypt = pefs_aesni_encrypt;
		pa->pa_decrypt = pefs_aesni_decrypt;
	} else
#ifndef PEFS_DEBUG
	if (bootverbose)
#endif
		printf("pefs: AESNI hardware acceleration disabled\n");
}
