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
 *
 * $FreeBSD$
 */

#define PEFS_FSTYPE			"pefs"
#define PEFS_KLD			PEFS_FSTYPE

#define PEFS_ALG_DEFAULT		PEFS_ALG_AES_CTR
#define PEFS_ALG_DEFAULT_KEYBITS	256

#define PEFS_KDF_ITERATIONS		50000

#define PEFS_RANDOMCHAIN_MIN		16
#define PEFS_RANDOMCHAIN_MAX		64

#define PEFS_KEYENC_MAC_SIZE		(PEFS_KEY_SIZE / 2)

struct pefs_xkeyenc {
	struct {
		struct pefs_xkey ke_next;
		uint32_t ke_alg;
		uint32_t ke_keybits;
	} a;
	u_char ke_mac[PEFS_KEYENC_MAC_SIZE];
};

struct pefs_keyparam {
	int kp_nopassphrase;
	int kp_iterations;
	char *kp_keyfile;
	char *kp_alg;
};

static inline void
pefs_keyparam_init(struct pefs_keyparam *kp)
{
	kp->kp_nopassphrase = 0;
	kp->kp_iterations = PEFS_KDF_ITERATIONS;
	kp->kp_keyfile = NULL;
	kp->kp_alg = NULL;
}

void	pefs_usage(void);
int	pefs_getfsroot(const char *path, char *fsroot, size_t size);
int	pefs_key_get(struct pefs_xkey *xk, const char *prompt, int verify,
    struct pefs_keyparam *kp);
int	pefs_key_encrypt(struct pefs_xkeyenc *xe,
    const struct pefs_xkey *xk_parent);
int	pefs_key_decrypt(struct pefs_xkeyenc *xe,
    const struct pefs_xkey *xk_parent);
uintmax_t	pefs_keyid_as_int(char *keyid);
const char *	pefs_alg_name(struct pefs_xkey *xk);
void	pefs_alg_list(FILE *stream);

