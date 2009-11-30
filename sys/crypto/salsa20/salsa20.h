/*
 * salsa20-merged.c version 20051118
 * D. J. Bernstein
 * Public domain.
 */

#ifndef _SYS_CRYPTO_SALSA20_H
#define _SYS_CRYPTO_SALSA20_H

#define SALSA20_MAXKEYSIZE		256
#define SALSA20_IVSIZE			64

typedef struct {
	uint32_t input[16];
	uint32_t j[16];
	uint8_t	tmp[64];
	uint32_t skip;
}	salsa20_ctx;

void	salsa20_keysetup(salsa20_ctx *ctx, const uint8_t *key, uint32_t keybits);
void	salsa20_ivsetup(salsa20_ctx *ctx, const uint8_t *iv, uint64_t offset);
void	salsa20_crypt(salsa20_ctx *ctx, const uint8_t *plaintext, uint8_t *ciphertext, uint32_t len);

#endif
