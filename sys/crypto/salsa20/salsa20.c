/*
 * salsa20-merged.c version 20051118
 * D. J. Bernstein
 * Public domain.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/endian.h>

#include <crypto/salsa20/salsa20.h>

#define U8TO32_LITTLE(p)	htole32(((const uint32_t*)(p))[0])
#define U32TO8_LITTLE(p, v)	(((uint32_t*)(p))[0] = le32toh(v))
#define ROTL32(v, n)		(((v) << (n)) | ((v) >> (32 - (n))))
#define ROTATE(v, c)		ROTL32(v, c)
#define XOR(v, w)		((v) ^ (w))
#define PLUS(v, w)		((v) + (w))
#define PLUSONE(v)		PLUS((v), 1)

static const char sigma[16] = "expand 32-byte k";
static const char tau[16] = "expand 16-byte k";

void
salsa20_keysetup(salsa20_ctx *x, const uint8_t *k, uint32_t kbits)
{
	const char *constants;

	x->input[1] = U8TO32_LITTLE(k + 0);
	x->input[2] = U8TO32_LITTLE(k + 4);
	x->input[3] = U8TO32_LITTLE(k + 8);
	x->input[4] = U8TO32_LITTLE(k + 12);
	if (kbits == 256) {		/* recommended */
		k += 16;
		constants = sigma;
	} else {			/* kbits == 128 */
		constants = tau;
	}
	x->input[11] = U8TO32_LITTLE(k + 0);
	x->input[12] = U8TO32_LITTLE(k + 4);
	x->input[13] = U8TO32_LITTLE(k + 8);
	x->input[14] = U8TO32_LITTLE(k + 12);
	x->input[0] = U8TO32_LITTLE(constants + 0);
	x->input[5] = U8TO32_LITTLE(constants + 4);
	x->input[10] = U8TO32_LITTLE(constants + 8);
	x->input[15] = U8TO32_LITTLE(constants + 12);
}

void
salsa20_ivsetup(salsa20_ctx *x, const uint8_t *iv, uint64_t offset)
{
	x->skip = offset & ((1 << 6) - 1);
	offset >>= 6;
	x->input[6] = U8TO32_LITTLE(iv + 0);
	x->input[7] = U8TO32_LITTLE(iv + 4);
	x->input[8] = htole32((uint32_t) offset);
	offset >>= 32;
	x->input[9] = htole32((uint32_t) offset);
}

void
salsa20_crypt(salsa20_ctx *x, const uint8_t *m, uint8_t *c, uint32_t bytes)
{
	uint32_t x0, x1, x2, x3, x4, x5, x6, x7,
		 x8, x9, x10, x11, x12, x13, x14, x15;
	uint8_t *ctarget = NULL;
	const uint8_t *msrc = NULL;
	int i;

	if (!bytes)
		return;

	x->j[0] = x->input[0];
	x->j[1] = x->input[1];
	x->j[2] = x->input[2];
	x->j[3] = x->input[3];
	x->j[4] = x->input[4];
	x->j[5] = x->input[5];
	x->j[6] = x->input[6];
	x->j[7] = x->input[7];
	x->j[8] = x->input[8];
	x->j[9] = x->input[9];
	x->j[10] = x->input[10];
	x->j[11] = x->input[11];
	x->j[12] = x->input[12];
	x->j[13] = x->input[13];
	x->j[14] = x->input[14];
	x->j[15] = x->input[15];

	for (;;) {
		if (__predict_false(x->skip != 0)) {
			msrc = m;
			ctarget = c;
			for (i = 0; i < bytes && i + x->skip < 64; ++i)
				x->tmp[i + x->skip] = msrc[i];
			m = x->tmp;
			c = x->tmp;
		} else if (bytes < 64) {
			ctarget = c;
			for (i = 0; i < bytes; ++i)
				x->tmp[i] = m[i];
			m = x->tmp;
			c = x->tmp;
		}
		x0 = x->j[0];
		x1 = x->j[1];
		x2 = x->j[2];
		x3 = x->j[3];
		x4 = x->j[4];
		x5 = x->j[5];
		x6 = x->j[6];
		x7 = x->j[7];
		x8 = x->j[8];
		x9 = x->j[9];
		x10 = x->j[10];
		x11 = x->j[11];
		x12 = x->j[12];
		x13 = x->j[13];
		x14 = x->j[14];
		x15 = x->j[15];
		for (i = 20; i > 0; i -= 2) {
			x4 = XOR(x4, ROTATE(PLUS(x0, x12), 7));
			x8 = XOR(x8, ROTATE(PLUS(x4, x0), 9));
			x12 = XOR(x12, ROTATE(PLUS(x8, x4), 13));
			x0 = XOR(x0, ROTATE(PLUS(x12, x8), 18));
			x9 = XOR(x9, ROTATE(PLUS(x5, x1), 7));
			x13 = XOR(x13, ROTATE(PLUS(x9, x5), 9));
			x1 = XOR(x1, ROTATE(PLUS(x13, x9), 13));
			x5 = XOR(x5, ROTATE(PLUS(x1, x13), 18));
			x14 = XOR(x14, ROTATE(PLUS(x10, x6), 7));
			x2 = XOR(x2, ROTATE(PLUS(x14, x10), 9));
			x6 = XOR(x6, ROTATE(PLUS(x2, x14), 13));
			x10 = XOR(x10, ROTATE(PLUS(x6, x2), 18));
			x3 = XOR(x3, ROTATE(PLUS(x15, x11), 7));
			x7 = XOR(x7, ROTATE(PLUS(x3, x15), 9));
			x11 = XOR(x11, ROTATE(PLUS(x7, x3), 13));
			x15 = XOR(x15, ROTATE(PLUS(x11, x7), 18));
			x1 = XOR(x1, ROTATE(PLUS(x0, x3), 7));
			x2 = XOR(x2, ROTATE(PLUS(x1, x0), 9));
			x3 = XOR(x3, ROTATE(PLUS(x2, x1), 13));
			x0 = XOR(x0, ROTATE(PLUS(x3, x2), 18));
			x6 = XOR(x6, ROTATE(PLUS(x5, x4), 7));
			x7 = XOR(x7, ROTATE(PLUS(x6, x5), 9));
			x4 = XOR(x4, ROTATE(PLUS(x7, x6), 13));
			x5 = XOR(x5, ROTATE(PLUS(x4, x7), 18));
			x11 = XOR(x11, ROTATE(PLUS(x10, x9), 7));
			x8 = XOR(x8, ROTATE(PLUS(x11, x10), 9));
			x9 = XOR(x9, ROTATE(PLUS(x8, x11), 13));
			x10 = XOR(x10, ROTATE(PLUS(x9, x8), 18));
			x12 = XOR(x12, ROTATE(PLUS(x15, x14), 7));
			x13 = XOR(x13, ROTATE(PLUS(x12, x15), 9));
			x14 = XOR(x14, ROTATE(PLUS(x13, x12), 13));
			x15 = XOR(x15, ROTATE(PLUS(x14, x13), 18));
		}
		x0 = PLUS(x0, x->j[0]);
		x1 = PLUS(x1, x->j[1]);
		x2 = PLUS(x2, x->j[2]);
		x3 = PLUS(x3, x->j[3]);
		x4 = PLUS(x4, x->j[4]);
		x5 = PLUS(x5, x->j[5]);
		x6 = PLUS(x6, x->j[6]);
		x7 = PLUS(x7, x->j[7]);
		x8 = PLUS(x8, x->j[8]);
		x9 = PLUS(x9, x->j[9]);
		x10 = PLUS(x10, x->j[10]);
		x11 = PLUS(x11, x->j[11]);
		x12 = PLUS(x12, x->j[12]);
		x13 = PLUS(x13, x->j[13]);
		x14 = PLUS(x14, x->j[14]);
		x15 = PLUS(x15, x->j[15]);

		x0 = XOR(x0, U8TO32_LITTLE(m + 0));
		x1 = XOR(x1, U8TO32_LITTLE(m + 4));
		x2 = XOR(x2, U8TO32_LITTLE(m + 8));
		x3 = XOR(x3, U8TO32_LITTLE(m + 12));
		x4 = XOR(x4, U8TO32_LITTLE(m + 16));
		x5 = XOR(x5, U8TO32_LITTLE(m + 20));
		x6 = XOR(x6, U8TO32_LITTLE(m + 24));
		x7 = XOR(x7, U8TO32_LITTLE(m + 28));
		x8 = XOR(x8, U8TO32_LITTLE(m + 32));
		x9 = XOR(x9, U8TO32_LITTLE(m + 36));
		x10 = XOR(x10, U8TO32_LITTLE(m + 40));
		x11 = XOR(x11, U8TO32_LITTLE(m + 44));
		x12 = XOR(x12, U8TO32_LITTLE(m + 48));
		x13 = XOR(x13, U8TO32_LITTLE(m + 52));
		x14 = XOR(x14, U8TO32_LITTLE(m + 56));
		x15 = XOR(x15, U8TO32_LITTLE(m + 60));

		x->j[8] = PLUSONE(x->j[8]);
		if (__predict_false(!x->j[8])) {
			x->j[9] = PLUSONE(x->j[9]);
			/*
			 * stopping at 2^70 bytes per nonce is user's
			 * responsibility
			 */
		}

		U32TO8_LITTLE(c + 0, x0);
		U32TO8_LITTLE(c + 4, x1);
		U32TO8_LITTLE(c + 8, x2);
		U32TO8_LITTLE(c + 12, x3);
		U32TO8_LITTLE(c + 16, x4);
		U32TO8_LITTLE(c + 20, x5);
		U32TO8_LITTLE(c + 24, x6);
		U32TO8_LITTLE(c + 28, x7);
		U32TO8_LITTLE(c + 32, x8);
		U32TO8_LITTLE(c + 36, x9);
		U32TO8_LITTLE(c + 40, x10);
		U32TO8_LITTLE(c + 44, x11);
		U32TO8_LITTLE(c + 48, x12);
		U32TO8_LITTLE(c + 52, x13);
		U32TO8_LITTLE(c + 56, x14);
		U32TO8_LITTLE(c + 60, x15);

		if (__predict_false(x->skip != 0)) {
			for (i = 0; i < bytes && i + x->skip < 64; ++i)
				ctarget[i] = c[i + x->skip];
			bytes -= i;
			if (!bytes) {
				x->skip = (x->skip + i) & 63;
				if (x->skip != 0) {
					if (x->j[8] == 0)
						x->j[9]--;
					x->j[8]--;
				}
				x->input[8] = x->j[8];
				x->input[9] = x->j[9];
				return;
			}
			m = msrc + i;
			c = ctarget + i;
			x->skip = 0;
		} else if (bytes <= 64) {
			if (bytes < 64) {
				for (i = 0; i < bytes; ++i)
					ctarget[i] = c[i];
				if (x->j[8] == 0)
					x->j[9]--;
				x->j[8]--;
				x->skip = bytes;
			}
			x->input[8] = x->j[8];
			x->input[9] = x->j[9];
			return;
		} else {
			bytes -= 64;
			c += 64;
			m += 64;
		}
	}
}
