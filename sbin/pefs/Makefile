# $FreeBSD$

SYS=	${.CURDIR}/../../sys
.PATH:	${SYS}/fs/pefs
.PATH:	${SYS}/crypto
.PATH:	${SYS}/crypto/rijndael
.PATH:	${SYS}/crypto/hmac ${SYS}/crypto/pbkdf2 ${SYS}/crypto/sha2

PROG=	pefs
SRCS=	pefs_ctl.c pefs_key.c pefs_keychain.c pefs_subr.c
SRCS+=	rijndael-api.c rijndael-api-fst.c rijndael-alg-fst.c
SRCS+=	sha512c.c
SRCS+=	hmac_sha512.c
SRCS+=	pbkdf2_hmac_sha512.c
SRCS+=	crypto_verify_bytes.c

MAN=	pefs.8

CFLAGS+=-I${SYS}
WARNS?=	2

DPADD=  ${LIBUTIL}
LDADD=  -lutil

BINDIR?= /sbin
.include <bsd.prog.mk>
