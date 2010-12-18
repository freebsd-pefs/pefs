# $FreeBSD$

SYS=	${.CURDIR}/../../sys
.PATH:	${SYS}/geom/eli
.PATH:	${SYS}/crypto/hmac ${SYS}/crypto/rijndael ${SYS}/crypto/sha2

PROG=	pefs
SRCS=	pefs_ctl.c pefs_key.c pefs_keychain.c pefs_subr.c
SRCS+=	hmac_sha512.c sha2.c
SRCS+=	rijndael-api.c rijndael-api-fst.c rijndael-alg-fst.c
SRCS+=	pkcs5v2.c

MAN=	pefs.8

CFLAGS+=-I${SYS}
WARNS?=	6
DEBUG_FLAGS+= -g

DPADD=  ${LIBUTIL}
LDADD=  -lutil

BINDIR?= /sbin

.include <bsd.prog.mk>
