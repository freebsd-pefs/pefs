# $FreeBSD$

SYS=	${.CURDIR}/../../sys
.PATH:	${SYS}/geom/eli ${SYS}/crypto/hmac ${SYS}/crypto/sha2

PROG=	pefs
SRCS=	pefs_ctl.c pefs_key.c pefs_keychain.c
SRCS+=	hmac_sha512.c sha2.c
SRCS+=	pkcs5v2.c

MAN=	pefs.8

CFLAGS+=-I${SYS}
WARNS?=	6
DEBUG_FLAGS+= -g

DPADD=  ${LIBCRYPTO} ${LIBUTIL}
LDADD=  -lcrypto -lutil

.include <bsd.prog.mk>
