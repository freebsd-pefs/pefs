# PAM module for pefs
# $FreeBSD$

SYS=		${.CURDIR}/../../../../sys
PEFSDIR=	${.CURDIR}/../../../../sbin/pefs

LIB=	pam_pefs
MAN=	pam_pefs.8
SRCS=	pam_pefs.c
SRCS+=	pefs_key.c pefs_keychain.c pefs_subr.c
SRCS+=	hmac_sha512.c pkcs5v2.c sha2.c
SRCS+=	rijndael-api.c rijndael-api-fst.c rijndael-alg-fst.c

CFLAGS+= -I${PEFSDIR}
CFLAGS+= -I${SYS}

DPADD= ${LIBUTIL}
LDADD= -lutil

.include <bsd.lib.mk>

.PATH: ${PEFSDIR}
.PATH: ${SYS}/geom/eli
.PATH: ${SYS}/crypto/hmac ${SYS}/crypto/sha2 ${SYS}/crypto/rijndael
