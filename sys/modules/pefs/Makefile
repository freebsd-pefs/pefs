# $FreeBSD$

.PATH:	${.CURDIR}/../../fs/pefs
.PATH:	${.CURDIR}/../../crypto
.PATH:	${.CURDIR}/../../crypto/sha2
.PATH:	${.CURDIR}/../../crypto/hmac
.PATH:	${.CURDIR}/../../crypto/pbkdf2

KMOD=	pefs
SRCS=	vnode_if.h \
	pefs_subr.c pefs_vfsops.c pefs_vnops.c pefs_xbase64.c pefs_crypto.c \
	pefs_dircache.c \
	pefs_xts.c vmac.c \
	crypto_verify_bytes.c hmac_sha512.c sha512c.c

.if ${MACHINE_CPUARCH} == "i386" || ${MACHINE_CPUARCH} == "amd64"
SRCS+=	pefs_aesni.c
CFLAGS+= -DPEFS_AESNI
.endif

CFLAGS+= -I${.CURDIR}/../../

.include <bsd.kmod.mk>
