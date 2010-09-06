# $FreeBSD$

.PATH:	${.CURDIR}/../../fs/pefs

KMOD=	pefs
SRCS=	vnode_if.h \
	pefs_subr.c pefs_vfsops.c pefs_vnops.c pefs_xbase64.c pefs_crypto.c \
	pefs_dircache.c \
	pefs_xts.c vmac.c
DEBUG_FLAGS+= -g
#DEBUG_FLAGS+= -DPEFS_DEBUG
#DEBUG_FLAGS+= -DPEFS_DEBUG_EXTRA

CFLAGS+= -I${.CURDIR}/../../

# Temporally build crypto/hmac into pefs module
.PATH:	${.CURDIR}/../../crypto/hmac

SRCS+=	hmac_sha512.c

.include <bsd.kmod.mk>

