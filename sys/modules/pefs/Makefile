# $FreeBSD$

.PATH:	${.CURDIR}/../../fs/pefs

KMOD=	pefs
SRCS=	vnode_if.h \
	pefs_subr.c pefs_vfsops.c pefs_vnops.c pefs_xbase64.c pefs_crypto.c \
	pefs_dircache.c \
	vmac.c
DEBUG_FLAGS+= -g
#DEBUG_FLAGS+= -DPEFS_DEBUG
#DEBUG_FLAGS+= -DPEFS_DEBUG_EXTRA

.include <bsd.kmod.mk>

