# Include Makefiles from $SRCDIR

LIBDIR=${PREFIX}/lib

SYSDIR?=	/usr/src/sys

.include <${SYSDIR}/../lib/libpam/modules/Makefile.inc>
