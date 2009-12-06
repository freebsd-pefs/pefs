SUBDIR=	sys/modules/pefs \
	sbin/pefs

# Should be built from sources tree
# SUBDIR+= lib/libpam/modules/pam_pefs

.include <bsd.subdir.mk>
