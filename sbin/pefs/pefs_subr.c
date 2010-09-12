/*-
 * Copyright (c) 2009 Gleb Kurtsou
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/ioccom.h>
#include <sys/module.h>
#include <sys/mount.h>

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <fs/pefs/pefs.h>

#include "pefs_ctl.h"

int
pefs_getfsroot(const char *path, int flags, char *fsroot, size_t size)
{
	struct statfs fs;
	const char *realfsroot;

	if (statfs(path, &fs) == -1) {
		pefs_warn("statfs failed: %s: %s", path, strerror(errno));
		return (PEFS_ERR_SYS);
	}

	realfsroot = fs.f_mntonname;
	if (strcmp(PEFS_FSTYPE, fs.f_fstypename) != 0) {
		if ((flags & PEFS_FS_IGNORE_TYPE) != 0)
			realfsroot = path;
		else {
			pefs_warn("invalid filesystem type: %s", path);
			return (PEFS_ERR_INVALID);
		}
	}

	if (fsroot != NULL)
		strlcpy(fsroot, realfsroot, size);

	return (0);
}
