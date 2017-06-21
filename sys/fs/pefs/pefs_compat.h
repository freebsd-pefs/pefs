/*-
 * Copyright (c) 2016 Gleb Kurtsou <gleb@FreeBSD.org>
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
 * $FreeBSD$
 */


/*
 * Use PEFS_OSREL defines for backported changes.
 * Format:
 * PEFS_OSREL_<corresponding current version>_<name>
 */

#if P_OSREL_MAJOR(__FreeBSD_version) == 11
#if __FreeBSD_version >= 1100506
#define PEFS_OSREL_1200013_PAGE_SLEEP_XBUSY
#endif
#if __FreeBSD_version >= 1100509
#define PEFS_OSREL_1200013_CACHE_PURGEVFS
#endif
#if __FreeBSD_version >= 1100514
#define PEFS_OSREL_1200014_VM_PAGE_CACHE
#endif
#if __FreeBSD_version >= 1100510
#define PEFS_OSREL_1200020_M_STATFS
#endif
#endif

#if P_OSREL_MAJOR(__FreeBSD_version) == 10
#if __FreeBSD_version >= 1003510
#define PEFS_OSREL_1200013_PAGE_SLEEP_XBUSY
#endif
#endif
