/*-
 * Copyright (c) 2009 Gleb Kurtsou <gk@FreeBSD.org>
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
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/stat.h>
#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <db.h>
#include <fcntl.h>
#include <limits.h>
#include <sysexits.h>
#include <err.h>
#include <errno.h>

#include <fs/pefs/pefs.h>

#include "pefs_ctl.h"
#include "pefs_keychain.h"

#define KEYCHAIN_DBFILE			".pefs"

static DB *
keychain_dbopen(const char *filesystem, int kc_flags, int flags)
{
	char buf[MAXPATHLEN];
	DB *db;

	if (pefs_getfsroot(filesystem, buf, sizeof(buf)) != 0)
		return (NULL);
	strlcat(buf, "/", sizeof(buf));
	strlcat(buf, KEYCHAIN_DBFILE, sizeof(buf));
	db = dbopen(buf, flags | O_EXLOCK, S_IRUSR | S_IWUSR, DB_BTREE, NULL);
	if (db == NULL && (kc_flags & PEFS_KEYCHAIN_USE || errno != ENOENT))
		warn("keychain %s", buf);
	return (db);
}

void
pefs_keychain_free(struct pefs_keychain_head *kch)
{
	struct pefs_keychain *kc;

	if (kch == NULL)
		return;
	while ((kc = TAILQ_FIRST(kch)) != NULL) {
		TAILQ_REMOVE(kch, kc, kc_entry);
		bzero(kc, sizeof(struct pefs_keychain));
		free(kc);
	}
}

static int
pefs_keychain_get_db(DB *db, struct pefs_keychain_head *kch)
{
	struct pefs_keychain *kc_parent = NULL, *kc;
	struct pefs_xkeyenc ke;
	DBT db_key, db_data;
	int error;

	while (1) {
		kc_parent = TAILQ_LAST(kch, pefs_keychain_head);
		TAILQ_FOREACH(kc, kch, kc_entry) {
			if (kc != kc_parent &&
			    memcmp(kc->kc_key.pxk_keyid,
			    kc_parent->kc_key.pxk_keyid,
			    PEFS_KEYID_SIZE) == 0) {
				pefs_keychain_free(kch);
				errx(EX_DATAERR,
				    "keychain: loop detected: %016jx",
				    pefs_keyid_as_int(kc->kc_key.pxk_keyid));
			}
		}
		db_key.data = kc_parent->kc_key.pxk_keyid;
		db_key.size = PEFS_KEYID_SIZE;
		error = db->get(db, &db_key, &db_data, 0);
		if (error != 0) {
			if (error == -1)
				warn("keychain");
			if (TAILQ_FIRST(kch) != kc_parent)
				error = 0;
			break;
		}
		if (db_data.size != sizeof(struct pefs_xkeyenc))
			errx(EX_DATAERR, "keychain: db damaged");

		kc = calloc(1, sizeof(struct pefs_keychain));
		if (kc == NULL)
			err(EX_OSERR, "calloc");

		memcpy(&ke, db_data.data, sizeof(struct pefs_xkeyenc));
		error = pefs_key_decrypt(&ke, &kc_parent->kc_key);
		if (error)
			break;
		kc->kc_key = ke.a.ke_next;
		kc_parent->kc_key.pxk_alg = le32toh(ke.a.ke_alg);
		kc_parent->kc_key.pxk_keybits = le32toh(ke.a.ke_keybits);
		if (pefs_alg_name(&kc_parent->kc_key) == NULL)
			errx(EX_DATAERR, "keychain: db damaged");
		kc->kc_key.pxk_index = -1;
		kc->kc_key.pxk_alg = le32toh(kc->kc_key.pxk_alg);
		kc->kc_key.pxk_keybits = le32toh(kc->kc_key.pxk_keybits);

		if (kc->kc_key.pxk_alg == PEFS_ALG_INVALID ||
		    pefs_alg_name(&kc->kc_key) == NULL) {
			bzero(&kc->kc_key, sizeof(struct pefs_xkey));
			if (kc->kc_key.pxk_alg != PEFS_ALG_INVALID)
				warn("keychain %016jx -> %016jx: invalid algorithm (decyption failed)",
				    pefs_keyid_as_int(
				    kc_parent->kc_key.pxk_keyid),
				    pefs_keyid_as_int(kc->kc_key.pxk_keyid));
			free(kc);
			break;
		}
		TAILQ_INSERT_TAIL(kch, kc, kc_entry);
	}

	return (error);
}

int
pefs_keychain_get(struct pefs_keychain_head *kch, const char *filesystem,
    int flags, struct pefs_xkey *xk)
{
	struct pefs_keychain *kc;
	DB *db;
	int error;

	assert(filesystem != NULL && kch != NULL && xk != NULL);

	TAILQ_INIT(kch);

	kc = calloc(1, sizeof(struct pefs_keychain));
	if (kc == NULL)
		err(EX_OSERR, "calloc");
	kc->kc_key = *xk;
	TAILQ_INSERT_HEAD(kch, kc, kc_entry);

	if (flags == 0)
		return (0);

	db = keychain_dbopen(filesystem, flags, O_RDONLY);
	if (db == NULL) {
		if (flags & PEFS_KEYCHAIN_IGNORE_MISSING)
			return (0);
		return (ENOENT);
	}

	error = pefs_keychain_get_db(db, kch);

	db->close(db);

	if (error) {
		if (flags & PEFS_KEYCHAIN_USE)
			errx(EX_DATAERR, "keychain: Key not found %016jx",
			    pefs_keyid_as_int(xk->pxk_keyid));
	}

	return (0);
}

int
pefs_keychain_set(const char *filesystem, struct pefs_xkey *xk,
    struct pefs_xkey *xknext)
{
	struct pefs_xkeyenc ke;
	DBT db_key, db_data;
	DB *db;
	int error;

	ke.a.ke_next = *xknext;
	ke.a.ke_next.pxk_index = (uint32_t)random();
	ke.a.ke_next.pxk_alg = htole32(ke.a.ke_next.pxk_alg);
	ke.a.ke_next.pxk_keybits = htole32(ke.a.ke_next.pxk_keybits);
	ke.a.ke_alg = htole32(xk->pxk_alg);
	ke.a.ke_keybits = htole32(xk->pxk_keybits);
	if (pefs_key_encrypt(&ke, xk) != 0)
		return (-1);

	db = keychain_dbopen(filesystem, PEFS_KEYCHAIN_USE, O_RDWR | O_CREAT);
	if (db == NULL)
		return (-1);

	db_data.data = &ke;
	db_data.size = sizeof(struct pefs_xkeyenc);
	db_key.data = xk->pxk_keyid;
	db_key.size = PEFS_KEYID_SIZE;
	error = db->put(db, &db_key, &db_data, R_NOOVERWRITE);
	bzero(&ke, sizeof(struct pefs_xkeyenc));
	if (error != 0) {
		if (error == -1)
			warn("keychain");
		else
			warnx("keychain: cannot set key chain %016jx",
			    pefs_keyid_as_int(xk->pxk_keyid));
	}
	db->close(db);

	return (error ? -1 : 0);
}

int
pefs_keychain_del(const char *filesystem, struct pefs_xkey *xk)
{
	DBT db_key;
	DB *db;
	int error;

	db = keychain_dbopen(filesystem, PEFS_KEYCHAIN_USE, O_RDWR | O_CREAT);
	if (db == NULL)
		return (-1);
	db_key.data = xk->pxk_keyid;
	db_key.size = PEFS_KEYID_SIZE;
	error = db->del(db, &db_key, 0);
	if (error != 0) {
		if (error == -1)
			warn("keychain");
		else
			warnx("keychain: cannot delete key chain %016jx",
			    pefs_keyid_as_int(xk->pxk_keyid));
	}
	db->close(db);

	return (error ? -1 : 0);
}

