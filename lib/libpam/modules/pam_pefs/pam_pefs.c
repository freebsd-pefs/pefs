/*-
 * Copyright (c) 2003 Networks Associates Technology, Inc.
 * Copyright (c) 2009 Gleb Kurtsou <gleb@FreeBSD.org>
 * Copyright (c) 2011,2015 David Naylor <dbn@FreeBSD.org>
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by ThinkSec AS and
 * NAI Labs, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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
#include <sys/ipc.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <libutil.h>
#include <paths.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#define	PAM_SM_AUTH
#define	PAM_SM_SESSION

#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_mod_misc.h>
#include <security/openpam.h>

#include <fs/pefs/pefs.h>

#include "pefs_ctl.h"
#include "pefs_keychain.h"

#define	PEFS_OPT_IGNORE_MISSING		"ignore_missing"
#define	PEFS_OPT_DELKEYS		"delkeys"
#define	PEFS_OPT_USE_SHM		"use_shm"

#define	PAM_PEFS_KEYS			"pam_pefs_keys"
#define	PAM_PEFS_SESSION		"pam_pefs_session"
#define	PAM_PEFS_SHMID			"pam_pefs_shmid"

#define	PEFS_SESSION_SIZE		16
#define	PEFS_SESSION_DIR		"/var/run/pefs"
#define	PEFS_SESSION_DIR_MODE		0700
#define	PEFS_SESSION_FILE_MODE		0600
#define	PEFS_SESSION_FILE_FLAGS		\
	(O_RDWR | O_NONBLOCK | O_CREAT | O_EXLOCK)

static int pam_pefs_debug;
static int pam_pefs_use_shm;

void
pefs_warn(const char *fmt, ...)
{
	static const char *label = "pam_pefs: ";
	char buf[BUFSIZ];
        va_list ap;

	if (pam_pefs_debug == 0)
		return;

        va_start(ap, fmt);
	if (strlen(fmt) + sizeof(label) >= sizeof(buf)) {
		vsyslog(LOG_DEBUG, fmt, ap);
	} else {
		strlcpy(buf, label, sizeof(buf));
		strlcat(buf, fmt, sizeof(buf));
		vsyslog(LOG_DEBUG, buf, ap);
	}
        va_end(ap);
}

static int
flopen_retry(const char *filename)
{
	int fd, try;

	for (try = 1; try <= 1024; try *= 2) {
		fd = flopen(filename, PEFS_SESSION_FILE_FLAGS,
		    PEFS_SESSION_FILE_MODE);
		if (fd != -1)
			return (fd);
		else if (errno != EWOULDBLOCK)
			return (-1);
		// Exponential back-off up to 1 second
		usleep(try * 1000000 / 1024);
	}
	errno = ETIMEDOUT;
	return (-1);
}

static bool
session_ctr_empty(const uint8_t *sc)
{
	const uint8_t *end;
	uint8_t acc;

	for (end = sc + PEFS_SESSION_SIZE, acc = 0; sc < end; sc++)
		acc |= *sc;
	return (acc == 0);
}

static void
session_ctr_xor(uint8_t *sc, const uint8_t *si)
{
	int i;

	for (i = 0; i < PEFS_SESSION_SIZE; sc++, si++, i++)
		*sc ^= *si;
}

static int
session_ctr_update(const char *user, const char *sess_id, bool incr)
{
	struct stat sb;
	struct timespec tp_uptime, tp_now;
	ssize_t sess_size;
	int fd;
	char filename[MAXPATHLEN];
	uint8_t sess_ctr[PEFS_SESSION_SIZE];

	if (session_ctr_empty(sess_id))
		return (-1);

	snprintf(filename, sizeof(filename), "%s/%s", PEFS_SESSION_DIR, user);

	if (lstat(PEFS_SESSION_DIR, &sb) == -1) {
		if (errno != ENOENT) {
			pefs_warn("unable to access session directory %s: %s",
			    PEFS_SESSION_DIR, strerror(errno));
			return (-1);
		}
		if (mkdir(PEFS_SESSION_DIR, PEFS_SESSION_DIR_MODE) == -1) {
			pefs_warn("unable to create session directory %s: %s",
			    PEFS_SESSION_DIR, strerror(errno));
			return (-1);
		}
	} else if (!S_ISDIR(sb.st_mode)) {
		pefs_warn("%s is not a directory", PEFS_SESSION_DIR);
		return (-1);
	}

	if ((fd = flopen_retry(filename)) == -1) {
		pefs_warn("unable to create session counter file %s: %s",
		    filename, strerror(errno));
		return (-1);
	}

	if ((sess_size = pread(fd, sess_ctr, PEFS_SESSION_SIZE, 0)) == -1) {
		pefs_warn("unable to read from the session counter file %s: %s",
		    filename, strerror(errno));
		close(fd);
		return (-1);
	}
	lseek(fd, 0L, SEEK_SET);
	if (sess_size != PEFS_SESSION_SIZE) {
		if (sess_size != 0) {
			pefs_warn("invalid session counter file size: %s: %zd",
			    filename, sess_size);
		}
		memset(sess_ctr, 0, PEFS_SESSION_SIZE);
		ftruncate(fd, PEFS_SESSION_SIZE);
	}

	/*
	 * Determine if this is the first increment of the session file.
	 *
	 * It is considered the first increment if the session file has not
	 * been modified since the last boot time.
	 */
	if (incr && !session_ctr_empty(sess_ctr)) {
		if (fstat(fd, &sb) == -1) {
			pefs_warn("unable to access session counter file %s: %s",
			    filename, strerror(errno));
			close(fd);
			return (-1);
		}
		/*
		 * Check is messy and will fail if wall clock isn't monotonical
		 * (e.g. because of ntp, DST, leap seconds)
		 */
		clock_gettime(CLOCK_REALTIME_FAST, &tp_now);
		clock_gettime(CLOCK_UPTIME_FAST, &tp_uptime);
		if (sb.st_mtime < tp_now.tv_sec - tp_uptime.tv_sec) {
			pefs_warn("stale session counter file: %s",
			    filename);
			memset(sess_ctr, 0, PEFS_SESSION_SIZE);
		}
	}

	session_ctr_xor(sess_ctr, sess_id);
	if (incr && session_ctr_empty(sess_ctr)) {
		pefs_warn("corrupted session counter file after increment: %s",
		    filename);
		close(fd);
		return (-1);
	}
	pwrite(fd, sess_ctr, PEFS_SESSION_SIZE, 0);
	close(fd);

	return (session_ctr_empty(sess_ctr) ? 0 : 1);
}

static int
session_ctr_incr(pam_handle_t *pamh, const char *user)
{
	uint8_t *id;
	int r;

	id = malloc(PEFS_SESSION_SIZE);
	if (id == NULL)
		return (-1);
	arc4random_buf(id, PEFS_SESSION_SIZE);
	if (session_ctr_empty(id))
		arc4random_buf(id, PEFS_SESSION_SIZE);
	r = pam_set_data(pamh, PAM_PEFS_SESSION, id, openpam_free_data);
	if (r != PAM_SUCCESS) {
		free(id);
		return (-1);
	}
	r = session_ctr_update(user, id, true);
	if (r == -1) {
		/* Make consequent session_ctr_decr no-op. */
		memset(id, 0, PEFS_SESSION_SIZE);
	}
	return (r);
}

static int
session_ctr_decr(pam_handle_t *pamh, const char *user)
{
	const uint8_t *id;
	int r;

	r = pam_get_data(pamh, PAM_PEFS_SESSION, (const void **)(void *)&id);
	if (r != PAM_SUCCESS)
		return (-1);
	r = session_ctr_update(user, id, false);
	pam_set_data(pamh, PAM_PEFS_SESSION, NULL, NULL);
	return (r);
}

static int
pam_pefs_checkfs(const char *homedir)
{
	char fsroot[MAXPATHLEN];
	char abshomedir[MAXPATHLEN];

	if (realpath(homedir, abshomedir) == NULL) {
		pefs_warn("unable to resulve home dir: %s", homedir);
		return (PAM_USER_UNKNOWN);
	}
	if (pefs_getfsroot(abshomedir, 0, fsroot, sizeof(fsroot)) != 0) {
		pefs_warn("file system is not mounted: %s", abshomedir);
		return (PAM_USER_UNKNOWN);
	}
	if (strcmp(fsroot, abshomedir) != 0) {
		pefs_warn("file system is not mounted on home dir: %s", fsroot);
		return (PAM_USER_UNKNOWN);
	}

	return (PAM_SUCCESS);
}

/*
 * Perform key lookup in ~/.pefs;
 * returns PAM_AUTH_ERR if and only if key wasn't found in database.
 */
static int
pam_pefs_getkeys(struct pefs_keychain_head *kch,
    const char *homedir, const char *passphrase, int chainflags)
{
	struct pefs_xkey k;
	struct pefs_keyparam kp;
	int error;

	pefs_keyparam_create(&kp);
	pefs_keyparam_init(&kp, homedir);

	error = pefs_key_generate(&k, passphrase, &kp);
	if (error != 0)
		return (PAM_SERVICE_ERR);

	error = pefs_keychain_get(kch, homedir, chainflags, &k);
	bzero(&k, sizeof(k));
	if (error != 0)
		return (error == PEFS_ERR_NOENT ? PAM_AUTH_ERR :
		    PAM_SERVICE_ERR);

	return (PAM_SUCCESS);
}

static int
pam_pefs_addkeys(const char *homedir, struct pefs_keychain_head *kch)
{
	struct pefs_keychain *kc;
	int fd;

	fd = open(homedir, O_RDONLY);
	if (fd == -1) {
		pefs_warn("cannot open homedir %s: %s",
		    homedir, strerror(errno));
		return (PAM_USER_UNKNOWN);
	}

	TAILQ_FOREACH(kc, kch, kc_entry) {
		if (ioctl(fd, PEFS_ADDKEY, &kc->kc_key) == -1) {
			pefs_warn("cannot add key: %s: %s",
			    homedir, strerror(errno));
			break;
		}
	}
	close(fd);

	return (PAM_SUCCESS);
}

static int
pam_pefs_delkeys(const char *homedir)
{
	struct pefs_xkey k;
	int fd;

	fd = open(homedir, O_RDONLY);
	if (fd == -1) {
		pefs_warn("cannot open homedir %s: %s",
		    homedir, strerror(errno));
		return (PAM_USER_UNKNOWN);
	}

	bzero(&k, sizeof(k));
	while (1) {
		if (ioctl(fd, PEFS_GETKEY, &k) == -1)
			break;

		if (ioctl(fd, PEFS_DELKEY, &k) == -1) {
			pefs_warn("cannot del key: %s: %s",
			    homedir, strerror(errno));
			k.pxk_index++;
		}
	}
	close(fd);

	return (PAM_SUCCESS);
}

static void
pam_pefs_freekeys(pam_handle_t *pamh __unused, void *data, int pam_err __unused)
{
	struct pefs_keychain_head *kch = data;

	pefs_keychain_free(kch);
	free(kch);
}

static void
pam_pefs_store_key(pam_handle_t *pamh, struct pefs_keychain_head *kch)
{
	struct pefs_keychain *kc;
	struct pefs_xkey *shmkey;
	size_t shmsize;
	int keycnt, shmid;
	char *id_hex;
	void *shmdata;
	if (!pam_pefs_use_shm)
		pam_set_data(pamh, PAM_PEFS_KEYS, kch, pam_pefs_freekeys);
	else {
		keycnt = 0;
		TAILQ_FOREACH(kc, kch, kc_entry)
			keycnt++;
		shmsize = sizeof(int) + (sizeof(*shmkey) * keycnt);

		if ((shmid = shmget(IPC_PRIVATE, shmsize, SHM_R | SHM_W)) > 0
		    && (shmdata = shmat(shmid, 0, 0)) != (void *)-1
		    && (id_hex = calloc(1, sizeof(int) * 2 + 3)) != NULL) {
			sprintf(id_hex, "%#.*x", (int)(sizeof(int) * 2), shmid);
			pam_setenv(pamh, PAM_PEFS_KEYS, id_hex, 1);
			free(id_hex);
			*(int *)shmdata = keycnt;
			shmkey = shmdata + sizeof(keycnt);
			TAILQ_FOREACH(kc, kch, kc_entry)
				memcpy(shmkey++, &(kc->kc_key), sizeof(*shmkey));
		}
		else
			pefs_warn("failed to allocate shared memory for key");

		if (shmdata != (void *)-1)
			shmdt(shmdata);

		pefs_keychain_free(kch);
		free(kch);
	}
}

static int
pam_pefs_retrieve_key(pam_handle_t *pamh, struct pefs_keychain_head **kch)
{
	struct pefs_keychain *kc;
	struct pefs_xkey *shmkey;
	int keycnt, shmid, status;
	const char *id_hex;
	void *shmdata;

	if (!pam_pefs_use_shm)
		status = pam_get_data(pamh, PAM_PEFS_KEYS, (const void **)kch);
	else {
		status = PAM_SYSTEM_ERR;
		if ((id_hex = pam_getenv(pamh, PAM_PEFS_KEYS)) != NULL
		    && (shmid = strtol(id_hex, NULL, 16)) > 0
		    && (shmdata = shmat(shmid, 0, 0)) != (void *)-1
		    && (*kch = calloc(1, sizeof(**kch))) != NULL) {
			status = PAM_SUCCESS;
			TAILQ_INIT(*kch);
			shmkey = shmdata + sizeof(keycnt);
			for (keycnt = *(int *)shmdata; keycnt; keycnt--) {
				if ((kc = calloc(1, sizeof(*kc))) == NULL) {
					while (!TAILQ_EMPTY(*kch)) {
						kc = TAILQ_FIRST(*kch);
						TAILQ_REMOVE(*kch, kc, kc_entry);
						free(kc);
					}

					free(*kch);
					*kch = NULL;
					status = PAM_SYSTEM_ERR;
					break;
				}

				memcpy(&(kc->kc_key), shmkey++, sizeof(*shmkey));
				TAILQ_INSERT_HEAD(*kch, kc, kc_entry);
			}
		}

		if (status != PAM_SUCCESS)
			pefs_warn("failed to retrieve key from shared memory");

		if (shmdata != (void *)-1)
			shmdt(shmdata);
	}

	return status;
}

static void
pam_pefs_release_key(pam_handle_t *pamh, struct pefs_keychain_head *kch)
{
	size_t shmsize;
	int keycnt, shmid;
	const char *id_hex;
	void *shmdata;

	if (!pam_pefs_use_shm)
		pam_set_data(pamh, PAM_PEFS_KEYS, NULL, NULL);
	else {
		if ((id_hex = pam_getenv(pamh, PAM_PEFS_KEYS)) != NULL
		    && (shmid = strtol(id_hex, NULL, 16)) > 0
		    && (shmdata = shmat(shmid, 0, 0)) != (void *)-1) {
			keycnt = *(int *)shmdata;
			shmsize = sizeof(keycnt)
			    + (sizeof(struct pefs_xkey) * keycnt);
			memset(shmdata, 0, shmsize);
			shmdt(shmdata);
		}
		else
			pefs_warn("failed to release shared memory for key");

		if (shmid > 0)
			shmctl(shmid, IPC_RMID, NULL);
		if (id_hex != NULL)
			pam_setenv(pamh, PAM_PEFS_KEYS, "", 1);
		if (kch != NULL) {
			pefs_keychain_free(kch);
			free(kch);
		}
	}
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	struct pefs_keychain_head *kch;
	struct passwd *pwd;
	const char *passphrase, *user;
	const void *item;
	int pam_err, canretry, chainflags;

	/* Get user name and home directory */
	pam_err = pam_get_user(pamh, &user, NULL);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);
	pwd = getpwnam(user);
	if (pwd == NULL)
		return (PAM_USER_UNKNOWN);
	if (pwd->pw_dir == NULL)
		return (PAM_AUTH_ERR);

	pam_pefs_debug = (openpam_get_option(pamh, PAM_OPT_DEBUG) != NULL);
	pam_pefs_use_shm = (openpam_get_option(pamh, PEFS_OPT_USE_SHM) != NULL);

	chainflags = PEFS_KEYCHAIN_USE;
	if (openpam_get_option(pamh, PEFS_OPT_IGNORE_MISSING) != NULL)
		chainflags = PEFS_KEYCHAIN_IGNORE_MISSING;

	canretry = (pam_get_item(pamh, PAM_AUTHTOK, &item) == PAM_SUCCESS &&
	    item != NULL && chainflags != PEFS_KEYCHAIN_IGNORE_MISSING);

	pam_err = openpam_borrow_cred(pamh, pwd);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);

	/*
	 * Check to see if the passwd db is available, avoids asking for
	 * password if we cannot even validate it.
	 */
	pam_err = pam_pefs_checkfs(pwd->pw_dir);
	openpam_restore_cred(pamh);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);


retry:
	/* Get passphrase */
	pam_err = pam_get_authtok(pamh, PAM_AUTHTOK,
	    &passphrase, NULL);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);

	if (*passphrase != '\0') {
		kch = calloc(1, sizeof(*kch));
		if (kch == NULL)
			return (PAM_SYSTEM_ERR);

		/* Switch to user credentials */
		pam_err = openpam_borrow_cred(pamh, pwd);
		if (pam_err != PAM_SUCCESS)
			return (pam_err);

		pam_err = pam_pefs_getkeys(kch, pwd->pw_dir, passphrase,
		    chainflags);
		if (pam_err == PAM_SUCCESS)
			pam_pefs_store_key(pamh, kch);
		else
			free(kch);

		/* Switch back to arbitrator credentials */
		openpam_restore_cred(pamh);
	} else
		pam_err = PAM_AUTH_ERR;

	/*
	 * If we tried an old token and didn't get anything, and
	 * try_first_pass was specified, try again after prompting the
	 * user for a new passphrase.
	 */
	if (pam_err == PAM_AUTH_ERR && canretry != 0 &&
	    openpam_get_option(pamh, "try_first_pass") != NULL) {
		pam_set_item(pamh, PAM_AUTHTOK, NULL);
		canretry = 0;
		goto retry;
	}

	return (pam_err);
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	struct pefs_keychain_head *kch = NULL;
	struct passwd *pwd;
	const char *user;
	int pam_err, opt_delkeys;

	pam_err = pam_get_user(pamh, &user, NULL);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);
	pwd = getpwnam(user);
	if (pwd == NULL)
		return (PAM_USER_UNKNOWN);
	if (pwd->pw_dir == NULL)
		return (PAM_SYSTEM_ERR);

	pam_pefs_debug = (openpam_get_option(pamh, PAM_OPT_DEBUG) != NULL);
	pam_pefs_use_shm = (openpam_get_option(pamh, PEFS_OPT_USE_SHM) != NULL);
	opt_delkeys = (openpam_get_option(pamh, PEFS_OPT_DELKEYS) != NULL);

	pam_err = pam_pefs_retrieve_key(pamh, &kch);
	if (pam_err != PAM_SUCCESS || kch == NULL || TAILQ_EMPTY(kch)) {
		pam_err = PAM_SUCCESS;
		opt_delkeys = 0;
		goto out;
	}

	/* Switch to user credentials */
	pam_err = openpam_borrow_cred(pamh, pwd);
	if (pam_err != PAM_SUCCESS)
		goto out;

	pam_err = pam_pefs_checkfs(pwd->pw_dir);
	if (pam_err != PAM_SUCCESS) {
		openpam_restore_cred(pamh);
		pam_err = PAM_SUCCESS;
		opt_delkeys = 0;
		goto out;
	}

	pam_err = pam_pefs_addkeys(pwd->pw_dir, kch);

	/* Switch back to arbitrator credentials */
	openpam_restore_cred(pamh);

out:
	/* Remove keys from memory */
	pam_pefs_release_key(pamh, kch);

	/* Increment login count */
	if (pam_err == PAM_SUCCESS && opt_delkeys) {
		session_ctr_incr(pamh, user);
	}

	return (pam_err);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	struct passwd *pwd;
	const char *user;
	int pam_err, opt_delkeys;

	pam_err = pam_get_user(pamh, &user, NULL);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);

	pwd = getpwnam(user);
	if (pwd == NULL)
		return (PAM_USER_UNKNOWN);
	if (pwd->pw_dir == NULL)
		return (PAM_SYSTEM_ERR);

	pam_pefs_debug = (openpam_get_option(pamh, PAM_OPT_DEBUG) != NULL);
	opt_delkeys = (openpam_get_option(pamh, PEFS_OPT_DELKEYS) != NULL);
	if (!opt_delkeys)
		return PAM_SUCCESS;

	pam_err = openpam_borrow_cred(pamh, pwd);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);
	pam_err = pam_pefs_checkfs(pwd->pw_dir);
	openpam_restore_cred(pamh);
	if (pam_err != PAM_SUCCESS)
		return (PAM_SUCCESS);

	/* Decrease login count and remove keys if at zero */
	pam_err = PAM_SUCCESS;
	if (session_ctr_decr(pamh, user) == 0) {
		pam_err = openpam_borrow_cred(pamh, pwd);
		if (pam_err != PAM_SUCCESS)
			return (pam_err);
		pam_err = pam_pefs_delkeys(pwd->pw_dir);
		openpam_restore_cred(pamh);
	}

	return (pam_err);
}

PAM_MODULE_ENTRY("pam_pefs");
