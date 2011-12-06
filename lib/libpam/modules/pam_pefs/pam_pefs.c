/*-
 * Copyright (c) 2003 Networks Associates Technology, Inc.
 * Copyright (c) 2009 Gleb Kurtsou
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
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
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

#define	PAM_PEFS_OPT_IGNORE_MISSING	"ignore_missing"
#define	PAM_PEFS_KEYS			"pam_pefs_keys"

#define PEFS_OPT_DELKEYS		"delkeys"

#define PEFS_SESSION_DIR 		"/var/run/pefs"
#define PEFS_SESSION_DIR_MODE		0700
#define PEFS_SESSION_FILE_MODE		0600

static int pam_pefs_debug;

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

static FILE*
fopen_retry(const char *filename, const int flags, const char *mode)
{
	int fd, try;

	for (try = 1; try <= 1024; try *= 2) {
		if (flags & O_CREAT)
			fd = open(filename, flags, PEFS_SESSION_FILE_MODE);
		else
			fd = open(filename, flags);
		if (fd > 0)
			return fdopen(fd, mode);
		else if (!(errno == EWOULDBLOCK || errno == EAGAIN))
			return NULL;
		// Exponential back-off up to 1 second
		usleep(try * 1000000 / 1024);
	}
	return (NULL);
}

static int
pefs_session_count_incr(const char *user, const bool incr,
			const bool first_mount)
{
	FILE *fd;
	struct stat sb;
	int total = 0;
	char filename[MAXPATHLEN + 1];

	snprintf(filename, MAXPATHLEN, "%s/%s", PEFS_SESSION_DIR, user);

	if (stat(PEFS_SESSION_DIR, &sb) == -1)
		if (mkdir(PEFS_SESSION_DIR, PEFS_SESSION_DIR_MODE)) {
			pefs_warn("unable to create session directory %s: %s",
				  PEFS_SESSION_DIR, strerror(errno));
			return -1;
		}
	else if (!S_ISDIR(sb.st_mode)) {
		pefs_warn("%s is not a directory", dirname(filename));
		return (-1);
	}

	if (stat(filename, &sb) == -1) {
		/* File does not exist and needs to be created */
		if ((fd = fopen_retry(filename, O_WRONLY | O_CREAT |
				O_NONBLOCK | O_EXLOCK, "w")) == NULL) {
			pefs_warn("unable to create session counter file %s: %s",
				  filename, strerror(errno));
			return (-1);
		}
		if (!first_mount)
			pefs_warn("unexpected missing session counter file: %s",
				  filename);
	} else {
		/* File exists and contains previous total */
		if ((fd = fopen_retry(filename, O_RDWR | O_NONBLOCK | O_EXLOCK,
				"r+")) == NULL) {
			pefs_warn("unable to open session counter file %s: %s",
				  filename, strerror(errno));
			return (-1);
		}

		fscanf(fd, "%i", &total);
		rewind(fd);
		ftruncate(fileno(fd), 0L);

		if ((total == 0) ^ first_mount) {
			if (first_mount)
				total = 0;
			pefs_warn("stale session counter file: %s", filename);
		}
	}

	pefs_warn("%s: session count %i%s%i", user, total, incr > 0 ? "+" : "",
		  (incr ? 1 : -1));
	total += incr ? 1 : -1;
	if (total < 0) {
		pefs_warn("corrupted session counter file: %s", filename);
	} else
		fprintf(fd, "%i", total);
	fclose(fd);

	return (total);
}

static int
pam_pefs_getfsroot(const char *homedir)
{
	char fsroot[MAXPATHLEN];
	int error;

	error = pefs_getfsroot(homedir, 0, fsroot, sizeof(fsroot));
	if (error != 0) {
		pefs_warn("file system is not mounted: %s", homedir);
		return (PAM_USER_UNKNOWN);
	} if (strcmp(fsroot, homedir) != 0) {
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

static void
pam_pefs_freekeys(pam_handle_t *pamh __unused, void *data, int pam_err __unused)
{
	struct pefs_keychain_head *kch = data;

	pefs_keychain_free(kch);
	free(kch);
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

	chainflags = PEFS_KEYCHAIN_USE;
	if (openpam_get_option(pamh, PAM_PEFS_OPT_IGNORE_MISSING) != NULL)
		chainflags = PEFS_KEYCHAIN_IGNORE_MISSING;

	canretry = (pam_get_item(pamh, PAM_AUTHTOK, &item) == PAM_SUCCESS &&
	    item != NULL && chainflags != PEFS_KEYCHAIN_IGNORE_MISSING);

	/* Switch to user credentials */
	pam_err = openpam_borrow_cred(pamh, pwd);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);

	/*
	 * Check to see if the passwd db is available, avoids asking for
	 * password if we cannot even validate it.
	 */
	pam_err = pam_pefs_getfsroot(pwd->pw_dir);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);

	/* Switch back to arbitrator credentials */
	openpam_restore_cred(pamh);

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
			pam_set_data(pamh, PAM_PEFS_KEYS, kch,
			    pam_pefs_freekeys);
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
	struct pefs_keychain_head *kch;
	struct pefs_keychain *kc;
	struct passwd *pwd;
	const char *user;
	int fd, pam_err, pam_pefs_delkeys;
	bool good_key = true;

	pam_pefs_debug = 1;

	pam_err = pam_get_data(pamh, PAM_PEFS_KEYS, (const void **)&kch);
	if (pam_err != PAM_SUCCESS || kch == NULL || TAILQ_EMPTY(kch))
		return (PAM_SUCCESS);

	pam_err = pam_get_user(pamh, &user, NULL);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);
	pwd = getpwnam(user);
	if (pwd == NULL)
		return (PAM_USER_UNKNOWN);
	if (pwd->pw_dir == NULL)
		return (PAM_SYSTEM_ERR);

	pam_pefs_debug = (openpam_get_option(pamh, PAM_OPT_DEBUG) != NULL);
	pam_pefs_delkeys = (openpam_get_option(pamh, PEFS_OPT_DELKEYS) != NULL);

	/* Switch to user credentials */
	pam_err = openpam_borrow_cred(pamh, pwd);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);

	if (pefs_getfsroot(pwd->pw_dir, 0, NULL, 0) != 0)
		return PAM_SYSTEM_ERR;

	fd = open(pwd->pw_dir, O_RDONLY);
	TAILQ_FOREACH(kc, kch, kc_entry) {
		if (ioctl(fd, PEFS_ADDKEY, &kc->kc_key) == -1) {
			pefs_warn("cannot add key: %s: %s", pwd->pw_dir,
			    strerror(errno));
			good_key = false;
			break;
		}
	}
	close(fd);

	/* Remove keys from memory */
	pefs_keychain_free(kch);

	/* Switch back to arbitrator credentials */
	openpam_restore_cred(pamh);

	/* Increment login count */
	if (pam_pefs_delkeys)
		pefs_session_count_incr(user, true, good_key);

	return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char *argv[] __unused)
{
	struct pefs_xkey k;
	struct passwd *pwd;
	const char *user;
	int fd, pam_err, pam_pefs_delkeys;

	pam_err = pam_get_user(pamh, &user, NULL);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);

	pwd = getpwnam(user);
	if (pwd == NULL)
		return (PAM_USER_UNKNOWN);
	if (pwd->pw_dir == NULL)
		return (PAM_SYSTEM_ERR);

	pam_pefs_debug = (openpam_get_option(pamh, PAM_OPT_DEBUG) != NULL);
	pam_pefs_delkeys = (openpam_get_option(pamh, PEFS_OPT_DELKEYS) != NULL);

	/* Switch to user credentials */
	pam_err = openpam_borrow_cred(pamh, pwd);
	if (pam_err != PAM_SUCCESS)
		return (pam_err);

	if (pefs_getfsroot(pwd->pw_dir, 0, NULL, 0) != 0)
		return PAM_SYSTEM_ERR;

	/* Switch back to arbitrator credentials */
	openpam_restore_cred(pamh);

	/* Decrease login count and remove keys if at zero */
	if (pam_pefs_delkeys && pefs_session_count_incr(user, false, false) == 0) {
		/* Switch to user credentials */
		pam_err = openpam_borrow_cred(pamh, pwd);
		if (pam_err != PAM_SUCCESS)
			return (pam_err);

		fd = open(pwd->pw_dir, O_RDONLY);

		bzero(&k, sizeof(k));
		while (1) {
			if (ioctl(fd, PEFS_GETKEY, &k) == -1)
				break;

			if (ioctl(fd, PEFS_DELKEY, &k) == -1) {
				pefs_warn("cannot del key: %s: %s", pwd->pw_dir,
					  strerror(errno));
				k.pxk_index++;
			}
		}
		close(fd);

		/* Switch back to arbitrator credentials */
		openpam_restore_cred(pamh);
	}

	return (PAM_SUCCESS);
}

PAM_MODULE_ENTRY("pam_pefs");
