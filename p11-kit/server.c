/*
 * Copyright (C) 2014 Red Hat Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above
 *       copyright notice, this list of conditions and the
 *       following disclaimer.
 *     * Redistributions in binary form must reproduce the
 *       above copyright notice, this list of conditions and
 *       the following disclaimer in the documentation and/or
 *       other materials provided with the distribution.
 *     * The names of contributors to this software may not be
 *       used to endorse or promote products derived from this
 *       software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
 * THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 *
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "compat.h"
#include "debug.h"
#include "external.h"
#include "message.h"
#include "p11-kit.h"
#include "remote.h"
#include "unix-peer.h"
#include "tool.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef HAVE_SIGHANDLER_T
#define SIGHANDLER_T sighandler_t
#elif HAVE_SIG_T
#define SIGHANDLER_T sig_t
#elif HAVE___SIGHANDLER_T
#define SIGHANDLER_T __sighandler_t
#else
typedef void (*sighandler_t)(int);
#define SIGHANDLER_T sighandler_t
#endif

static bool need_children_cleanup = false;
static bool terminate = false;
static unsigned children_avail = 0;

static SIGHANDLER_T
ocsignal (int signum, SIGHANDLER_T handler)
{
	struct sigaction new_action, old_action;

	new_action.sa_handler = handler;
	sigemptyset (&new_action.sa_mask);
	new_action.sa_flags = 0;

	sigaction (signum, &new_action, &old_action);
	return old_action.sa_handler;
}

static void
cleanup_children (void)
{
	int status;
	pid_t pid;

	while ((pid = waitpid (-1, &status, WNOHANG)) > 0) {
		if (children_avail > 0)
			children_avail--;
		if (WIFSIGNALED (status)) {
			if (WTERMSIG (status) == SIGSEGV)
				p11_message ("child %u died with sigsegv", (unsigned)pid);
			else
				p11_message ("child %u died with signal %d", (unsigned)pid, (int)WTERMSIG (status));
		}
	}
	need_children_cleanup = false;
}

static void
handle_children (int signo)
{
	need_children_cleanup = true;
}

static void
handle_term (int signo)
{
	terminate = true;
}

static int
set_cloexec_on_fd (void *data,
                   int fd)
{
	int *max_fd = data;
	if (fd >= *max_fd)
		fcntl (fd, F_SETFD, FD_CLOEXEC);
	return 0;
}

static int
loop (const char *module_name,
      const char *socket_file,
      uid_t uid,
      gid_t gid,
      bool foreground,
      struct timespec *timeout)
{
	int ret = 1, rc, sd;
	int cfd;
	pid_t pid;
	socklen_t sa_len;
	struct sockaddr_un sa;
	fd_set rd_set;
	sigset_t emptyset, blockset;
	uid_t tuid;
	gid_t tgid;
	char *args[] = { "remote", NULL, NULL };
	int max_fd;
	int errn;

	sigemptyset (&blockset);
	sigemptyset (&emptyset);
	sigaddset (&blockset, SIGCHLD);
	sigaddset (&blockset, SIGTERM);
	sigaddset (&blockset, SIGINT);
	ocsignal (SIGCHLD, handle_children);
	ocsignal (SIGTERM, handle_term);
	ocsignal (SIGINT, handle_term);

	/* listen to unix socket */
	memset (&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	snprintf (sa.sun_path, sizeof (sa.sun_path), "%s", socket_file);

	remove (socket_file);

	sd = socket (AF_UNIX, SOCK_STREAM, 0);
	if (sd == -1) {
		p11_message_err (errno, "could not create socket %s", socket_file);
		return 1;
	}

	umask (066);
	rc = bind (sd, (struct sockaddr *)&sa, SUN_LEN (&sa));
	if (rc == -1) {
		p11_message_err (errno, "could not create socket %s", socket_file);
		return 1;
	}

	if (uid != -1 && gid != -1) {
		rc = chown (socket_file, uid, gid);
		if (rc == -1) {
			p11_message_err (errno, "could not chown socket %s", socket_file);
			return 1;
		}
	}

	/* run as daemon */
	if (!foreground) {
		pid = fork ();
		switch (pid) {
		case -1:
			p11_message_err (errno, "could not fork() to daemonize");
			return 1;
		case 0:
			break;
		default:
			_exit (0);
		}
		if (setsid () == -1) {
			p11_message_err (errno, "could not create a new session");
			return 1;
		}
	}

	rc = listen (sd, 1024);
	if (rc == -1) {
		p11_message_err (errno, "could not listen to socket %s", socket_file);
		return 1;
	}

	sigprocmask (SIG_BLOCK, &blockset, NULL);
	/* accept connections */
	ret = 0;
	for (;;) {
		if (need_children_cleanup)
			cleanup_children ();

		if (terminate)
			break;

		FD_ZERO (&rd_set);
		FD_SET (sd, &rd_set);

		ret = pselect (sd + 1, &rd_set, NULL, NULL, timeout, &emptyset);
		if (ret == -1 && errno == EINTR)
			continue;

		if (ret == 0 && children_avail == 0) { /* timeout */
			p11_message ("no connections to %s for %lu secs, exiting", socket_file, timeout->tv_sec);
			break;
		}

		if (FD_ISSET (sd, &rd_set)) {
			sa_len = sizeof (sa);
			cfd = accept (sd, (struct sockaddr *)&sa, &sa_len);
			if (cfd == -1) {
				if (errno != EINTR)
					p11_message_err (errno, "could not accept from socket %s", socket_file);
				continue;
			}

			/* check the uid of the peer */
			rc = p11_get_upeer_id (cfd, &tuid, &tgid, NULL);
			if (rc == -1) {
				p11_message_err (errno, "could not check uid from socket %s", socket_file);
				close (cfd);
				continue;
			}

			if (uid != -1 && uid != tuid) {
				p11_message ("connecting uid (%u) doesn't match expected (%u)",
					     (unsigned)tuid, (unsigned)uid);
				close (cfd);
				continue;
			}

			if (gid != -1 && gid != tgid) {
				p11_message ("connecting gid (%u) doesn't match expected (%u)",
					     (unsigned)tgid, (unsigned)gid);
				close (cfd);
				continue;
			}

			pid = fork ();
			switch (pid) {
			case -1:
				p11_message_err (errno, "failed to fork for accept");
				continue;
			/* Child */
			case 0:
				sigprocmask (SIG_UNBLOCK, &blockset, NULL);
				if (dup2 (cfd, STDIN_FILENO) < 0 ||
				    dup2 (cfd, STDOUT_FILENO) < 0) {
					errn = errno;
					p11_message_err (errn, "couldn't dup file descriptors in remote child");
					_exit (errn);
				}

				/* Close file descriptors, except for above on exec */
				max_fd = STDERR_FILENO + 1;
				fdwalk (set_cloexec_on_fd, &max_fd);

				/* Execute 'p11-kit remote'; this shouldn't return */
				args[1] = (char *) module_name;
				p11_kit_external (2, args);

				errn = errno;
				p11_message_err (errn, "couldn't execute 'p11-kit remote' for module '%s'", module_name);
				_exit (errn);
			default:
				children_avail++;
				break;
			}
			close (cfd);
		}
	}

	remove (socket_file);

	return ret;
}

int
main (int argc,
      char *argv[])
{
	char *module_name;
	char *socket_file;
	uid_t uid = -1, run_as_uid = -1;
	gid_t gid = -1, run_as_gid = -1;
	int opt;
	const struct passwd *pwd;
	const struct group *grp;
	bool foreground = false;
	struct timespec *timeout = NULL, ts;

	enum {
		opt_verbose = 'v',
		opt_help = 'h',
		opt_user = 'u',
		opt_group = 'g',
		opt_run_as_user = 'a',
		opt_run_as_group = 'z',
		opt_foreground = 'f',
		opt_timeout = 't',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, opt_help },
		{ "foreground", no_argument, NULL, opt_foreground },
		{ "user", required_argument, NULL, opt_user },
		{ "group", required_argument, NULL, opt_group },
		{ "run-as-user", required_argument, NULL, opt_run_as_user },
		{ "run-as-group", required_argument, NULL, opt_run_as_group },
		{ "timeout", required_argument, NULL, opt_timeout },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit server <module> <socket-file>" },
		{ 0, "usage: p11-kit server <module> <socket-file> -u <allowed-user> -g <allowed-group> --run-as-user <user> --run-as-group <group>" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_timeout:
			ts.tv_sec = atoi (optarg);
			ts.tv_nsec = 0;
			timeout = &ts;
			break;
		case opt_group:
			grp = getgrnam (optarg);
			if (grp == NULL) {
				p11_message ("unknown group: %s", optarg);
				return 2;
			}
			gid = grp->gr_gid;
			break;
		case opt_user:
			pwd = getpwnam (optarg);
			if (pwd == NULL) {
				p11_message ("unknown user: %s", optarg);
				return 2;
			}
			uid = pwd->pw_uid;
			break;
		case opt_run_as_group:
			grp = getgrnam (optarg);
			if (grp == NULL) {
				p11_message ("unknown group: %s", optarg);
				return 2;
			}
			run_as_gid = grp->gr_gid;
			break;
		case opt_run_as_user:
			pwd = getpwnam (optarg);
			if (pwd == NULL) {
				p11_message ("unknown user: %s", optarg);
				return 2;
			}
			run_as_uid = pwd->pw_uid;
			break;
		case opt_foreground:
			foreground = true;
			break;
		case opt_help:
		case '?':
			p11_tool_usage (usages, options);
			return 0;
		default:
			assert_not_reached ();
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 2) {
		p11_tool_usage (usages, options);
		return 2;
	}

	module_name = argv[0];
	socket_file = argv[1];

	if (run_as_gid != -1) {
		if (setgid (run_as_gid) == -1) {
			p11_message_err (errno, "cannot set gid to %u", (unsigned)run_as_gid);
			return 1;
		}

		if (setgroups (1, &run_as_gid) == -1) {
			p11_message_err (errno, "cannot setgroups to %u", (unsigned)run_as_gid);
			return 1;
		}
	}

	if (run_as_uid != -1) {
		if (setuid (run_as_uid) == -1) {
			p11_message_err (errno, "cannot set uid to %u", (unsigned)run_as_uid);
			return 1;
		}
	}

	return loop (module_name, socket_file, uid, gid, foreground, timeout);
}
