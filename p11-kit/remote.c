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
#include "message.h"
#include "p11-kit.h"
#include "remote.h"
#include "tool.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>

int
main (int argc,
      char *argv[])
{
	CK_FUNCTION_LIST *module;
	char *socket_file = NULL;
	uid_t uid = -1;
	gid_t gid = -1;
	int opt;
	int ret;

	enum {
		opt_verbose = 'v',
		opt_help = 'h',
		opt_socket = 's',
		opt_user = 'u',
		opt_group = 'g',
	};

	struct option options[] = {
		{ "verbose", no_argument, NULL, opt_verbose },
		{ "help", no_argument, NULL, opt_help },
		{ "socket", required_argument, NULL, opt_socket },
		{ "user", required_argument, NULL, opt_user },
		{ "group", required_argument, NULL, opt_group },
		{ 0 },
	};

	p11_tool_desc usages[] = {
		{ 0, "usage: p11-kit remote <module> -s <socket-file> -u <allowed-user> -g <allowed-group>" },
		{ 0 },
	};

	while ((opt = p11_tool_getopt (argc, argv, options)) != -1) {
		switch (opt) {
		case opt_verbose:
			p11_kit_be_loud ();
			break;
		case opt_socket:
			socket_file = strdup(optarg);
			break;
		case opt_group: {
			const struct group* grp = getgrnam(optarg);
			if (grp == NULL) {
				p11_message ("unknown group: %s", optarg);
				return 2;
			}
			gid = grp->gr_gid;
			break;
		}
		case opt_user: {
			const struct passwd* pwd = getpwnam(optarg);
			if (pwd == NULL) {
				p11_message ("unknown user: %s", optarg);
				return 2;
			}
			uid = pwd->pw_uid;
			break;
		}
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

	if (socket_file == NULL) {
		p11_tool_usage (usages, options);
		return 2;
	}

	if (argc != 1) {
		p11_message ("specify the module to remote");
		return 2;
	}

	module = p11_kit_module_load (argv[0], 0);
	if (module == NULL)
		return 1;

	ret = p11_kit_remote_serve_module (module, socket_file, uid, gid);
	p11_kit_module_release (module);

	return ret;
}
