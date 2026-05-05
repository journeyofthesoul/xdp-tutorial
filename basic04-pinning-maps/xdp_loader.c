/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "../common/common_libbpf.h"
#include "common_kern_user.h" /* struct datarec + XDP_ACTION_MAX */

static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      required_argument,	NULL, 'U' },
	 "Unload XDP program <id> instead of loading", "<id>"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_stats_map";

static int map_reset_counters(int map_fd)
{
	struct bpf_map_info info = { 0 };
	__u32 info_len = sizeof(info);
	int nr_cpus;
	__u32 key;
	int err;

	err = bpf_obj_get_info_by_fd(map_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: bpf_obj_get_info_by_fd failed: %s\n",
			strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (info.type == BPF_MAP_TYPE_ARRAY) {
		struct datarec value = { 0 };
		for (key = 0; key < XDP_ACTION_MAX; key++) {
			err = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
			if (err) {
				fprintf(stderr, "ERR: resetting map key %u failed: %s\n",
					key, strerror(errno));
				return EXIT_FAIL_BPF;
			}
		}
		return 0;
	}

	if (info.type == BPF_MAP_TYPE_PERCPU_ARRAY) {
		nr_cpus = libbpf_num_possible_cpus();
		if (nr_cpus < 1) {
			fprintf(stderr, "ERR: libbpf_num_possible_cpus failed\n");
			return EXIT_FAIL;
		}

		struct datarec zero_values[nr_cpus];
		memset(zero_values, 0, sizeof(zero_values));
		for (key = 0; key < XDP_ACTION_MAX; key++) {
			err = bpf_map_update_elem(map_fd, &key, zero_values, BPF_ANY);
			if (err) {
				fprintf(stderr, "ERR: resetting percpu key %u failed: %s\n",
					key, strerror(errno));
				return EXIT_FAIL_BPF;
			}
		}
		return 0;
	}

	fprintf(stderr, "WARN: unsupported map type(%u), skip reset\n", info.type);
	return 0;
}

static struct xdp_program *load_bpf_and_xdp_attach_reuse_maps(struct config *cfg,
							      bool *map_reused,
							      int *reused_map_fd)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);
	struct xdp_program *prog;
	struct bpf_map *map;
	char map_path[PATH_MAX];
	int err, len, pinned_map_fd;

	*map_reused = false;
	*reused_map_fd = -1;

	xdp_opts.open_filename = cfg->filename;
	xdp_opts.prog_name = cfg->progname;
	xdp_opts.opts = &opts;

	prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) {
		char errmsg[1024];
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: loading program: %s\n", errmsg);
		return NULL;
	}

	map = bpf_object__find_map_by_name(xdp_program__bpf_obj(prog), map_name);
	if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", map_name);
		xdp_program__close(prog);
		return NULL;
	}

	len = snprintf(map_path, PATH_MAX, "%s/%s", cfg->pin_dir, map_name);
	if (len < 0 || len >= PATH_MAX) {
		fprintf(stderr, "ERR: creating map path for reuse\n");
		xdp_program__close(prog);
		return NULL;
	}

	pinned_map_fd = bpf_obj_get(map_path);
	if (pinned_map_fd >= 0) {
		err = bpf_map__reuse_fd(map, pinned_map_fd);
		if (err) {
			fprintf(stderr, "ERR: bpf_map__reuse_fd failed: %s\n",
				strerror(-err));
			close(pinned_map_fd);
			xdp_program__close(prog);
			return NULL;
		}
		*map_reused = true;
		*reused_map_fd = pinned_map_fd;
		if (verbose)
			printf(" - Reusing pinned map: %s\n", map_path);
	}

	err = xdp_program__attach(prog, cfg->ifindex, cfg->attach_mode, 0);
	if (err) {
		fprintf(stderr, "ERR: xdp_program__attach failed: %s\n",
			strerror(-err));
		xdp_program__close(prog);
		return NULL;
	}

	return prog;
}

/* Pinning maps under /sys/fs/bpf */
int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, struct config *cfg)
{
	char map_filename[PATH_MAX];
	int err, len;

	len = snprintf(map_filename, PATH_MAX, "%s/%s", cfg->pin_dir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       cfg->pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, cfg->pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", cfg->pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", cfg->pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, cfg->pin_dir);
	if (err) {
		fprintf(stderr, "ERR: Pinning maps in %s\n", cfg->pin_dir);
		return EXIT_FAIL_BPF;
	}

	return 0;
}

/* Unpinning map under /sys/fs/bpf */
void unpin_map(struct config *cfg)
{
	char map_path[PATH_MAX];
	int len;

	len = snprintf(map_path, PATH_MAX, "%s/%s", cfg->pin_dir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map filename for unpin\n");
		return;
	}

	/* If the map file exists, unpin it */
	if (access(map_path, F_OK) == 0) {
		if (verbose)
			printf(" - Unpinning map %s\n", map_path);

		/* Use unlink to remove the pinned map file */
		if (unlink(map_path)) {
			fprintf(stderr, "ERR: Failed to unpin map %s: %s\n",
				map_path, strerror(errno));
		}
	}
}

int main(int argc, char **argv)
{
	struct xdp_program *program;
	int err, len, reused_map_fd = -1;
	bool map_reused = false;

	struct config cfg = {
		.attach_mode = XDP_MODE_NATIVE,
		.ifindex     = -1,
		.do_unload   = false,
	};
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	/* Cmdline options can change progname */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

	/* Initialize the pin_dir configuration */
	len = snprintf(cfg.pin_dir, 512, "%s/%s", pin_basedir, cfg.ifname);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	if (cfg.do_unload) {
		unpin_map(&cfg);

		/* unload the program */
		err = do_unload(&cfg);
		if (err) {
			char errmsg[1024];
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			fprintf(stderr, "Couldn't unload XDP program: %s\n", errmsg);
			return err;
		}

		printf("Success: Unloaded XDP program\n");
		return EXIT_OK;
	}

	program = load_bpf_and_xdp_attach_reuse_maps(&cfg, &map_reused,
						     &reused_map_fd);
	if (!program) {
		err = EXIT_FAIL_BPF;
		goto out;
	}

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	if (map_reused) {
		err = map_reset_counters(reused_map_fd);
		if (err) {
			fprintf(stderr, "ERR: failed resetting reused map counters\n");
			goto out;
		}
		if (verbose)
			printf(" - Reset reused map counters to zero\n");
	} else {
		/* Use the --dev name as subdir for exporting/pinning maps */
		err = pin_maps_in_bpf_object(xdp_program__bpf_obj(program), &cfg);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			goto out;
		}
	}

	err = EXIT_OK;

out:
	if (reused_map_fd >= 0)
		close(reused_map_fd);
	xdp_program__close(program);
	return err;
}
