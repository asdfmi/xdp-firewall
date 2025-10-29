#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>

#include "xdp_telemetry.h"

static void report_failure(const char *stage, int err)
{
	if (err < 0)
		fprintf(stderr, "test_attach: %s failed: %s (%d)\n", stage,
			strerror(-err), err);
	else
		fprintf(stderr, "test_attach: %s failed with code %d\n", stage,
			err);
}

static int cleanup_pin_root(const char *pin_root, const char *ifname,
			    bool unmount_bpffs)
{
	char path[PATH_MAX];
	int ret = 0;

	if (!pin_root || !pin_root[0] || !ifname || !ifname[0])
		return 0;

    if (snprintf(path, sizeof(path), "%s/%s_events", pin_root, ifname) >=
        (int)sizeof(path))
        return -ENAMETOOLONG;
	if (unlink(path) && errno != ENOENT) {
		fprintf(stderr,
			"test_attach: warning: failed to unlink %s: %s\n", path,
			strerror(errno));
		ret = -errno;
	}

	if (snprintf(path, sizeof(path), "%s/%s_rules_v4", pin_root, ifname) >=
	    (int)sizeof(path))
		return -ENAMETOOLONG;
	if (unlink(path) && errno != ENOENT) {
		fprintf(stderr,
			"test_attach: warning: failed to unlink %s: %s\n", path,
			strerror(errno));
		ret = ret ? ret : -errno;
	}

	if (unmount_bpffs) {
		if (umount(pin_root) && errno != EINVAL && errno != ENOENT) {
			fprintf(stderr,
				"test_attach: warning: failed to unmount %s: %s\n",
				pin_root, strerror(errno));
			ret = ret ? ret : -errno;
		}
	}

	if (rmdir(pin_root) && errno != ENOENT) {
		fprintf(stderr,
			"test_attach: warning: failed to remove %s: %s\n",
			pin_root, strerror(errno));
		ret = ret ? ret : -errno;
	}

	return ret;
}

int main(void)
{
	struct xdp_telemetry_device *device = NULL;
	struct xdp_telemetry_attach_opts opts = {0};
	char tmp_bpffs_template[] = "/tmp/xdp_telemetry_bpffs.XXXXXX";
	char *pin_root = NULL;
	bool pin_root_is_tmp_mount = false;
    char events_path[PATH_MAX];
	char rules_path[PATH_MAX];
	const char *ifname = "lo";
	bool attached = false;
	int err;
	int rc = 1;

	if (geteuid() != 0) {
		fprintf(stderr,
			"test_attach: SKIP (requires root privileges)\n");
		return 77;
	}

	pin_root = mkdtemp(tmp_bpffs_template);
	if (!pin_root) {
		fprintf(stderr,
			"test_attach: SKIP (failed to create bpffs mount point: %s)\n",
			strerror(errno));
		rc = 77;
		goto out;
	}

	if (mount("bpffs", pin_root, "bpf", 0, NULL) != 0) {
		fprintf(stderr,
			"test_attach: SKIP (failed to mount bpffs at %s: %s)\n",
			pin_root, strerror(errno));
		(void)rmdir(pin_root);
		rc = 77;
		pin_root = NULL;
		goto out;
	}

	pin_root_is_tmp_mount = true;

	memset(&opts, 0, sizeof(opts));
	opts.ifname = ifname;
	opts.mode = XDP_TELEMETRY_ATTACH_MODE_SKB;
	opts.pin_maps = true;
	opts.pin_maps_set = true;
	opts.pin_path = pin_root;

	err = xdp_telemetry_device_open(&device, &opts);
	if (err) {
		report_failure("xdp_telemetry_device_open", err);
		goto out;
	}

	err = xdp_telemetry_device_attach(device);
	if (err) {
		report_failure("xdp_telemetry_device_attach", err);
		goto out;
	}
	attached = true;

    if (snprintf(events_path, sizeof(events_path), "%s/%s_events",
             pin_root, ifname) >= (int)sizeof(events_path)) {
        fprintf(stderr,
            "test_attach: events path truncated unexpectedly\n");
        goto out;
    }

    if (access(events_path, F_OK) != 0) {
        fprintf(stderr,
            "test_attach: expected events map to be pinned at %s\n",
            events_path);
        goto out;
    }

	if (snprintf(rules_path, sizeof(rules_path), "%s/%s_rules_v4",
		     pin_root, ifname) >= (int)sizeof(rules_path)) {
		fprintf(stderr,
			"test_attach: rules path truncated unexpectedly\n");
		goto out;
	}

	if (access(rules_path, F_OK) != 0) {
		fprintf(stderr,
			"test_attach: expected rules map to be pinned at %s\n",
			rules_path);
		goto out;
	}

	err = xdp_telemetry_device_detach(device);
	if (err) {
		report_failure("xdp_telemetry_device_detach", err);
		goto out;
	}
	attached = false;

    if (access(events_path, F_OK) == 0) {
        fprintf(stderr,
            "test_attach: expected events map %s to be removed\n",
            events_path);
        goto out;
    }
	if (access(rules_path, F_OK) == 0) {
		fprintf(stderr,
			"test_attach: expected rules map %s to be removed\n",
			rules_path);
		goto out;
	}

	rc = 0;

out:
	if (attached)
		(void)xdp_telemetry_device_detach(device);
	xdp_telemetry_device_close(device);
	if (pin_root)
		(void)cleanup_pin_root(pin_root, ifname,
				       pin_root_is_tmp_mount);
	return rc;
}
