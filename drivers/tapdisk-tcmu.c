#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>
#include <errno.h>

#include <sys/select.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <scsi/scsi.h>

#include "libtcmu.h"
#include "libvhd.h"

#include "tapdisk.h"
#include "tapdisk-server.h"
#include "scheduler.h"

#define BUG(_cond)       td_panic()
#define BUG_ON(_cond)    if (unlikely(_cond)) { td_panic(); }

#define DBG(_f, _a...)       tlog_syslog(TLOG_DBG, _f, ##_a)
#define INFO(_f, _a...)      tlog_syslog(TLOG_INFO, _f, ##_a)
#define ERR(_err, _f, _a...) tlog_error(_err, _f, ##_a)
#define WARN(_f, _a...)      tlog_syslog(TLOG_WARN, "WARNING: "_f "in %s:%d", \
					 ##_a, __func__, __LINE__)
struct sh_state {
	vhd_context_t cxt;
	uint64_t num_lbas;
	uint32_t block_size;
};

void dbgp(const char *fmt, ...)
{
	va_list va;
        DBG(fmt, va);
}

void errp(const char *fmt, ...)
{
	va_list va;

        DBG(fmt, va);
}

static int set_medium_error(uint8_t *sense)
{
	return tcmu_set_sense_data(sense, MEDIUM_ERROR, ASC_READ_ERROR, NULL);
}

/*
 * Return scsi status or TCMU_NOT_HANDLED
 */
static int sh_handle_cmd(
	struct tcmu_device *dev,
	struct tcmulib_cmd *tcmulib_cmd)
{
	uint8_t *cdb = tcmulib_cmd->cdb;
	struct iovec *iovec = tcmulib_cmd->iovec;
	size_t iov_cnt = tcmulib_cmd->iov_cnt;
	uint8_t *sense = tcmulib_cmd->sense_buf;
	struct sh_state *state = tcmu_get_dev_private(dev);
	uint8_t cmd;
	int remaining;
	size_t ret;

	cmd = cdb[0];

	switch (cmd) {
	case INQUIRY:
		return tcmu_emulate_inquiry(dev, cdb, iovec, iov_cnt, sense);
		break;
	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt, sense);
		break;
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return tcmu_emulate_read_capacity_16(state->num_lbas,
							     state->block_size,
							     cdb, iovec, iov_cnt, sense);
		else
			return TCMU_NOT_HANDLED;
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(cdb, iovec, iov_cnt, sense);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(cdb, iovec, iov_cnt, sense);
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	{
		void *buf;
		uint64_t offset = state->block_size * tcmu_get_lba(cdb);
		int length = tcmu_get_xfer_length(cdb) * state->block_size;
                int ret;

		/* Using this buf DTRT even if seek is beyond EOF */
                ret = posix_memalign(&buf, state->block_size, length);
                if (ret < 0) {
			errp("read failed: fail to allocate buffer\n");
			return set_medium_error(sense);
                }

		memset(buf, 0, length);

		ret = vhd_io_read_bytes(&state->cxt, buf, length, offset);
		if (ret < 0) {
			errp("read failed: %m\n");
			free(buf);
			return set_medium_error(sense);
		}

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, length);

		free(buf);

		return SAM_STAT_GOOD;
	}
	break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	{
		uint64_t offset = state->block_size * tcmu_get_lba(cdb);
		int length = be16toh(*((uint16_t *)&cdb[7])) * state->block_size;

		remaining = length;

		while (remaining) {
			unsigned int to_copy;

			to_copy = (remaining > iovec->iov_len) ? iovec->iov_len : remaining;

			ret = vhd_io_write_bytes(&state->cxt, iovec->iov_base, to_copy, offset);
			if (ret < 0) {
				errp("Could not write: %m\n");
				return set_medium_error(sense);
			}

			remaining -= to_copy;
			offset += to_copy;
			iovec++;
		}

		return SAM_STAT_GOOD;
	}
	break;
	default:
		errp("unknown command %x\n", cdb[0]);
		return TCMU_NOT_HANDLED;
	}
}

static bool sh_check_config(const char *cfgstring, char **reason)
{
        char *path;
        int ret;

        path = strchr(cfgstring, '/');
	if (!path) {
		ret = asprintf(reason, "No path found");
		return false;
	}
	path += 1; /* get past '/' */

	if (access(path, W_OK) != -1) {
		/* File exists and is writable, we need to verify it's VHD file */
                vhd_context_t cxt;
                ret = vhd_open(&cxt, path, VHD_OPEN_RDONLY);
                if (ret != 0) {
                        ret = asprintf(reason, "Fail to verify VHD file");
                        return false;
                }
                vhd_close(&cxt);
                return true;
        }

	unlink(path);

        return true;
}

static void tcmu_handle_command(event_id_t id, char mode, void *data)
{
	struct tcmu_device *dev = data;
	int ret;

	int completed = 0;
	struct tcmulib_cmd *cmd;

	tcmulib_processing_start(dev);

	while ((cmd = tcmulib_get_next_command(dev)) != NULL) {
		/*
		   int i;
		   bool short_cdb = cmd->cdb[0] <= 0x1f;

		   for (i = 0; i < (short_cdb ? 6 : 10); i++) {
		   dbgp("%x ", cmd->cdb[i]);
		   }
		   dbgp("\n");
		   */

		ret = sh_handle_cmd(dev, cmd);
		if (ret != TCMU_ASYNC_HANDLED) {
			tcmulib_command_complete(dev, cmd, ret);
			completed = 1;
		}
	}

	if (completed)
		tcmulib_processing_complete(dev);

	return;
}

static void sh_close(struct tcmu_device *dev)
{
	int ret;
        struct sh_state *state;

        state = tcmu_get_dev_private(dev);
        vhd_close(&state->cxt);
        free(state);
}

static int sh_open(struct tcmu_device *dev)
{
	int ret;
	struct sh_state *state;
	int64_t size;
	char *config;
        char *path;
	int dev_event_id;

	state = calloc(1, sizeof(*state));
	if (!state)
		return -ENOMEM;

	tcmu_set_dev_private(dev, state);

	state->block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (state->block_size == -1) {
		errp("Could not get device block size\n");
		goto err;
	}

	size = tcmu_get_device_size(dev);
	if (size == -1) {
		errp("Could not get device size\n");
		goto err;
	}

	state->num_lbas = size / state->block_size;

	config = strchr(tcmu_get_dev_cfgstring(dev), '/');
	if (!config) {
		errp("no configuration found in cfgstring\n");
		goto err;
	}
	config += 1; /* get past '/' */

        path = config;

        /* Open or create a VHD file, need to verify */
	if (access(path, W_OK) < 0) {
                ret = vhd_create(path, size, HD_TYPE_DYNAMIC, 0, 0);
                if (ret < 0) {
                        errp("Cannot create vhd file at %s, err %d", path, ret);
                }
        }

        ret = vhd_open(&state->cxt, path, VHD_OPEN_RDWR);
        if (ret != 0) {
                errp("Fail to open VHD file");
                return false;
        }

	dev_event_id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
		tcmu_get_dev_fd(dev), 0,
		tcmu_handle_command, dev);
	if (dev_event_id < 0) {
		errp("Fail to register dev event!");
		return dev_event_id;
	}

	return 0;

err:
	free(state);
	return -EINVAL;
}

static struct tcmulib_handler sh_handler = {
	.name = "Shorthorn TCMU handler",
	.subtype = "file",
	.cfg_desc = "VHD based TCMU handler, dev_config=file/<path>",
	.check_config = sh_check_config,
	.added = sh_open,
	.removed = sh_close,
};

static void
td_tcmu_accept_fd(event_id_t id, char mode, void *data)
{
	struct tcmulib_context *cxt = data;
	errp("tcmu accept fd called!\n");

	tcmulib_master_fd_ready(cxt);
}

void td_tcmu_start()
{
	struct tcmulib_context *tcmulib_cxt;
	int fd_event_id;

	tcmulib_cxt = tcmulib_initialize(&sh_handler, 1, errp);
	if (tcmulib_cxt <= 0) {
		errp("tcmulib_initialize failed with %p\n", tcmulib_cxt);
		exit(1);
	}

	fd_event_id = tapdisk_server_register_event(SCHEDULER_POLL_READ_FD,
		tcmulib_get_master_fd(tcmulib_cxt), 0,
		td_tcmu_accept_fd, tcmulib_cxt);

	DBG("TCMU event_id is %d\n", fd_event_id);
}
