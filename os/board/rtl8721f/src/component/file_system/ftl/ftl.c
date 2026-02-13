#include "os_wrapper.h"
#include "ameba.h"
#include "basic_types.h"
#include "ftl.h"

#include "vfs.h"
#ifndef CONFIG_PLATFORM_TIZENRT_OS
#include "lfs.h"
#endif //#ifndef CONFIG_PLATFORM_TIZENRT_OS

static const char *const TAG = "FTL";

#define FTL_FILE_NAME "ftl_for_ble"
#define FTL_TRACE_FILE_NAME "ftl_trace_for_ble"
#define MAX_FILE_NAME_LEN 32

static char *prefix;
static rtos_mutex_t ftl_op_mux = NULL;
static char *path = NULL;
static char *path_trace = NULL;

uint32_t ftl_save_to_storage(u8 *pdata_tmp, uint16_t offset, uint16_t size)
{
	FILE *finfo;
	int res;
	int file_size;
	int pad_size, write_size;
#ifndef CONFIG_PLATFORM_TIZENRT_OS
	vfs_file *v_file;
	lfs_file_t *l_file;
#endif //#ifndef CONFIG_PLATFORM_TIZENRT_OS
	u8 *buffer = NULL;

	rtos_mutex_take(ftl_op_mux, MUTEX_WAIT_TIMEOUT);

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	/* TizenRT: open with "r+" if file exists, or "w+" to create.
	 * Original FreeRTOS "rx" always fails (LFS_O_EXCL without CREAT),
	 * then "+" (Realtek's custom CREAT|RDWR mode) creates the file. */
	finfo = fopen(path_trace, "r+");
	if (finfo == NULL) {
		finfo = fopen(path_trace, "w+");
		if (finfo == NULL) {
			RTK_LOGS(TAG, RTK_LOG_ERROR, "ftl open file error\r\n");
			rtos_mutex_give(ftl_op_mux);
			return FTL_WRITE_ERROR_NOT_INIT;
		}
	}
#else
	finfo = fopen(path_trace, "rx");
	if (finfo == NULL) {
		finfo = fopen(path_trace, "+");
		if (finfo == NULL) {
			RTK_LOGS(TAG, RTK_LOG_ERROR, "ftl open file error\r\n");
			return FTL_WRITE_ERROR_NOT_INIT;
		}
	} else {
		RTK_LOGS(TAG, RTK_LOG_ERROR, "ftl init file error\r\n");
		rtos_mutex_give(ftl_op_mux);
		return FTL_WRITE_ERROR_NOT_INIT;
	}
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	/* TizenRT: use fseek/ftell to get file size (no vfs_file/lfs_file_t access) */
	fseek(finfo, 0, SEEK_END);
	file_size = (int)ftell(finfo);
	fseek(finfo, 0, SEEK_SET);
#else
	v_file = (vfs_file *)finfo;
	l_file = (lfs_file_t *)(v_file->file);
	file_size = (int)l_file->ctz.size;
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS

	if (file_size < offset) {
		pad_size = offset - file_size;
		buffer = (u8 *)rtos_mem_zmalloc(2048);
		fseek(finfo, 0, SEEK_END);

		while (pad_size > 0) {
			write_size = pad_size > 2048 ? 2048 : pad_size;
			res = fwrite(buffer, write_size, 1, finfo);
#ifdef CONFIG_PLATFORM_TIZENRT_OS
			if (res != 1) {
#else
			if (res != write_size) {
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS
				RTK_LOGS(TAG, RTK_LOG_ERROR, "fwrite fail, res : %d\r\n", res);
				res = FTL_WRITE_ERROR_INVALID_ADDR;
				goto exit;
			}
			pad_size -= write_size;
		}
		rtos_mem_free(buffer);
		buffer = NULL;
	}

	res = fseek(finfo, offset, SEEK_SET);
	if (res < 0) {
		RTK_LOGS(TAG, RTK_LOG_ERROR, "fseek fail, res : %d\r\n", res);
		res = FTL_WRITE_ERROR_INVALID_ADDR;
		goto exit;
	}

	buffer = (u8 *)rtos_mem_zmalloc(2048);
	memset(buffer, 1, 2048);
	pad_size = size;
	while (pad_size > 0) {
		write_size = pad_size > 2048 ? 2048 : pad_size;
		res = fwrite(buffer, write_size, 1, finfo);
#ifdef CONFIG_PLATFORM_TIZENRT_OS
		if (res != 1) {
#else
		if (res != write_size) {
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS
			RTK_LOGS(TAG, RTK_LOG_ERROR, "fwrite fail, res : %d\r\n", res);
			res = FTL_WRITE_ERROR_INVALID_ADDR;
			goto exit;
		}
		pad_size -= write_size;
	}
	rtos_mem_free(buffer);
	buffer = NULL;
	fclose(finfo);

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	/* TizenRT: open with "r+" if file exists, or "w+" to create. */
	finfo = fopen(path, "r+");
	if (finfo == NULL) {
		finfo = fopen(path, "w+");
		if (finfo == NULL) {
			RTK_LOGS(TAG, RTK_LOG_ERROR, "ftl open file error\r\n");
			rtos_mutex_give(ftl_op_mux);
			return FTL_WRITE_ERROR_NOT_INIT;
		}
	}
#else
	finfo = fopen(path, "rx");
	if (finfo == NULL) {
		finfo = fopen(path, "+");
		if (finfo == NULL) {
			RTK_LOGS(TAG, RTK_LOG_ERROR, "ftl open file error\r\n");
			return FTL_WRITE_ERROR_NOT_INIT;
		}
	} else {
		RTK_LOGS(TAG, RTK_LOG_ERROR, "ftl init file error\r\n");
		rtos_mutex_give(ftl_op_mux);
		return FTL_WRITE_ERROR_NOT_INIT;
	}
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	fseek(finfo, 0, SEEK_END);
	file_size = (int)ftell(finfo);
	fseek(finfo, 0, SEEK_SET);
#else
	v_file = (vfs_file *)finfo;
	l_file = (lfs_file_t *)(v_file->file);
	file_size = (int)l_file->ctz.size;
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS

	if (file_size < offset) {
		pad_size = offset - file_size;
		buffer = (u8 *)rtos_mem_zmalloc(2048);
		fseek(finfo, 0, SEEK_END);

		while (pad_size > 0) {
			write_size = pad_size > 2048 ? 2048 : pad_size;
			res = fwrite(buffer, write_size, 1, finfo);
#ifdef CONFIG_PLATFORM_TIZENRT_OS
			if (res != 1) {
#else
			if (res != write_size) {
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS
				RTK_LOGS(TAG, RTK_LOG_ERROR, "fwrite fail, res : %d\r\n", res);
				res = FTL_WRITE_ERROR_INVALID_ADDR;
				goto exit;
			}
			pad_size -= write_size;
		}
		rtos_mem_free(buffer);
		buffer = NULL;
	}

	res = fseek(finfo, offset, SEEK_SET);
	if (res < 0) {
		RTK_LOGS(TAG, RTK_LOG_ERROR, "fseek fail, res : %d\r\n", res);
		res = FTL_WRITE_ERROR_INVALID_ADDR;
		goto exit;
	}

	res = fwrite(pdata_tmp, size, 1, finfo);
#ifdef CONFIG_PLATFORM_TIZENRT_OS
	if (res != 1) {
#else
	if (res != size) {
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS
		RTK_LOGS(TAG, RTK_LOG_ERROR, "fwrite fail, res : %d\r\n", res);
		res = FTL_WRITE_ERROR_INVALID_ADDR;
		goto exit;
	}

	res = FTL_WRITE_SUCCESS;

exit:
	if (buffer) {
		rtos_mem_free(buffer);
	}
	fclose(finfo);
	rtos_mutex_give(ftl_op_mux);

	return res;
}

uint32_t ftl_load_from_storage(void *pdata_tmp, uint16_t offset, uint16_t size)
{
	FILE *finfo;
	int res;
	int file_size;
#ifndef CONFIG_PLATFORM_TIZENRT_OS
	vfs_file *v_file;
	lfs_file_t *l_file;
#endif //#ifndef CONFIG_PLATFORM_TIZENRT_OS

	rtos_mutex_take(ftl_op_mux, MUTEX_WAIT_TIMEOUT);

	finfo = fopen(path_trace, "r");
	if (finfo == NULL) {
		RTK_LOGS(TAG, RTK_LOG_ERROR, "ftl open file error\r\n");
		rtos_mutex_give(ftl_op_mux);
		return FTL_READ_ERROR_NOT_INIT;
	}

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	fseek(finfo, 0, SEEK_END);
	file_size = (int)ftell(finfo);
	fseek(finfo, 0, SEEK_SET);
#else
	v_file = (vfs_file *)finfo;
	l_file = (lfs_file_t *)(v_file->file);
	file_size = (int)l_file->ctz.size;
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS

	if (offset + size > file_size) {
		RTK_LOGS(TAG, RTK_LOG_DEBUG, "ftl region is not writed\r\n");
		res = FTL_READ_ERROR_READ_NOT_FOUND;
		goto exit;
	} else {
		res = fseek(finfo, offset, SEEK_SET);
		if (res < 0) {
			RTK_LOGS(TAG, RTK_LOG_ERROR, "fseek fail, res : %d\r\n", res);
			res = FTL_READ_ERROR_INVALID_LOGICAL_ADDR;
			goto exit;
		}

		res = fread(pdata_tmp, size, 1, finfo);
#ifdef CONFIG_PLATFORM_TIZENRT_OS
		if (res != 1) {
#else
		if (res < 0) {
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS
			RTK_LOGS(TAG, RTK_LOG_ERROR, "fread fail, res : %d\r\n", res);
			res = FTL_READ_ERROR_INVALID_LOGICAL_ADDR;
			goto exit;
		}

		for (int i = 0; i < size; i++) {
			if (((u8 *)pdata_tmp)[i] == 0) {
				res = FTL_READ_ERROR_READ_NOT_FOUND;
				goto exit;
			}
		}

		fclose(finfo);
	}

	finfo = fopen(path, "r");
	if (finfo == NULL) {
		RTK_LOGS(TAG, RTK_LOG_ERROR, "ftl open file error\r\n");
		rtos_mutex_give(ftl_op_mux);
		return FTL_READ_ERROR_NOT_INIT;
	}

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	fseek(finfo, 0, SEEK_END);
	file_size = (int)ftell(finfo);
	fseek(finfo, 0, SEEK_SET);
#else
	v_file = (vfs_file *)finfo;
	l_file = (lfs_file_t *)(v_file->file);
	file_size = (int)l_file->ctz.size;
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS

	if (offset > file_size) {
		memset(pdata_tmp, 0, size);
		res = FTL_READ_SUCCESS;
		goto exit;
	}

	res = fseek(finfo, offset, SEEK_SET);
	if (res < 0) {
		RTK_LOGS(TAG, RTK_LOG_ERROR, "fseek fail, res : %d\r\n", res);
		res = FTL_READ_ERROR_INVALID_LOGICAL_ADDR;
		goto exit;
	}

	res = fread(pdata_tmp, size, 1, finfo);
#ifdef CONFIG_PLATFORM_TIZENRT_OS
	if (res != 1) {
#else
	if (res < 0) {
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS
		RTK_LOGS(TAG, RTK_LOG_ERROR, "fread fail, res : %d\r\n", res);
		res = FTL_READ_ERROR_INVALID_LOGICAL_ADDR;
		goto exit;
	}

	res = FTL_READ_SUCCESS;

exit:
	fclose(finfo);
	rtos_mutex_give(ftl_op_mux);

	return res;
}

uint32_t vfs_ftl_init(void)
{
	FILE *finfo;

	if ((path == NULL) && ((path = rtos_mem_zmalloc(MAX_FILE_NAME_LEN + 1)) == NULL)) {
		RTK_LOGS(TAG, RTK_LOG_ERROR, "ftl_init fail\r\n");
		return FTL_INIT_ERROR_ERASE_FAIL;
	}

	if ((path_trace == NULL) && ((path_trace = rtos_mem_zmalloc(MAX_FILE_NAME_LEN + 1)) == NULL)) {
		RTK_LOGS(TAG, RTK_LOG_ERROR, "ftl_init fail\r\n");
		return FTL_INIT_ERROR_ERASE_FAIL;
	}

	prefix = find_vfs_tag(VFS_REGION_1);
	if (prefix == NULL) {
		RTK_LOGS(TAG, RTK_LOG_ERROR, "littlefs init fail\r\n");
		return FTL_INIT_ERROR_ERASE_FAIL;
	}

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	DiagSnPrintf(path, MAX_FILE_NAME_LEN + 1, "%s/%s", prefix, FTL_FILE_NAME);
#else
	DiagSnPrintf(path, MAX_FILE_NAME_LEN + 1, "%s:%s", prefix, FTL_FILE_NAME);
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS
	finfo = fopen(path, "r");
	if (finfo == NULL) {
#ifdef CONFIG_PLATFORM_TIZENRT_OS
		finfo = fopen(path, "w+");
#else
		finfo = fopen(path, "+");
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS
		if (finfo == NULL) {
			RTK_LOGS(TAG, RTK_LOG_ERROR, "littlefs open file error\r\n");
			return FTL_INIT_ERROR_ERASE_FAIL;
		}
	}

	fclose(finfo);

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	DiagSnPrintf(path_trace, MAX_FILE_NAME_LEN + 1, "%s/%s", prefix, FTL_TRACE_FILE_NAME);
#else
	DiagSnPrintf(path_trace, MAX_FILE_NAME_LEN + 1, "%s:%s", prefix, FTL_TRACE_FILE_NAME);
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS
	finfo = fopen(path_trace, "r");
	if (finfo == NULL) {
#ifdef CONFIG_PLATFORM_TIZENRT_OS
		finfo = fopen(path_trace, "w+");
#else
		finfo = fopen(path_trace, "+");
#endif //#ifdef CONFIG_PLATFORM_TIZENRT_OS
		if (finfo == NULL) {
			RTK_LOGS(TAG, RTK_LOG_ERROR, "littlefs open file error\r\n");
			return FTL_INIT_ERROR_ERASE_FAIL;
		}
	}

	fclose(finfo);

	printf("init ftl lfs file success\r\n");

	rtos_mutex_create(&ftl_op_mux);

	return 0;
}






