/****************************************************************************
 *
 * Copyright 2025 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * os/board/rtl8721f/src/rtl8721f_lfs_mtd.c
 *
 * MTD adapter that wraps Realtek's NOR flash callbacks into a TizenRT
 * struct mtd_dev_s.  This allows TizenRT's standard LittleFS mount path
 * (little_initialize + mount("littlefs")) to work with the on-chip NOR
 * flash region reserved for the virtual file-system (VFS).
 *
 * Geometry reported to lfs_vfs.c (littlefs_bind):
 *   blocksize    = 256   (min R/W unit -> lfs read_size/prog_size/cache_size)
 *   erasesize    = 4096  (flash sector  -> lfs block_size)
 *   neraseblocks = LFS_FLASH_SIZE / 4096
 *
 * The bread/bwrite callbacks operate in 256-byte blocks.
 * The erase callback operates in 4096-byte erase-blocks.
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <tinyara/config.h>

#include <sys/types.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <debug.h>

#include <tinyara/fs/mtd.h>
#include <tinyara/fs/ioctl.h>
#include <tinyara/kmalloc.h>

#include "flash_api.h"
#include "littlefs_adapter.h"

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

/* Minimum read/write unit exposed to LittleFS via MTD geometry.
 * littlefs_bind() sets:  read_size = prog_size = cache_size = blocksize.
 * Realtek's original config uses cache_size=256, so 256 is a good choice.
 */
#define RTK_LFS_MTD_BLOCKSIZE   256

/* Erase block size – matches NOR flash sector size (4 KiB). */
#define RTK_LFS_MTD_ERASESIZE   4096

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct rtk_lfs_mtd_s {
	struct mtd_dev_s mtd;      /* Must be first – MTD macros cast to this */
	uint32_t        base_addr; /* Flash base address for LFS region */
	uint32_t        flash_size;/* Total flash size for LFS region */
};

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static int     rtk_lfs_mtd_erase(FAR struct mtd_dev_s *dev, off_t startblock, size_t nblocks);
static ssize_t rtk_lfs_mtd_bread(FAR struct mtd_dev_s *dev, off_t startblock, size_t nblocks, FAR uint8_t *buffer);
static ssize_t rtk_lfs_mtd_bwrite(FAR struct mtd_dev_s *dev, off_t startblock, size_t nblocks, FAR const uint8_t *buffer);
static int     rtk_lfs_mtd_ioctl(FAR struct mtd_dev_s *dev, int cmd, unsigned long arg);

/****************************************************************************
 * Private Functions
 ****************************************************************************/

/****************************************************************************
 * Name: rtk_lfs_mtd_erase
 *
 * Description:
 *   Erase 'nblocks' erase-blocks starting at 'startblock'.
 *   Each erase-block is RTK_LFS_MTD_ERASESIZE (4096) bytes.
 ****************************************************************************/

static int rtk_lfs_mtd_erase(FAR struct mtd_dev_s *dev, off_t startblock, size_t nblocks)
{
	FAR struct rtk_lfs_mtd_s *priv = (FAR struct rtk_lfs_mtd_s *)dev;
	flash_t flash;
	size_t i;

	for (i = 0; i < nblocks; i++) {
		uint32_t addr = priv->base_addr + (startblock + i) * RTK_LFS_MTD_ERASESIZE;
		flash_erase_sector(&flash, addr);
	}

	return (int)nblocks;
}

/****************************************************************************
 * Name: rtk_lfs_mtd_bread
 *
 * Description:
 *   Read 'nblocks' blocks starting at 'startblock' into 'buffer'.
 *   Each block is RTK_LFS_MTD_BLOCKSIZE (256) bytes.
 *   Returns number of blocks read, or negative errno.
 ****************************************************************************/

static ssize_t rtk_lfs_mtd_bread(FAR struct mtd_dev_s *dev, off_t startblock,
				  size_t nblocks, FAR uint8_t *buffer)
{
	FAR struct rtk_lfs_mtd_s *priv = (FAR struct rtk_lfs_mtd_s *)dev;
	flash_t flash;
	uint32_t addr = priv->base_addr + startblock * RTK_LFS_MTD_BLOCKSIZE;
	uint32_t len  = nblocks * RTK_LFS_MTD_BLOCKSIZE;

	flash_stream_read(&flash, addr, len, buffer);

	return (ssize_t)nblocks;
}

/****************************************************************************
 * Name: rtk_lfs_mtd_bwrite
 *
 * Description:
 *   Write 'nblocks' blocks starting at 'startblock' from 'buffer'.
 *   Each block is RTK_LFS_MTD_BLOCKSIZE (256) bytes.
 *   Returns number of blocks written, or negative errno.
 ****************************************************************************/

static ssize_t rtk_lfs_mtd_bwrite(FAR struct mtd_dev_s *dev, off_t startblock,
				   size_t nblocks, FAR const uint8_t *buffer)
{
	FAR struct rtk_lfs_mtd_s *priv = (FAR struct rtk_lfs_mtd_s *)dev;
	flash_t flash;
	uint32_t addr = priv->base_addr + startblock * RTK_LFS_MTD_BLOCKSIZE;
	uint32_t len  = nblocks * RTK_LFS_MTD_BLOCKSIZE;

	flash_stream_write(&flash, addr, len, (uint8_t *)buffer);

	return (ssize_t)nblocks;
}

/****************************************************************************
 * Name: rtk_lfs_mtd_ioctl
 *
 * Description:
 *   Handle MTD ioctls.  Only MTDIOC_GEOMETRY is required by littlefs_bind().
 ****************************************************************************/

static int rtk_lfs_mtd_ioctl(FAR struct mtd_dev_s *dev, int cmd, unsigned long arg)
{
	FAR struct rtk_lfs_mtd_s *priv = (FAR struct rtk_lfs_mtd_s *)dev;

	switch (cmd) {
	case MTDIOC_GEOMETRY: {
		FAR struct mtd_geometry_s *geo = (FAR struct mtd_geometry_s *)arg;
		if (!geo) {
			return -EINVAL;
		}

		geo->blocksize    = RTK_LFS_MTD_BLOCKSIZE;
		geo->erasesize    = RTK_LFS_MTD_ERASESIZE;
		geo->neraseblocks = priv->flash_size / RTK_LFS_MTD_ERASESIZE;
		memset(geo->model, 0, sizeof(geo->model));
		strncpy(geo->model, "rtk-nor-lfs", sizeof(geo->model) - 1);
		return OK;
	}

	case MTDIOC_BULKERASE: {
		/* Erase the entire LFS region */
		uint32_t nblocks = priv->flash_size / RTK_LFS_MTD_ERASESIZE;
		return rtk_lfs_mtd_erase(dev, 0, nblocks);
	}

	default:
		return -ENOTTY;
	}
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: rtk_lfs_mtd_initialize
 *
 * Description:
 *   Allocate and initialise an MTD device backed by the Realtek NOR flash
 *   region described by LFS_FLASH_BASE_ADDR / LFS_FLASH_SIZE (which must
 *   already be populated, e.g. via vfs_assign_region()).
 *
 * Returned Value:
 *   Pointer to struct mtd_dev_s on success, NULL on failure.
 ****************************************************************************/

FAR struct mtd_dev_s *rtk_lfs_mtd_initialize(void)
{
	FAR struct rtk_lfs_mtd_s *priv;

	if (LFS_FLASH_SIZE == 0) {
		dbg("ERROR: LFS_FLASH_SIZE is 0 – call vfs_assign_region() first\n");
		return NULL;
	}

	priv = (FAR struct rtk_lfs_mtd_s *)kmm_zalloc(sizeof(struct rtk_lfs_mtd_s));
	if (!priv) {
		dbg("ERROR: Failed to allocate rtk_lfs_mtd_s\n");
		return NULL;
	}

	priv->base_addr  = LFS_FLASH_BASE_ADDR;
	priv->flash_size = LFS_FLASH_SIZE;

	/* Wire up MTD operations */
	priv->mtd.erase  = rtk_lfs_mtd_erase;
	priv->mtd.bread  = rtk_lfs_mtd_bread;
	priv->mtd.bwrite = rtk_lfs_mtd_bwrite;
	priv->mtd.read   = NULL;  /* byte-level read not needed by LittleFS */
#ifdef CONFIG_MTD_BYTE_WRITE
	priv->mtd.write  = NULL;
#endif
	priv->mtd.ioctl  = rtk_lfs_mtd_ioctl;
	priv->mtd.isbad  = NULL;
	priv->mtd.markbad = NULL;

	return &priv->mtd;
}
