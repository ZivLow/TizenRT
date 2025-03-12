/**
  ******************************************************************************
  * @file    inic_ipc_host.c
  * @author
  * @version
  * @date
  * @brief
  ******************************************************************************
  * @attention
  *
  * This module is a confidential and proprietary property of RealTek and
  * possession or use of this module requires written permission of RealTek.
  *
  * Copyright(c) 2024, Realtek Semiconductor Corporation. All rights reserved.
  ******************************************************************************
  */

#include "inic_ipc_host_trx.h"
#include "inic_ipc_msg_queue.h"
#define CONFIG_ENABLE_CACHE

/* -------------------------------- Defines --------------------------------- */

/* -------------------------------- Macros ---------------------------------- */

/* --------------------------- Private Variables ---------------------------- */

/* ---------------------------- Private Functions --------------------------- */

/**
 * @brief  to initialize the ipc host for the inic.
 * @param  none.
 * @return none.
 */
void inic_host_init(void)
{
	/* Move message queue init after user config set*/

	/* Initialize the parameters of ipc host. */
	inic_host_init_priv();

	inic_api_init_host();
}
/* ---------------------------- Global Variables ---------------------------- */
IPC_TABLE_DATA_SECTION
const IPC_INIT_TABLE ipc_host_event_table = {
	.USER_MSG_TYPE = IPC_USER_POINT,
	.Rxfunc = inic_host_trx_int_hdl,
	.RxIrqData = (void *) NULL,
	.Txfunc = IPC_TXHandler,
	.TxIrqData = (void *) NULL,
	.IPC_Direction = IPC_DIR_MSG_RX,
	.IPC_Channel = IPC_D2H_WIFI_TRX_TRAN
};

IPC_TABLE_DATA_SECTION
const IPC_INIT_TABLE ipc_api_host_table = {
	.USER_MSG_TYPE = IPC_USER_POINT,
	.Rxfunc = inic_api_host_int_hdl,
	.RxIrqData = (void *) NULL,
	.Txfunc = IPC_TXHandler,
	.TxIrqData = (void *) NULL,
	.IPC_Direction = IPC_DIR_MSG_RX,
	.IPC_Channel = IPC_D2H_WIFI_API_TRAN
};

