/**
  ******************************************************************************
  * @file    inic_ipc_host_api.c
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

#include "inic_ipc.h"
#include "lwip_netconf.h"
#include "inic_ipc_cfg.h"
#include "wifi_ind.h"

/* -------------------------------- Defines --------------------------------- */
#define CONFIG_INIC_IPC_HOST_API_PRIO 3
#define WIFI_STACK_SIZE_INIC_IPC_HST_API (2880 + 128 + CONTEXT_SAVE_SIZE)	// for psp overflow when update group key: jira: https://jira.realtek.com/browse/RSWLANQC-1027

/* ---------------------------- Global Variables ---------------------------- */
rtos_sema_t  g_host_inic_api_task_wake_sema = NULL;
rtos_sema_t  g_host_inic_api_message_send_sema = NULL;

rtos_task_t inic_api_host_handler;

// // handle to log queue	//ziv TODO: reimplement fix for mix log
// extern void *g_km4_log_queue;

// // static buffer to hold log message
// static u8 g_inic_ipc_logging_buf[CONFIG_KM4_MAX_LOG_QUEUE_SIZE][CONFIG_KM4_MAX_LOG_BUFFER_SIZE] = { 0 };
// static u8 g_inic_ipc_logging_buf_ctr = 0;

//todo:move to non-cache data section
struct inic_ipc_host_req_msg g_host_ipc_api_request_info __attribute__((aligned(64)));
u32	latest_api_id = 0;  /*for debug*/
#ifdef IPC_DIR_MSG_TX
IPC_MSG_STRUCT g_host_ipc_api_msg __attribute__((aligned(64)));
#endif

/* -------------------------- Function declaration -------------------------- */
#ifdef CONFIG_ENABLE_EAP
extern void eap_autoreconnect_hdl(u8 method_id);
#endif
extern int (*scan_ssid_result_hdl)(char *, int, char *, void *);
extern enum _rtw_result_t (*scan_user_callback_ptr)(unsigned int, void *);
extern enum _rtw_result_t (*scan_each_report_user_callback_ptr)(struct rtw_scan_result *, void *);
extern enum _rtw_result_t (*scan_acs_report_user_callback_ptr)(struct acs_mntr_rpt *acs_mntr_rpt);
extern ap_channel_switch_callback_t p_ap_channel_switch_callback;

extern enum _promisc_result_t (*promisc_user_callback_ptr)(void *);
#ifndef CONFIG_PLATFORM_TIZENRT_OS
extern int dhcps_ip_in_table_check(uint8_t gate, uint8_t d);
#endif
/* ---------------------------- Private Functions --------------------------- */
static void _inic_api_host_scan_user_callback_handler(struct inic_ipc_dev_req_msg *p_ipc_msg)
{
	unsigned int ap_num = p_ipc_msg->param_buf[0];
	void *user_data = (void *)p_ipc_msg->param_buf[1];

	if (scan_user_callback_ptr) {
		scan_user_callback_ptr(ap_num, user_data);
	}
}

static void _inic_api_host_acs_report_callback_handler(struct inic_ipc_dev_req_msg *p_ipc_msg)
{
	struct acs_mntr_rpt *acs_rpt = (struct acs_mntr_rpt *)p_ipc_msg->param_buf[0];
	DCache_Invalidate((u32)acs_rpt, sizeof(struct acs_mntr_rpt));

	if (scan_acs_report_user_callback_ptr) {
		scan_acs_report_user_callback_ptr(acs_rpt);
	}
}

static void _inic_api_host_scan_each_report_callback_handler(struct inic_ipc_dev_req_msg *p_ipc_msg)
{
	struct rtw_scan_result *scanned_ap_info = (struct rtw_scan_result *)p_ipc_msg->param_buf[0];
	void *user_data = (void *)p_ipc_msg->param_buf[1];
	DCache_Invalidate((u32)scanned_ap_info, sizeof(struct rtw_scan_result));

	if (scan_each_report_user_callback_ptr) {
		scan_each_report_user_callback_ptr(scanned_ap_info, user_data);
	}
}

static void _inic_api_host_ap_ch_switch_handler(struct inic_ipc_dev_req_msg *p_ipc_msg)
{
	unsigned char channel = (unsigned char)p_ipc_msg->param_buf[0];
	enum rtw_channel_switch_res res = (enum rtw_channel_switch_res)p_ipc_msg->param_buf[1];

	if (p_ap_channel_switch_callback) {
		p_ap_channel_switch_callback(channel, res);
	}
}

static void _inic_api_host_wifi_event_handler(struct inic_ipc_dev_req_msg *p_ipc_msg)
{
	enum rtw_event_indicate event = (enum rtw_event_indicate)p_ipc_msg->param_buf[0];
	char *buf = (char *)p_ipc_msg->param_buf[1];
	int buf_len = (int)p_ipc_msg->param_buf[2];
	int flags = (int)p_ipc_msg->param_buf[3];
	DCache_Invalidate((u32)buf, buf_len);

	wifi_indication(event, buf, buf_len, flags);
}

static void _inic_api_host_lwip_info_handler(struct inic_ipc_dev_req_msg *p_ipc_msg)
{
#ifndef CONFIG_MP_SHRINK
	u32 type = (u32)p_ipc_msg->param_buf[0];
	unsigned char *input = (unsigned char *)p_ipc_msg->param_buf[1];
	int idx = p_ipc_msg->param_buf[2];

	switch (type) {
	case INIC_WLAN_GET_IP:
		p_ipc_msg->ret = (u32)LwIP_GetIP(idx);
		DCache_Clean(p_ipc_msg->ret, 4);
		break;
	case INIC_WLAN_GET_GW:
		p_ipc_msg->ret = (u32)LwIP_GetGW(idx);
		DCache_Clean(p_ipc_msg->ret, 4);
		break;
	case INIC_WLAN_GET_GWMSK:
		p_ipc_msg->ret = (u32)LwIP_GetMASK(idx);
		DCache_Clean(p_ipc_msg->ret, 4);
		break;
	case INIC_WLAN_GET_HW_ADDR:
		p_ipc_msg->ret = (u32)LwIP_GetMAC(idx);
		DCache_Clean(p_ipc_msg->ret, 6);
		break;
	case INIC_WLAN_IS_VALID_IP:
		DCache_Invalidate((u32)input, 4);
		p_ipc_msg->ret = LwIP_netif_is_valid_IP(idx, input);
		break;
	}
#else
	(void)p_ipc_msg;
#endif
}

static void _inic_api_host_set_netif_info_handler(struct inic_ipc_dev_req_msg *p_ipc_msg)
{
#ifndef CONFIG_MP_SHRINK
	int idx = (u32)p_ipc_msg->param_buf[0];
	unsigned char *dev_addr = (unsigned char *)p_ipc_msg->param_buf[1];
	DCache_Invalidate((u32)dev_addr, ETH_ALEN);

	LwIP_wlan_set_netif_info(idx, NULL, dev_addr);
#else
	(void)p_ipc_msg;
#endif
}

static u32 _inic_ipc_ip_addr_update_in_wowlan(u32 expected_idle_time, void *param)
{
	/* To avoid gcc warnings */
	(void) expected_idle_time;
	(void) param;
#ifndef CONFIG_MP_SHRINK
	static u8 inic_ipc_old_ip_addr[4] = {0};

	u32 try_cnt = 2500;//wait 5ms
	u8 i;

	u8 *new_addr = LwIP_GetIP(0);
	for (i = 0; i < 4; i++) {
		if (inic_ipc_old_ip_addr[i] != new_addr[i]) {
			goto send;
		}
	}

	return TRUE;

send:
	while (try_cnt) {
		DCache_Invalidate((u32)&g_host_ipc_api_request_info, sizeof(struct inic_ipc_host_req_msg));
		if (g_host_ipc_api_request_info.api_id != INIC_API_PROCESS_DONE) {
			try_cnt --;
			DelayUs(2);
		} else {
			break;
		}
	}

	if (try_cnt == 0) {
		RTK_LOGE(TAG_WLAN_INIC, "update ip addr TO, last inic ipc not hdl\n");
		return _FAIL;
	} else {
		try_cnt = 2500;
	}

	memset(&g_host_ipc_api_request_info, 0, sizeof(struct inic_ipc_host_req_msg));

	g_host_ipc_api_request_info.api_id = INIC_API_WIFI_IP_UPDATE;
	g_host_ipc_api_request_info.param_buf[0] = (u32)LwIP_GetIP(0);
	g_host_ipc_api_request_info.param_buf[1] = (u32)LwIP_GetGW(0);
	DCache_Clean(g_host_ipc_api_request_info.param_buf[0], 4);
	DCache_Clean(g_host_ipc_api_request_info.param_buf[1], 4);

	DCache_Clean((u32)&g_host_ipc_api_request_info, sizeof(struct inic_ipc_host_req_msg));

	memset(&g_host_ipc_api_msg, 0, sizeof(IPC_MSG_STRUCT));
	g_host_ipc_api_msg.msg = (u32)&g_host_ipc_api_request_info;
	g_host_ipc_api_msg.msg_type = IPC_USER_POINT;
	g_host_ipc_api_msg.msg_len = sizeof(struct inic_ipc_host_req_msg);
	DCache_Clean((u32)&g_host_ipc_api_msg, sizeof(IPC_MSG_STRUCT));
	ipc_send_message(IPC_DIR_MSG_TX, IPC_H2D_WIFI_API_TRAN, \
					 &g_host_ipc_api_msg);

	while (try_cnt) {
		DCache_Invalidate((u32)&g_host_ipc_api_request_info, sizeof(struct inic_ipc_host_req_msg));
		if (g_host_ipc_api_request_info.api_id != INIC_API_PROCESS_DONE) {
			try_cnt --;
			DelayUs(2);
		} else {
			break;
		}
	}
	if (try_cnt == 0) {
		/* jira: https://jira.realtek.com/browse/RSWLANQC-1036 */
		RTK_LOGE(TAG_WLAN_INIC, "update ip addr TO, Driver busy\n");
		g_host_ipc_api_request_info.api_id = INIC_API_WIFI_MSG_TO;
		DCache_Clean((u32)&g_host_ipc_api_request_info, sizeof(struct inic_ipc_host_req_msg));
		return _FAIL;
	}
	/* only update old when success */
	memcpy(inic_ipc_old_ip_addr, new_addr, 4);
#endif
	return _SUCCESS;
}

static enum _promisc_result_t _inic_api_host_promisc_user_callback_handler(struct inic_ipc_dev_req_msg *p_ipc_msg)
{
	struct rx_pkt_info *ppktinfo = (struct rx_pkt_info *)p_ipc_msg->param_buf[0];
	enum _promisc_result_t ret = NEED_DRIVER_HANDLE;

	if (promisc_user_callback_ptr) {
		/* invalidate will be safe if callback read mem only */
		DCache_Invalidate((u32)ppktinfo, sizeof(struct rx_pkt_info));
		DCache_Invalidate((u32)ppktinfo->buf, (u32)ppktinfo->len);
		ret = promisc_user_callback_ptr((void *)p_ipc_msg->param_buf[0]);
	}
	return ret;
}

#ifdef CONFIG_BT_COEXIST
__weak void rtk_coex_bt_hci_msg_send(uint8_t type, uint8_t *pdata, uint16_t len)
{
	(void) type;
	(void) pdata;
	(void) len;
}
static void _inic_api_host_wifi_coex_bt_hci_msg_send(struct inic_ipc_dev_req_msg *p_ipc_msg)
{
	u8 type = (u8)p_ipc_msg->param_buf[0];
	u16 length = (u16)p_ipc_msg->param_buf[1];
	u8 *data = (u8 *)p_ipc_msg->param_buf[2];
	DCache_Invalidate((u32)data, length);

	rtk_coex_bt_hci_msg_send(type, data, length);
}
#endif

/* ---------------------------- Public Functions ---------------------------- */
/**
 * @brief  process the ipc message.
 * @param  none.
 * @return none.
 */
void inic_api_host_task_h(void)
{
	struct inic_ipc_dev_req_msg *p_ipc_msg = NULL;

	do {
		rtos_sema_take(g_host_inic_api_task_wake_sema, 0xFFFFFFFF);

#ifdef IPC_DIR_MSG_RX
		PIPC_MSG_STRUCT p_ipc_recv_msg = ipc_get_message(IPC_DIR_MSG_RX, \
										 IPC_D2H_WIFI_API_TRAN);
		p_ipc_msg = (struct inic_ipc_dev_req_msg *)p_ipc_recv_msg->msg;
#else
		p_ipc_msg = (struct inic_ipc_dev_req_msg *)ipc_get_message(IPC_INT_CHAN_WIFI_API_TRAN);
#endif /* IPC_DIR_MSG_RX */

		DCache_Invalidate((u32)p_ipc_msg, sizeof(struct inic_ipc_dev_req_msg));

		if (p_ipc_msg == NULL) {
			RTK_LOGS(TAG_WLAN_INIC, "DEV IPC API msg NULL\n");
			continue;
		}

		switch (p_ipc_msg->enevt_id) {
		/* receive callback indication */
		case INIC_API_SCAN_USER_CALLBACK:
			_inic_api_host_scan_user_callback_handler(p_ipc_msg);
			break;
		case INIC_API_IP_ACS:
			_inic_api_host_acs_report_callback_handler(p_ipc_msg);
			break;
		case INIC_API_SCAN_EACH_REPORT_USER_CALLBACK:
			_inic_api_host_scan_each_report_callback_handler(p_ipc_msg);
			break;
		case INIC_API_AP_CH_SWITCH:
			_inic_api_host_ap_ch_switch_handler(p_ipc_msg);
			break;
		/* receive wifi event indication */
		case INIC_API_HDL:
			_inic_api_host_wifi_event_handler(p_ipc_msg);
			break;
		case INIC_API_GET_LWIP_INFO:
			_inic_api_host_lwip_info_handler(p_ipc_msg);
			break;
		case INIC_API_SET_NETIF_INFO:
			_inic_api_host_set_netif_info_handler(p_ipc_msg);
			break;
		case INIC_API_PROMISC_CALLBACK:
			p_ipc_msg->ret = (int)_inic_api_host_promisc_user_callback_handler(p_ipc_msg);
			break;
#ifndef CONFIG_MP_SHRINK
#ifndef CONFIG_PLATFORM_TIZENRT_OS
		case INIC_API_IP_TABLE_CHK:
			p_ipc_msg->ret = dhcps_ip_in_table_check(p_ipc_msg->param_buf[0], p_ipc_msg->param_buf[1]);
			break;
#endif //CONFIG_PLATFORM_TIZENRT_OS
#endif //CONFIG_MP_SHRINK
#ifdef CONFIG_BT_COEXIST
		case INIC_API_COEX_BT_HCI_MSG_SEND:
			_inic_api_host_wifi_coex_bt_hci_msg_send(p_ipc_msg);
			break;
#endif
		default:
			RTK_LOGS(TAG_WLAN_INIC, "Host API Unknown evt(%x)\n", p_ipc_msg->enevt_id);
			break;
		}
		/*set EVENT_ID to 0 to notify NP that event is finished*/
		p_ipc_msg->enevt_id = 0;
		DCache_Clean((u32)p_ipc_msg, sizeof(struct inic_ipc_dev_req_msg));
	} while (1);
	rtos_task_delete(NULL);
}

/**
 * @brief  to haddle the ipc message interrupt, wakeup event task to process.
 * @param  Data[inout]: IPC data.
 * @param  IrqStatus[in]: interrupt status.
 * @param  ChanNum[in]: IPC channel number.
 * @return none.
 */
void inic_api_host_int_hdl(void *Data, u32 IrqStatus, u32 ChanNum)
{
	/* To avoid gcc warnings */
	(void) Data;
	(void) IrqStatus;
	(void) ChanNum;

	/* wakeup task */
	rtos_sema_give(g_host_inic_api_task_wake_sema);
}

/**
 * @brief  to send a ipc message to device and wait result.
 * @param  ID[in]: api_id.
 * @param  param_buf[in]: pointer to API parameter.
 * @return result of API.
 */
int inic_api_host_message_send(u32 id, u32 *param_buf, u32 buf_len)
{
	int ret = 0;
	latest_api_id = id;
	rtos_sema_take(g_host_inic_api_message_send_sema, 0xFFFFFFFF);
	int cnt = 0;

	while (1) {
		DCache_Invalidate((u32)&g_host_ipc_api_request_info, sizeof(struct inic_ipc_host_req_msg));
		if (g_host_ipc_api_request_info.api_id != INIC_API_PROCESS_DONE) {
			rtos_time_delay_ms(1);
			/*When blocking scan is invoked in BT COEXIST, the scan time may increases due to TDMA scan, up to 8.96s (5G) +2.17s (2.4G)*/
			cnt = (cnt + 1) % 12000;
		} else {
			break;
		}
		if (cnt == 0) {
			RTK_LOGS(TAG_WLAN_INIC, "last inic ipc not hdl \n");
		}
	}

	memset(&g_host_ipc_api_request_info, 0, sizeof(struct inic_ipc_host_req_msg));

	g_host_ipc_api_request_info.api_id = id;
	if (param_buf != NULL) {
		memcpy(g_host_ipc_api_request_info.param_buf, param_buf, buf_len * sizeof(u32));
	}
	DCache_Clean((u32)&g_host_ipc_api_request_info, sizeof(struct inic_ipc_host_req_msg));

#ifdef IPC_DIR_MSG_TX
	memset(&g_host_ipc_api_msg, 0, sizeof(IPC_MSG_STRUCT));
	g_host_ipc_api_msg.msg = (u32)&g_host_ipc_api_request_info;
	g_host_ipc_api_msg.msg_type = IPC_USER_POINT;
	g_host_ipc_api_msg.msg_len = sizeof(struct inic_ipc_host_req_msg);
	DCache_Clean((u32)&g_host_ipc_api_msg, sizeof(IPC_MSG_STRUCT));

	ipc_send_message(IPC_DIR_MSG_TX, IPC_H2D_WIFI_API_TRAN, \
					 &g_host_ipc_api_msg);
#else
	ipc_send_message(IPC_INT_CHAN_WIFI_API_TRAN, &g_host_ipc_api_request_info);
#endif /* IPC_DIR_MSG_TX */

	while (1) {
		if (g_host_ipc_api_request_info.api_id != INIC_API_PROCESS_DONE) {
			rtos_time_delay_ms(1);
			DCache_Invalidate((u32)&g_host_ipc_api_request_info, sizeof(struct inic_ipc_host_req_msg));
			/*When blocking scan is invoked in BT COEXIST, the scan time may increases due to TDMA scan, up to 8.96s (5G) +2.17s (2.4G)*/
			cnt = (cnt + 1) % 12000;
		} else {
			break;
		}
		if (cnt == 0) {
			RTK_LOGS(TAG_WLAN_INIC, "HstMsgSend wait inic ipc done 0x%x, 0x%x\n", g_host_ipc_api_request_info.api_id, latest_api_id);
		}
	}
	ret = g_host_ipc_api_request_info.ret;
	rtos_sema_give(g_host_inic_api_message_send_sema);
	return ret;
}

/**
 * @brief  to initialize the ipc host for WIFI api.
 * @param  none.
 * @return none.
 */
void inic_api_init_host(void)
{
	/* initialize the semaphores */
	rtos_sema_create_static(&g_host_inic_api_task_wake_sema, 0, 0xFFFFFFFF);
	rtos_sema_create_static(&g_host_inic_api_message_send_sema, 0, 0xFFFFFFFF);
	rtos_sema_give(g_host_inic_api_message_send_sema);

	/*for updating ip address before sleep*/
	pmu_register_sleep_callback(PMU_WLAN_DEVICE, (PSM_HOOK_FUN)_inic_ipc_ip_addr_update_in_wowlan, NULL, NULL, NULL);

	/* Initialize the event task */
	if (SUCCESS != rtos_task_create(&inic_api_host_handler, (const char *const)"inic_api_host_task", (rtos_task_function_t)inic_api_host_task_h, NULL,
									WIFI_STACK_SIZE_INIC_IPC_HST_API, CONFIG_INIC_IPC_HOST_API_PRIO)) {
		RTK_LOGE(TAG_WLAN_INIC, "Create api_host_task Err\n");
	}
}

u64 inic_host_get_wifi_tsf(unsigned char port_id)
{
	u64 ret = 0;

	if ((HAL_READ32(WIFI_REG_BASE, 0xA4) & 0x7F00) == BIT13) {
		/* in ips flow, it will return 0 or will be hang, thus need additional check*/
		if (port_id == 0) {
			ret = (((u64) HAL_READ32(WIFI_REG_BASE, 0x564)) << 32) | HAL_READ32(WIFI_REG_BASE, 0x560); //REG_P0_TSFTR
		} else if (port_id == 1) {
			ret = (((u64) HAL_READ32(WIFI_REG_BASE, 0x56C)) << 32) | HAL_READ32(WIFI_REG_BASE, 0x568); //REG_P1_TSFTR
		}
	} else {
		ret = 0; /* !pon state */
	}

	return ret;
}

int inic_host_get_txbuf_pkt_num(void)
{
	int ret = 0;
#ifdef CONFIG_AMEBASMART
	u16 queue0_info = (HAL_READ16(WIFI_REG_BASE, 0x400) & 0x7F00) >> 8;//REG_Q0_INFO
	u16 queue1_info = (HAL_READ16(WIFI_REG_BASE, 0x404) & 0x7F00) >> 8;//REG_Q1_INFO
	u16 queue2_info = (HAL_READ16(WIFI_REG_BASE, 0x408) & 0x7F00) >> 8;//REG_Q2_INFO
	u16 queue3_info = (HAL_READ16(WIFI_REG_BASE, 0x40C) & 0x7F00) >> 8;//REG_Q3_INFO
	u16 mgnt_queue_info = (HAL_READ16(WIFI_REG_BASE, 0x410) & 0x7F00) >> 8;//REG_MGQ_INFO
	u16 high_queue_info = (HAL_READ16(WIFI_REG_BASE, 0x414) & 0x7F00) >> 8;//REG_HIQ_INFO
	ret = queue0_info + queue1_info + queue2_info + queue3_info + mgnt_queue_info + high_queue_info;
#endif
	return ret;

}

int inic_iwpriv_command(char *cmd, unsigned int cmd_len, int show_msg)
{
	int ret = 0;
	u32 param_buf[3];

	param_buf[0] = (u32)cmd;
	param_buf[1] = (u32)cmd_len;
	param_buf[2] = (u32)show_msg;
	DCache_Clean((u32)cmd, cmd_len);

	ret = inic_api_host_message_send(INIC_API_WIFI_IWPRIV_INFO, param_buf, 3);
	DCache_Invalidate((u32)cmd, 32);  /*read output log for some cmds */
	return ret;
}

void inic_ipc_buffered_printf_set_np_enable(u8 enable)
{
	u32 param_buf[1];
	param_buf[0] = (u32)enable;
	inic_api_host_message_send(INIC_API_BUFFERED_PRINTF_SET_NP_EN, param_buf, 1);
}

void inic_mp_command(char *token, unsigned int cmd_len, int show_msg)
{
	u32 param_buf[4];
#if defined(CONFIG_BT_ENABLE_FAST_MP) && CONFIG_BT_ENABLE_FAST_MP
	extern void bt_fast_mp_cmd_handle_api(void *arg);
	if (strncmp(token, "fastmp ", strlen("fastmp ")) == 0) {
		bt_fast_mp_cmd_handle_api(token);
	}
#endif
	char *user_buf = (char *)rtos_mem_zmalloc(INIC_MP_MSG_BUF_SIZE); //support max buf for PSD
	if (user_buf == NULL) {
		RTK_LOGE(TAG_WLAN_INIC, "inic_mp_command fail\n");
		return;
	}

	param_buf[0] = (u32)token;
	param_buf[1] = (u32)cmd_len;
	param_buf[2] = (u32)show_msg;
	param_buf[3] = (u32)user_buf;
	DCache_Clean((u32)user_buf, INIC_MP_MSG_BUF_SIZE);
	DCache_Clean((u32)token, cmd_len);

	inic_api_host_message_send(INIC_API_WIFI_MP_CMD, param_buf, 4);
	/* user_buf contains mp command result(in string format) from NP core,
	Dcache_Invalidate user_buf before use it */
	if (show_msg) {
		DCache_Invalidate((u32)user_buf, INIC_MP_MSG_BUF_SIZE);
		RTK_LOGA(TAG_WLAN_INIC, "Private Message: %s\n", user_buf);
	}
	rtos_mem_free((u8 *)user_buf);
}

#ifdef CONFIG_WIFI_TUNNEL
int inic_wltunnel_command(char *cmd, unsigned int cmd_len)
{
	int ret = 0;
	u32 param_buf[2];

	param_buf[0] = (u32)cmd;
	param_buf[1] = (u32)cmd_len;
	DCache_Clean((u32)cmd, cmd_len);

	ret = inic_api_host_message_send(INIC_API_WTN_CMD, param_buf, 2);
	DCache_Invalidate((u32)cmd, 32);  /*read output log for some cmds */
	return ret;
}
#endif

/* ---------------------------- Global Variables ---------------------------- */
