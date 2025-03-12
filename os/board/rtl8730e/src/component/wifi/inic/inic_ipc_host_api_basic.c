/**
  ******************************************************************************
  * @file    inic_ipc_host_api_basic.c
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

#include "rtw_wifi_constants.h"
#ifdef CONFIG_LWIP_LAYER
#include <lwip_netconf.h>
#ifndef CONFIG_PLATFORM_TIZENRT_OS
#include <dhcp/dhcps.h>
#endif
#endif

#include <wifi_ind.h>
#include <os_wrapper.h>
#include <rtw_timer.h>
#include <rtw_wakelock.h>

#if defined(CONFIG_AS_INIC_AP)
#include "inic_ipc.h"
#include "inic_ipc_msg_queue.h"
#endif
#include <wifi_intf_ram_to_rom.h>
#include "wpa_lite_intf.h"
#ifndef CONFIG_PLATFORM_TIZENRT_OS
#include "rom_hal_rom_to_flash.h"
#endif //#ifndef CONFIG_PLATFORM_TIZENRT_OS
#if CONFIG_AUTO_RECONNECT
#include <wifi_auto_reconnect.h>
#endif //CONFIG_AUTO_RECONNECT
/******************************************************
 *                    Constants
 ******************************************************/
#define RTW_JOIN_TIMEOUT  (3 * 12000 + 6500 + 50) //(MAX_CNT_SCAN_TIMES * SCANNING_TIMEOUT + MAX_JOIN_TIMEOUT + 50) // should big enough to cover max scan time, or no dhcp
/******************************************************
 *               Variables Declarations
 ******************************************************/

/******************************************************
 *               Variables Definitions
 ******************************************************/
struct internal_join_block_param *join_block_param = NULL;

enum _rtw_result_t (*scan_user_callback_ptr)(unsigned int, void *) = NULL;
enum _rtw_result_t (*scan_each_report_user_callback_ptr)(struct rtw_scan_result *, void *) = NULL;
enum _rtw_result_t (*scan_acs_report_user_callback_ptr)(struct acs_mntr_rpt *acs_mntr_rpt) = NULL;

enum _promisc_result_t (*promisc_user_callback_ptr)(struct rx_pkt_info *pkt_info) = NULL;

extern void *param_indicator;
enum rtw_join_status_type rtw_join_status;
enum _rtw_result_t join_fail_reason = RTW_SUCCESS;

wifi_do_fast_connect_ptr p_wifi_do_fast_connect = NULL;
write_fast_connect_info_ptr p_store_fast_connect_info = NULL;
wifi_jioninfo_free_ptr p_wifi_join_info_free = NULL;
/* Give default value if not defined */
/******************************************************
 *               Function Definitions
 ******************************************************/

#if CONFIG_WLAN

#ifdef CONFIG_PLATFORM_TIZENRT_OS
#include "rtk_wifi_utils.h"
rtk_network_link_callback_t g_link_up = NULL;
rtk_network_link_callback_t g_link_down = NULL;

typedef void (*rtk_network_link_callback_t)(rtk_reason_t *reason);

int8_t WiFiRegisterLinkCallback(rtk_network_link_callback_t link_up, rtk_network_link_callback_t link_down)
{
	if (!g_link_up) {
		g_link_up = link_up;
	}
	if (!g_link_down) {
		g_link_down = link_down;
	}

	return RTK_STATUS_SUCCESS;
}

extern void linkup_handler(rtk_reason_t *reason);
extern void linkdown_handler(rtk_reason_t *reason);

static void wifi_conn_hdl(char *buf, int buf_len, int flags, void *handler_user_data)
{
	/* To avoid gcc warnings */
	( void ) buf;
	( void ) buf_len;
	( void ) handler_user_data;

	enum rtw_join_status_type join_status = (enum rtw_join_status_type)flags;
	if (join_status == RTW_JOINSTATUS_SUCCESS) {
		if (g_link_up) {
			nvdbg("RTK_API %s() send link_up\n", __func__);
			rtk_reason_t reason = {0};
			reason.reason_code = join_status;
			g_link_up(&reason);
		}
	}
}

static void wifi_disconn_hdl(char *buf, int buf_len, int flags, void *handler_user_data)
{
	/* To avoid gcc warnings */
	( void ) buf;
	( void ) buf_len;
	( void ) handler_user_data;

	enum rtw_join_status_type join_status = (enum rtw_join_status_type)flags;
	if ((join_status == RTW_JOINSTATUS_DISCONNECT) || (join_status == RTW_JOINSTATUS_FAIL)) {
		if (g_link_down) {
			nvdbg("RTK_API %s() send link_down\n", __func__);
			rtk_reason_t reason = {0};
			reason.reason_code = join_status;
			g_link_down(&reason);
		}
		wifi_unreg_event_handler(WIFI_EVENT_JOIN_STATUS, wifi_disconn_hdl);
	}
}
#endif //CONFIG_PLATFORM_TIZENRT_OS

static void *_my_calloc(size_t nelements, size_t elementSize)
{
	size_t size;
	void *ptr = NULL;

	size = nelements * elementSize;
	ptr = rtos_mem_zmalloc(size);

	return ptr;
}

static void _my_free(void *pbuf)
{
	rtos_mem_free(pbuf);
}

static int _my_random(void *p_rng, unsigned char *output, size_t output_len)
{
	/* To avoid gcc warnings */
	(void) p_rng;

	TRNG_get_random_bytes(output, output_len);
	return 0;
}
int wifi_set_platform_rom_func(void *(*calloc_func)(size_t, size_t),
							   void (*free_func)(void *),
							   int (*rand_func)(void *, unsigned char *, size_t))
{
	/* Realtek added to initialize HW crypto function pointers
	* mbedtls RAM codes use function pointers in platform memory implementation
	* Not use malloc/free in ssl ram map for mbedtls RAM codes
	*/
	p_wifi_rom_func_map = (struct _wifi_rom_func_map *)&wifi_rom_func_map;
	p_wifi_rom_func_map->zmalloc = calloc_func;
	p_wifi_rom_func_map->mfree = free_func;
	p_wifi_rom_func_map->random = rand_func;

	return (0);
}

#ifndef CONFIG_PLATFORM_TIZENRT_OS
static void wifi_set_platform_rom_os_func(void)
{
	/* Realtek added for code in rom
	*/
	p_wifi_rom2flash = (struct _wifi_rom_to_flash_func_map *)&wifi_rom2flash;

	/* mutex */
	p_wifi_rom2flash->rtw_rtos_mutex_give_t = rtos_mutex_give;
	p_wifi_rom2flash->rtw_rtos_mutex_take_t = rtos_mutex_take;
	p_wifi_rom2flash->rtos_mutex_delete_static_t = rtos_mutex_delete_static;
	p_wifi_rom2flash->rtos_mutex_create_static_t = rtos_mutex_create_static;

	/* sema */
	p_wifi_rom2flash->rtos_sema_give = rtos_sema_give;
	p_wifi_rom2flash->rtos_sema_take = rtos_sema_take;

	/* critical */
	p_wifi_rom2flash->rtw_rtos_critical_enter_t = rtos_critical_enter;
	p_wifi_rom2flash->rtw_rtos_critical_exit_t = rtos_critical_exit;

	/* os */
	p_wifi_rom2flash->rtos_time_delay_ms_t = rtos_time_delay_ms;
	p_wifi_rom2flash->rtos_time_get_current_system_time_ms = rtos_time_get_current_system_time_ms;

	/* timer */
	p_wifi_rom2flash->rtw_init_timer_t = rtw_init_timer;
	p_wifi_rom2flash->rtw_set_timer_t = rtw_set_timer;

	p_wifi_rom2flash->rtw_cancel_timer_t = rtw_cancel_timer;
	p_wifi_rom2flash->rtw_del_timer_t = rtw_del_timer;

	/* pmu */
	p_wifi_rom2flash->pmu_set_sysactive_time_t = pmu_set_sysactive_time;
	p_wifi_rom2flash->rtw_wakelock_timeout = rtw_wakelock_timeout;

	/* wakelock */
	p_wifi_rom2flash->rtw_acquire_wakelock_t = rtw_acquire_wakelock;
	p_wifi_rom2flash->rtw_release_wakelock_t = rtw_release_wakelock;

	/* skbuff not in ap*/
}
#endif //#ifndef CONFIG_PLATFORM_TIZENRT_OS

void wifi_set_rom2flash(void)
{
	wifi_set_platform_rom_func(_my_calloc, _my_free, _my_random);
#ifndef CONFIG_PLATFORM_TIZENRT_OS
	wifi_set_platform_rom_os_func();
#endif //#ifndef CONFIG_PLATFORM_TIZENRT_OS
}

//----------------------------------------------------------------------------//
int wifi_connect(struct _rtw_network_info_t *connect_param, unsigned char block)
{
	enum _rtw_result_t result = RTW_SUCCESS;
	struct internal_join_block_param *block_param = NULL;
	u32 param_buf[1] = {0};
	u8 no_need_indicate = 0;
	struct rtw_event_join_fail_info_t fail_info = {0};

	/* check if SoftAP is running */
	if ((wifi_user_config.concurrent_enabled == _FALSE) && wifi_is_running(SOFTAP_WLAN_INDEX)) {
		RTK_LOGE(TAG_WLAN_INIC, "ap running, please set concurrent_enabled in wifi_set_user_config\n");
		return RTW_ERROR;
	}

	if (connect_param == NULL) {
		RTK_LOGE(TAG_WLAN_INIC, "connect param not set!\n");
		return RTW_ERROR;
	}

	/* step1: check if there's ongoing connect*/
	if ((rtw_join_status > RTW_JOINSTATUS_UNKNOWN) && (rtw_join_status < RTW_JOINSTATUS_SUCCESS)) {
		RTK_LOGD(TAG_WLAN_INIC, "on wifi connect\n");
		return RTW_BUSY;
	}

	/*clear for last connect status */
	rtw_join_status = RTW_JOINSTATUS_STARTING;
	wifi_indication(WIFI_EVENT_JOIN_STATUS, NULL, 0, RTW_JOINSTATUS_STARTING);

	/* step2: malloc and set synchronous connection related variables*/
	if (block) {
		block_param = (struct internal_join_block_param *)rtos_mem_zmalloc(sizeof(struct internal_join_block_param));
		if (!block_param) {
			result = (enum _rtw_result_t) RTW_NOMEM;
			rtw_join_status = RTW_JOINSTATUS_FAIL;
			goto error;
		}
		block_param->block = block;
		rtos_sema_create_static(&block_param->join_sema, 0, 0xFFFFFFFF);
		if (!block_param->join_sema) {
			result = (enum _rtw_result_t) RTW_NOMEM;
			rtw_join_status = RTW_JOINSTATUS_FAIL;
			goto error;
		}

	}

#if CONFIG_AUTO_RECONNECT
	rtw_reconn_new_conn(connect_param);/*auto reconn backup connnect parameters*/
#endif

	/* step3: set connect cmd to driver*/
	if (connect_param->password_len) {
		DCache_Clean((u32)connect_param->password, connect_param->password_len);
	}
	DCache_Clean((u32)connect_param, sizeof(struct _rtw_network_info_t));
	param_buf[0] = (u32)connect_param;

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	/* Register disconnect handler before starting join */
	wifi_reg_event_handler(WIFI_EVENT_JOIN_STATUS, wifi_conn_hdl, NULL);
	wifi_reg_event_handler(WIFI_EVENT_JOIN_STATUS, wifi_disconn_hdl, NULL);
#endif //CONFIG_PLATFORM_TIZENRT_OS

	result = inic_api_host_message_send(INIC_API_WIFI_CONNECT, param_buf, 1);

	if (result != RTW_SUCCESS) {
		rtw_join_status = RTW_JOINSTATUS_FAIL;
		goto error;
	}

	/* step4: wait connect finished for synchronous connection*/
	if (block) {
		join_block_param = block_param;

#ifdef CONFIG_ENABLE_EAP
		// for eap connection, timeout should be longer (default value in wpa_supplicant: 60s)
		if (wifi_get_eap_phase()) {
			block_param->join_timeout = 60000;
		} else
#endif
			block_param->join_timeout = RTW_JOIN_TIMEOUT;

		if (rtos_sema_take(block_param->join_sema, block_param->join_timeout) != SUCCESS) {
			RTK_LOGE(TAG_WLAN_INIC, "Join bss timeout\n");
			rtw_join_status = RTW_JOINSTATUS_FAIL;
			result = RTW_TIMEOUT;
			goto error;
		} else {
			if (wifi_is_connected_to_ap() != RTW_SUCCESS) {
				result = join_fail_reason;
				no_need_indicate = 1;/*already indicated in join fail event handle*/
				goto error;
			}
		}
	}

error:
	if (block_param) {
		if (block_param->join_sema) {
			rtos_sema_delete_static(block_param->join_sema);
		}
		rtos_mem_free((u8 *)block_param);
		join_block_param = NULL;
	}

	if (rtw_join_status == RTW_JOINSTATUS_FAIL && no_need_indicate == 0) {
		fail_info.fail_reason = result;
		wifi_indication(WIFI_EVENT_JOIN_STATUS, (char *)&fail_info, sizeof(struct rtw_event_join_fail_info_t), RTW_JOINSTATUS_FAIL);
	}

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	wifi_unreg_event_handler(WIFI_EVENT_JOIN_STATUS, wifi_conn_hdl);
#endif //CONFIG_PLATFORM_TIZENRT_OS

	return result;
}

int wifi_disconnect(void)
{
	int ret = 0;

	ret = inic_api_host_message_send(INIC_API_WIFI_DISCONNECT, NULL, 0);
	return ret;
}

//----------------------------------------------------------------------------//
int wifi_is_running(unsigned char wlan_idx)
{
	int ret;
	u32 param_buf[1];
	param_buf[0] = wlan_idx;

	ret = inic_api_host_message_send(INIC_API_WIFI_IS_RUNNING, param_buf, 1);
	return ret;
}

enum rtw_join_status_type wifi_get_join_status(void)
{
	return rtw_join_status;
}

int wifi_on(enum rtw_mode_type mode)
{
	int ret = 1;
	u32 param_buf[1];
	static u32 wifi_boot = 0;

#ifdef CONFIG_PLATFORM_TIZENRT_OS
    ret = WiFiRegisterLinkCallback(&linkup_handler, &linkdown_handler);
	if (ret != RTK_STATUS_SUCCESS) {
		printf("[RTK] Link callback handles: register failed !\n");
		return RTW_ERROR;
	} else {
		printf("[RTK] Link callback handles: registered\n");
	}
#endif //CONFIG_PLATFORM_TIZENRT_OS

	wifi_set_user_config();
	/* initialize the message queue, and assign the task haddle function after user config set */
	inic_msg_q_init();
	DCache_Clean((u32)(&wifi_user_config), sizeof(struct wifi_user_conf));
	param_buf[0] = (u32)(&wifi_user_config);
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_USR_CFG, param_buf, 1);

	inic_host_init_skb();

	param_buf[0] = mode;
	ret = inic_api_host_message_send(INIC_API_WIFI_ON, param_buf, 1);

	if (wifi_boot == 0) {
		wifi_boot = 1;
		init_timer_wrapper();
#ifndef CONFIG_MP_SHRINK
		rtw_wpa_init(STA_WLAN_INDEX);
#endif
		if (p_wifi_do_fast_connect && (mode == RTW_MODE_STA)) {
			p_wifi_do_fast_connect();
		}
	}

	if (ret == RTW_SUCCESS) { //wifi on success
#if !defined(CONFIG_PLATFORM_TIZENRT_OS)
#if CONFIG_LWIP_LAYER
		if (mode == RTW_MODE_STA) {
			LwIP_netif_set_up(0);
		}
#endif
#endif
	}

	return ret;
}

int wifi_off(void)
{
	int ret = 0;

	//inic_ipc_host_deinit_skb();/*should be called after np deinit*/
	return ret;
}

#ifdef CONFIG_PLATFORM_TIZENRT_OS
static void wifi_ap_sta_assoc_hdl(char *buf, int buf_len, int flags, void *handler_user_data)
{
	/* To avoid gcc warnings */
	( void ) buf;
	( void ) buf_len;
	( void ) flags;
	( void ) handler_user_data;

	if (g_link_up) {
		nvdbg("RTK_API rtk_link_event_handler send link_up\n");
		rtk_reason_t reason = {0};
		g_link_up(&reason);
	}
}
static void wifi_ap_sta_disassoc_hdl(char *buf, int buf_len, int flags, void *handler_user_data)
{
	/* To avoid gcc warnings */
	( void ) buf;
	( void ) buf_len;
	( void ) flags;
	( void ) handler_user_data;

	if (g_link_down) {
		nvdbg("RTK_API rtk_handle_disconnect send link_down\n");
		rtk_reason_t reason = {0};
		g_link_down(&reason);
	}
}
#endif //CONFIG_PLATFORM_TIZENRT_OS

int wifi_start_ap(struct _rtw_softap_info_t *softAP_config)
{
	int ret = 0;
	u32 param_buf[1];
	struct psk_info *PSK_INFO = NULL;

	/* check if softap is running */
	if (wifi_is_running(SOFTAP_WLAN_INDEX)) {
		RTK_LOGW(TAG_WLAN_DRV, "already an AP running\n");
		return ret;
	}

	/* check if STA is running */
	if ((wifi_user_config.concurrent_enabled == _FALSE) &&
		(rtw_join_status > RTW_JOINSTATUS_UNKNOWN) && (rtw_join_status <= RTW_JOINSTATUS_SUCCESS)) {
		RTK_LOGE(TAG_WLAN_INIC, "need ap? please set concurrent_enabled to _TRUE in wifi_set_user_config() !!\n");
		ret = RTW_ERROR;
		goto exit;
	}

	DCache_Clean((u32)softAP_config->password, softAP_config->password_len);
	DCache_Clean((u32)softAP_config, sizeof(struct _rtw_softap_info_t));
	param_buf[0] = (u32)softAP_config;

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	wifi_reg_event_handler(WIFI_EVENT_STA_ASSOC, wifi_ap_sta_assoc_hdl, NULL);
	wifi_reg_event_handler(WIFI_EVENT_STA_DISASSOC, wifi_ap_sta_disassoc_hdl, NULL);
#endif //CONFIG_PLATFORM_TIZENRT_OS

	rtw_wpa_init(SOFTAP_WLAN_INDEX);

	if ((PSK_INFO = rtos_mem_zmalloc(sizeof(struct psk_info))) == NULL) {
		ret = FALSE;
		goto exit;
	}
	if (softAP_config->password && softAP_config->password_len) {
		PSK_INFO->index = SOFTAP_WLAN_INDEX;
		PSK_INFO->security_type = softAP_config->security_type;
		memcpy(PSK_INFO->psk_essid, softAP_config->ssid.val, softAP_config->ssid.len);
		memcpy(PSK_INFO->psk_passphrase, softAP_config->password, softAP_config->password_len);
		rtw_psk_set_psk_info(PSK_INFO);
	}

	ret = inic_api_host_message_send(INIC_API_WIFI_START_AP, param_buf, 1);

	if (ret == RTW_SUCCESS) {
#ifndef CONFIG_PLATFORM_TIZENRT_OS
#ifdef CONFIG_LWIP_LAYER
		LwIP_netif_set_up(SOFTAP_WLAN_INDEX);
		LwIP_netif_set_link_up(SOFTAP_WLAN_INDEX);
#endif
#endif //#ifndef CONFIG_PLATFORM_TIZENRT_OS
	}

exit:
	if (PSK_INFO) {
		rtos_mem_free(PSK_INFO);
	}
	return ret;
}

int wifi_stop_ap(void)
{
	int ret = 0;

	if (wifi_is_running(SOFTAP_WLAN_INDEX) == 0) {
		RTK_LOGA(TAG_WLAN_INIC, "WIFI no run\n");
		return 0;
	}

#ifndef CONFIG_PLATFORM_TIZENRT_OS
#ifdef CONFIG_LWIP_LAYER
	dhcps_deinit();
	LwIP_netif_set_down(1);
	LwIP_netif_set_link_down(1);
#endif
#endif //#ifndef CONFIG_PLATFORM_TIZENRT_OS

	ret = inic_api_host_message_send(INIC_API_WIFI_STOP_AP, NULL, 0);
	rtw_psk_wpa_deinit(SOFTAP_WLAN_INDEX);

	return ret;
}

int wifi_scan_networks(struct _rtw_scan_param_t *scan_param, unsigned char block)
{
	assert_param(scan_param);
	int ret = 0;
	u32 param_buf[3];

	/* lock 2s to forbid suspend under scan */
	rtw_wakelock_timeout(2 * 1000);
	scan_user_callback_ptr = scan_param->scan_user_callback;
	scan_each_report_user_callback_ptr = scan_param->scan_report_each_mode_user_callback;
	scan_acs_report_user_callback_ptr = scan_param->scan_report_acs_user_callback;

	if (scan_param->ssid) {
		DCache_Clean((u32)scan_param->ssid, strlen((const char *)scan_param->ssid));
	}
	if (scan_param->channel_list) {
		DCache_Clean((u32)scan_param->channel_list, scan_param->channel_list_num);
	}
	DCache_Clean((u32)scan_param, sizeof(struct _rtw_scan_param_t));
	param_buf[0] = (u32)scan_param;
	param_buf[1] = block;
	if (scan_param->ssid) {
		param_buf[2] = strlen((const char *)scan_param->ssid);
	} else {
		param_buf[2] = 0;
	}

	ret = inic_api_host_message_send(INIC_API_WIFI_SCAN_NETWROKS, param_buf, 3);
	return ret;
}

void wifi_promisc_enable(u32 enable, struct _promisc_para_t *para)
{
	u32 buf[3] = {0};
	buf[0] = enable;
	buf[1] = (u32)para->filter_mode;
	if (para->callback) {
		promisc_user_callback_ptr = para->callback;
		buf[2] = ENABLE;
	}
	inic_api_host_message_send(INIC_API_WIFI_PROMISC_INIT, buf, 3);
}

#endif	//#if CONFIG_WLAN
