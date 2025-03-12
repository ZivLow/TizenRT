/**
  ******************************************************************************
  * @file    inic_ipc_host_api_ext.c
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

#ifdef CONFIG_AS_INIC_AP
#include "inic_ipc.h"
#endif
#include "wpa_lite_intf.h"
#include "inic_ipc_host_trx.h"
#if CONFIG_AUTO_RECONNECT
#include <wifi_auto_reconnect.h>
#endif //CONFIG_AUTO_RECONNECT

extern enum rtw_join_status_type rtw_join_status;

/******************************************************
 *                    Constants
 ******************************************************/

/******************************************************
 *                 Type Definitions
 ******************************************************/

/******************************************************
 *               Variables Declarations
 ******************************************************/

#ifdef CONFIG_LWIP_LAYER
extern struct netif xnetif[NET_IF_NUM];
#endif

ap_channel_switch_callback_t p_ap_channel_switch_callback = NULL;


/******************************************************
 *               Variables Declarations
 ******************************************************/
void *param_indicator;
struct task_struct wifi_autoreconnect_task = {0};

/******************************************************
 *               Variables Definitions
 ******************************************************/

/*NETMASK*/
#ifndef NETMASK_ADDR0
#define NETMASK_ADDR0   255
#define NETMASK_ADDR1   255
#define NETMASK_ADDR2   255
#define NETMASK_ADDR3   0
#endif

/*Gateway Address*/
#ifndef GW_ADDR0
#define GW_ADDR0   192
#define GW_ADDR1   168
#define GW_ADDR2   1
#define GW_ADDR3   1
#endif


/******************************************************
 *               Function Definitions
 ******************************************************/
#if CONFIG_WLAN
//----------------------------------------------------------------------------//
int wifi_is_connected_to_ap(void)
{
	int ret = 0;

	ret = inic_api_host_message_send(INIC_API_WIFI_IS_CONNECTED_TO_AP, NULL, 0);
	return ret;
}

//----------------------------------------------------------------------------//
int wifi_set_channel(unsigned char wlan_idx, u8 channel)
{
	int ret = 0;
	u32 param_buf[2];
	param_buf[0] = (u32)wlan_idx;
	param_buf[1] = (u32)channel;

	ret = inic_api_host_message_send(INIC_API_WIFI_SET_CHANNEL, param_buf, 2);
	return ret;
}

int wifi_get_channel(unsigned char wlan_idx, u8 *channel)
{
	int ret = 0;
	u32 param_buf[2];
	u8 *channel_temp = (u8 *)rtos_mem_zmalloc(sizeof(int));

	if (channel_temp == NULL) {
		return -1;
	}

	param_buf[0] = (u32)wlan_idx;
	param_buf[1] = (u32)channel_temp;
	DCache_CleanInvalidate((u32)channel_temp, sizeof(u8));

	ret = inic_api_host_message_send(INIC_API_WIFI_GET_CHANNEL, param_buf, 2);
	DCache_Invalidate((u32)channel_temp, sizeof(int));
	*channel = *channel_temp;
	rtos_mem_free((u8 *)channel_temp);

	return ret;
}

//----------------------------------------------------------------------------//
u8 wifi_set_countrycode(char *cntcode)
{
	int ret = 0;
	u32 param_buf[1];

	DCache_Clean((u32)cntcode, 2);
	param_buf[0] = (u32)cntcode;

	ret = inic_api_host_message_send(INIC_API_WIFI_SET_COUNTRY_CODE, param_buf, 1);
	return ret;
}

u8 wifi_set_chplan(u8 chplan)
{
	int ret = 0;
	u32 param_buf[1];
	param_buf[0] = (u32)chplan;

	ret = inic_api_host_message_send(INIC_API_WIFI_SET_CHPLAN, param_buf, 1);
	return ret;
}

int wifi_get_scan_records(unsigned int *AP_num, char *scan_buf)
{
	int ret = 0;
	u32 param_buf[2];

	unsigned int *AP_num_temp = (unsigned int *)rtos_mem_zmalloc(sizeof(unsigned int));
	if (AP_num_temp == NULL) {
		return -1;
	}
	*AP_num_temp = *AP_num;

	char *scan_buf_temp = (char *)rtos_mem_zmalloc((*AP_num) * sizeof(struct rtw_scan_result));
	if (scan_buf_temp == NULL) {
		rtos_mem_free(AP_num_temp);
		return -1;
	}

	param_buf[0] = (u32)AP_num_temp;
	param_buf[1] = (u32)scan_buf_temp;
	DCache_CleanInvalidate((u32)AP_num_temp, sizeof(unsigned int));
	DCache_CleanInvalidate((u32)scan_buf_temp, (*AP_num)*sizeof(struct rtw_scan_result));

	ret = inic_api_host_message_send(INIC_API_WIFI_GET_SCANNED_AP_INFO, param_buf, 2);
	DCache_Invalidate((u32)AP_num_temp, sizeof(unsigned int));
	DCache_Invalidate((u32)scan_buf_temp, (*AP_num)*sizeof(struct rtw_scan_result));
	*AP_num = *AP_num_temp;
	memcpy(scan_buf, scan_buf_temp, ((*AP_num)*sizeof(struct rtw_scan_result)));

	rtos_mem_free((u8 *)AP_num_temp);
	rtos_mem_free((u8 *)scan_buf_temp);
	return ret;
}

int wifi_scan_abort(u8 block)
{
	int ret = 0;
	u32 param_buf[1];

	param_buf[0] = (u32)block;
	ret = inic_api_host_message_send(INIC_API_WIFI_SCAN_ABORT, param_buf, 1);

	return ret;
}

//----------------------------------------------------------------------------//

int wifi_get_mac_address(int idx, struct _rtw_mac_t *mac, u8 efuse)
{
	int ret = 0;
	u32 param_buf[3];

	struct _rtw_mac_t *mac_temp = (struct _rtw_mac_t *)rtos_mem_zmalloc(sizeof(struct _rtw_mac_t));
	if (mac_temp == NULL) {
		return -1;
	}

	param_buf[0] = idx;
	param_buf[1] = (u32)mac_temp;
	param_buf[2] = efuse;
	DCache_CleanInvalidate((u32)mac_temp, sizeof(struct _rtw_mac_t));
	ret = inic_api_host_message_send(INIC_API_WIFI_GET_MAC_ADDR, param_buf, 3);

	DCache_Invalidate((u32)mac_temp, sizeof(struct _rtw_mac_t));
	memcpy(mac, mac_temp, sizeof(struct _rtw_mac_t));
	rtos_mem_free((u8 *)mac_temp);
	return ret;
}

int wifi_set_mac_address(int idx, unsigned char *mac, u8 efuse)
{
	int ret = 0;
	u32 param_buf[3];
	unsigned char *mac_temp = (unsigned char *)rtos_mem_zmalloc(ETH_ALEN);
	if (mac_temp == NULL) {
		return -1;
	}
	memcpy(mac_temp, mac, ETH_ALEN);

	DCache_Clean((u32)mac_temp, ETH_ALEN);

	param_buf[0] = idx;
	param_buf[1] = (u32)mac_temp;
	param_buf[2] = efuse;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_MAC_ADDR, param_buf, 3);

	rtos_mem_free((u8 *)mac_temp);
	return ret;
}
//----------------------------------------------------------------------------//
u8 wifi_driver_is_mp(void)
{
	int ret = 0;

	ret = (u8)inic_api_host_message_send(INIC_API_WIFI_DRIVE_IS_MP, NULL, 0);
	return ret;
}

//----------------------------------------------------------------------------//
int wifi_get_associated_client_list(struct _rtw_client_list_t *client_list_buffer)
{
	int ret = 0;
	u32 param_buf[1];

	struct _rtw_client_list_t *client_list_buffer_temp = (struct _rtw_client_list_t *)rtos_mem_zmalloc(sizeof(struct _rtw_client_list_t));
	if (client_list_buffer_temp == NULL) {
		return -1;
	}

	param_buf[0] = (u32)client_list_buffer_temp;
	DCache_CleanInvalidate((u32)client_list_buffer_temp, sizeof(struct _rtw_client_list_t));

	ret = inic_api_host_message_send(INIC_API_WIFI_GET_ASSOCIATED_CLIENT_LIST, param_buf, 1);
	DCache_Invalidate((u32)client_list_buffer_temp, sizeof(struct _rtw_client_list_t));
	memcpy(client_list_buffer, client_list_buffer_temp, sizeof(struct _rtw_client_list_t));
	rtos_mem_free((u8 *)client_list_buffer_temp);
	return ret;
}
//----------------------------------------------------------------------------//
int wifi_get_setting(unsigned char wlan_idx, struct _rtw_wifi_setting_t *psetting)
{
	int ret = 0;
	u32 param_buf[2];

	struct _rtw_wifi_setting_t *setting_temp = (struct _rtw_wifi_setting_t *)rtos_mem_zmalloc(sizeof(struct _rtw_wifi_setting_t));
	if (setting_temp == NULL) {
		return -1;
	}

	param_buf[0] = (u32)wlan_idx;
	param_buf[1] = (u32)setting_temp;
	DCache_CleanInvalidate((u32)setting_temp, sizeof(struct _rtw_wifi_setting_t));

	ret = inic_api_host_message_send(INIC_API_WIFI_GET_SETTING, param_buf, 2);
	DCache_Invalidate((u32)setting_temp, sizeof(struct _rtw_wifi_setting_t));
	memcpy(psetting, setting_temp, sizeof(struct _rtw_wifi_setting_t));
	rtos_mem_free((u8 *)setting_temp);

	return ret;
}

int wifi_set_ips_internal(u8 enable)
{
	int ret = 0;
	u32 param_buf[1];

	param_buf[0] = (u32)enable;

	ret = inic_api_host_message_send(INIC_API_WIFI_SET_IPS_EN, param_buf, 1);
	return ret;
}

int wifi_set_lps_enable(u8 enable)
{
	int ret = 0;
	u32 param_buf[1];

	param_buf[0] = (u32)enable;

	ret = inic_api_host_message_send(INIC_API_WIFI_SET_LPS_EN, param_buf, 1);
	return ret;
}

int wifi_set_lps_listen_interval(u8 interval)
{
	int ret = 0;
	u32 param_buf[1];

	param_buf[0] = (u32)interval;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_LPS_LISTEN_INTERVAL, param_buf, 1);
	return ret;
}

//----------------------------------------------------------------------------//

int wifi_set_mfp_support(unsigned char value)
{
	int ret = 0;
	u32 param_buf[1];

	param_buf[0] = (u32)value;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_MFP_SUPPORT, param_buf, 1);
	return ret;
}

int wifi_set_group_id(unsigned char value)
{
	rtw_sae_set_user_group_id(value);

	return RTW_SUCCESS;
}

int wifi_set_pmk_cache_enable(unsigned char value)
{
	int ret = 0;
	u32 param_buf[1];

	param_buf[0] = (u32)value;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_PMK_CACHE_EN, param_buf, 1);
	return ret;
}

//----------------------------------------------------------------------------//
int wifi_get_sw_statistic(unsigned char idx, struct _rtw_sw_statistics_t *statistic)
{
	u32 param_buf[2];
	int ret = 0;

	struct _rtw_sw_statistics_t *statistic_temp = (struct _rtw_sw_statistics_t *)rtos_mem_zmalloc(sizeof(struct _rtw_sw_statistics_t));
	if (statistic_temp == NULL) {
		return 0;
	}
	param_buf[0] = (u32)idx;
	param_buf[1] = (u32)statistic_temp;
	DCache_CleanInvalidate((u32)statistic_temp, sizeof(struct _rtw_sw_statistics_t));

	ret = inic_api_host_message_send(INIC_API_WIFI_GET_SW_STATISTIC, param_buf, 2);

	DCache_Invalidate((u32)statistic_temp, sizeof(struct _rtw_sw_statistics_t));
	memcpy(statistic, statistic_temp, sizeof(struct _rtw_sw_statistics_t));
	rtos_mem_free((u8 *)statistic_temp);
	return ret;
}

int wifi_fetch_phy_statistic(struct _rtw_phy_statistics_t *phy_statistic)
{
	u32 param_buf[1];
	int ret = 0;

	struct _rtw_phy_statistics_t *phy_statistic_temp = (struct _rtw_phy_statistics_t *)rtos_mem_zmalloc(sizeof(struct _rtw_phy_statistics_t));
	if (phy_statistic_temp == NULL) {
		return -1;
	}

	param_buf[0] = (u32)phy_statistic_temp;
	DCache_CleanInvalidate((u32)phy_statistic_temp, sizeof(struct _rtw_phy_statistics_t));

	ret = inic_api_host_message_send(INIC_API_WIFI_GET_PHY_STATISTIC, param_buf, 1);

	DCache_Invalidate((u32)phy_statistic_temp, sizeof(struct _rtw_phy_statistics_t));
	memcpy(phy_statistic, phy_statistic_temp, sizeof(struct _rtw_phy_statistics_t));
	rtos_mem_free((u8 *)phy_statistic_temp);
	return ret;
}

int wifi_get_network_mode(void)
{
	return inic_api_host_message_send(INIC_API_WIFI_GET_NETWORK_MODE, NULL, 0);
}

int wifi_set_network_mode(enum wlan_mode mode)
{
	int ret = 0;
	u32 param_buf[1];

	param_buf[0] = (u32)mode;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_NETWORK_MODE, param_buf, 1);
	return ret;
}

int wifi_set_wps_phase(unsigned char is_trigger_wps)
{
	int ret = 0;
	u32 param_buf[1];
	param_buf[0] = is_trigger_wps;

	ret = inic_api_host_message_send(INIC_API_WIFI_SET_WPS_PHASE, param_buf, 1);
	return ret;
}

int wifi_set_gen_ie(unsigned char wlan_idx, char *buf, __u16 buf_len, __u16 flags)
{
	int ret = 0;
	u32 param_buf[4];

	DCache_Clean((u32)buf, (u32)buf_len);
	param_buf[0] = (u32)wlan_idx;
	param_buf[1] = (u32)buf;
	param_buf[2] = (u32)buf_len;
	param_buf[3] = (u32)flags;

	ret = inic_api_host_message_send(INIC_API_WIFI_SET_GEN_IE, param_buf, 4);
	return ret;
}

int wifi_set_eap_phase(unsigned char is_trigger_eap)
{
#ifdef CONFIG_EAP
	int ret = 0;
	u32 param_buf[1];
	param_buf[0] = is_trigger_eap;

#if CONFIG_AUTO_RECONNECT
	if (is_trigger_eap == 0) {
		rtw_reconn.eap_method = 0;
	}
#endif

	ret = inic_api_host_message_send(INIC_API_WIFI_SET_EAP_PHASE, param_buf, 1);
	return ret;
#else
	return -1;
#endif
}

unsigned char wifi_get_eap_phase(void)
{
#ifdef CONFIG_EAP
	unsigned char eap_phase = 0;

	eap_phase = (u8)inic_api_host_message_send(INIC_API_WIFI_GET_EAP_PHASE, NULL, 0);
	return eap_phase;
#else
	return 0;
#endif
}

int wifi_set_eap_method(unsigned char eap_method)
{
#ifdef CONFIG_EAP
	int ret = 0;
	u32 param_buf[1];
	param_buf[0] = eap_method;

#if CONFIG_AUTO_RECONNECT
	rtw_reconn.eap_method = eap_method;
#endif

	ret = inic_api_host_message_send(INIC_API_WIFI_SET_EAP_METHOD, param_buf, 1);
	return ret;
#else
	return -1;
#endif
}

int wifi_if_send_eapol(unsigned char wlan_idx, char *buf, __u16 buf_len, __u16 flags)
{
	int ret = 0;
	u32 param_buf[4];

	DCache_Clean((u32)buf, (u32)buf_len);
	param_buf[0] = (u32)wlan_idx;
	param_buf[1] = (u32)buf;
	param_buf[2] = buf_len;
	param_buf[3] = flags;

	ret = inic_api_host_message_send(INIC_API_WIFI_SEND_EAPOL, param_buf, 4);
	return ret;
}

//----------------------------------------------------------------------------//
/*
 * Example for custom ie
 *
 * u8 test_1[] = {221, 2, 2, 2};
 * u8 test_2[] = {221, 2, 1, 1};
 * struct custom_ie buf[2] = {{test_1, BEACON},
 *		 {test_2, PROBE_RSP}};
 * u8 buf_test2[] = {221, 2, 1, 3} ;
 * struct custom_ie buf_update = {buf_test2, PROBE_RSP};
 *
 * add ie list
 * static void cmd_add_ie(int argc, char **argv)
 * {
 *	 wifi_add_custom_ie(buf, 2);
 * }
 *
 * update current ie
 * static void cmd_update_ie(int argc, char **argv)
 * {
 *	 wifi_update_custom_ie(&buf_update, 2);
 * }
 *
 * delete all ie for specific wlan interface
 * static void cmd_del_ie(int argc, char **argv)
 * {
 *	 wifi_del_custom_ie(SOFTAP_WLAN_INDEX);
 * }
 */
int wifi_add_custom_ie(struct custom_ie *cus_ie, int ie_num)
{
	int ret = 0;
	u32 param_buf[3];
	u8 ie_len = 0;
	int cnt = 0;

	struct custom_ie *pcus_ie = cus_ie;
	for (cnt = 0; cnt < ie_num; cnt++) {
		struct custom_ie ie_t = *(pcus_ie + cnt);
		ie_len = ie_t.ie[1];
		DCache_Clean((u32)ie_t.ie, (u32)(ie_len + 2));
	}
	DCache_Clean((u32)cus_ie, ie_num * sizeof(struct custom_ie));
	param_buf[0] = 0;//type 0 means add
	param_buf[1] = (u32)cus_ie;
	param_buf[2] = ie_num;
	ret = inic_api_host_message_send(INIC_API_WIFI_CUS_IE, param_buf, 3);
	return ret;
}

int wifi_update_custom_ie(struct custom_ie *cus_ie, int ie_index)
{
	int ret = 0;
	u32 param_buf[3];
	u8 ie_len = 0;


	struct custom_ie ie_t = *(struct custom_ie *)(cus_ie);
	ie_len = *(u8 *)(ie_t.ie + 1);
	DCache_Clean((u32)ie_t.ie, (u32)ie_len);

	DCache_Clean((u32)cus_ie, sizeof(struct custom_ie));
	param_buf[0] = 1;//type 1 means update
	param_buf[1] = (u32)cus_ie;
	param_buf[2] = ie_index;
	ret = inic_api_host_message_send(INIC_API_WIFI_CUS_IE, param_buf, 3);
	return ret;
}

int wifi_del_custom_ie(unsigned char wlan_idx)
{
	u32 param_buf[2];

	param_buf[0] = 2;//type 2 means delete
	param_buf[1] = (u32)wlan_idx;
	return inic_api_host_message_send(INIC_API_WIFI_CUS_IE, param_buf, 2);
}

void wifi_set_indicate_mgnt(int enable)
{
	u32 param_buf[1];
	param_buf[0] = (u32)enable;
	inic_api_host_message_send(INIC_API_WIFI_SET_IND_MGNT, param_buf, 1);
}

int wifi_send_mgnt(struct _raw_data_desc_t *raw_data_desc)
{
	int ret = 0;
	u32 param_buf[1];

	DCache_Clean((u32)raw_data_desc, sizeof(struct _raw_data_desc_t));
	DCache_Clean((u32)raw_data_desc->buf, (u32)raw_data_desc->buf_len);
	param_buf[0] = (u32)raw_data_desc;

	ret = inic_api_host_message_send(INIC_API_WIFI_SEND_MGNT, param_buf, 1);
	return ret;
}

int wifi_set_tx_rate_by_ToS(unsigned char enable, unsigned char ToS_precedence, unsigned char tx_rate)
{
	int ret = 0;
	u32 param_buf[3];

	param_buf[0] = (u32)enable;
	param_buf[1] = (u32)ToS_precedence;
	param_buf[2] = (u32)tx_rate;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_TXRATE_BY_TOS, param_buf, 3);
	return ret;
}

int wifi_set_EDCA_param(unsigned int AC_param)
{
	int ret = 0;
	u32 param_buf[1];

	param_buf[0] = AC_param;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_EDCA_PARAM, param_buf, 1);
	return ret;
}

int wifi_set_TX_CCA(unsigned char enable)
{
	int ret = 0;
	u32 param_buf[1];

	param_buf[0] = enable;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_TX_CCA, param_buf, 1);
	return ret;
}

int wifi_set_cts2self_duration_and_send(unsigned char wlan_idx, unsigned short duration)
{
	int ret = 0;
	u32 param_buf[2];

	param_buf[0] = (u32)wlan_idx;
	param_buf[1] = (u32)duration;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_CTS2SEFL_DUR_AND_SEND, param_buf, 2);
	return ret;

}

int wifi_get_antdiv_info(unsigned char *antdiv_mode, unsigned char *curr_ant)
{
#ifdef CONFIG_WIFI_ANTDIV
	int ret = 0;
	u32 param_buf[1];
	u8 *antInfo_temp = (u8 *)rtos_mem_zmalloc(sizeof(int));

	if (antInfo_temp == NULL) {
		return -1;
	}
	param_buf[0] = (u32)antInfo_temp;
	DCache_CleanInvalidate((u32)antInfo_temp, sizeof(int));
	ret = inic_api_host_message_send(INIC_API_WIFI_GET_ANTENNA_INFO, param_buf, 1);
	DCache_Invalidate((u32)antInfo_temp, sizeof(int));
	*antdiv_mode = *(u8 *)antInfo_temp;
	*curr_ant = *(u8 *)(antInfo_temp + sizeof(u8));
	rtos_mem_free(antInfo_temp);
	return ret;
#else
	UNUSED(antdiv_mode);
	UNUSED(curr_ant);
	return -1;
#endif
}

/*
 * @brief get WIFI band type
 *@retval  the support band type.
 * 	WL_BAND_2_4G: only support 2.4G
 *	WL_BAND_5G: only support 5G
 *      WL_BAND_2_4G_5G_BOTH: support both 2.4G and 5G
 */
enum _WL_BAND_TYPE wifi_get_band_type(void)
{
	u8 ret;

	ret = inic_api_host_message_send(INIC_API_WIFI_GET_BAND_TYPE, NULL, 0);

	if (ret == 0) {
		return WL_BAND_2_4G;
	} else if (ret == 1) {
		return WL_BAND_5G;
	} else {
		return WL_BAND_2_4G_5G_BOTH;
	}
}

int wifi_del_station(unsigned char *hwaddr)
{
	int ret = 0;
	u32 param_buf[2];

	DCache_Clean((u32)hwaddr, ETH_ALEN);
	param_buf[0] = (u32)IFACE_PORT1;
	param_buf[1] = (u32)hwaddr;
	ret = inic_api_host_message_send(INIC_API_WIFI_DEL_STA, param_buf, 2);
	return ret;

}

int wifi_ap_switch_chl_and_inform(struct _rtw_csa_parm_t *csa_param)
{
	int ret = 0;
	u32 param_buf[3];
	p_ap_channel_switch_callback = csa_param->callback;

	param_buf[0] = (u32)csa_param;
	DCache_Clean((u32)csa_param, sizeof(struct _rtw_csa_parm_t));
	ret = inic_api_host_message_send(INIC_API_WIFI_AP_CH_SWITCH, param_buf, 1);
	DCache_Invalidate((u32)csa_param, sizeof(struct _rtw_csa_parm_t));
	return ret;
}

u64 wifi_get_tsf(unsigned char port_id)
{
	return inic_host_get_wifi_tsf(port_id);
}

int wifi_get_txbuf_pkt_num(void)
{
	return inic_host_get_txbuf_pkt_num();
}

//----------------------------------------------------------------------------//
int wifi_csi_config(struct _rtw_csi_action_parm_t *act_param)
{
	int ret = 0;
	u32 param_buf[1];

	param_buf[0] = (u32)act_param;
	DCache_Clean((u32)act_param, sizeof(struct _rtw_csi_action_parm_t));
	ret = inic_api_host_message_send(INIC_API_WIFI_CONFIG_CSI, param_buf, 1);
	DCache_Invalidate((u32)act_param, sizeof(struct _rtw_csi_action_parm_t));
	return ret;
}

int wifi_csi_report(u32 buf_len, u8 *csi_buf, u32 *len)
{
	int ret = 0;
	u32 param_buf[3];

	void *csi_buf_temp = rtos_mem_zmalloc(buf_len);
	if (csi_buf_temp == NULL) {
		return -1;
	}

	u32 *len_temp = (u32 *)rtos_mem_zmalloc(sizeof(u32));
	if (len_temp == NULL) {
		rtos_mem_free((u8 *)csi_buf_temp);
		return -1;
	}

	param_buf[0] = (u32)csi_buf_temp;
	param_buf[1] = (u32)buf_len;
	param_buf[2] = (u32)len_temp;
	DCache_CleanInvalidate((u32)csi_buf_temp, buf_len);
	DCache_CleanInvalidate((u32)len_temp, sizeof(u32));

	ret = inic_api_host_message_send(INIC_API_WIFI_GET_CSI_REPORT, param_buf, 3);
	DCache_Invalidate((u32)csi_buf_temp, buf_len);
	memcpy(csi_buf, csi_buf_temp, buf_len);

	DCache_Invalidate((u32)len_temp, sizeof(u32));
	memcpy(len, len_temp, sizeof(u32));

	rtos_mem_free((u8 *)csi_buf_temp);
	rtos_mem_free((u8 *)len_temp);
	return ret;
}
//----------------------------------------------------------------------------//

void wifi_btcoex_set_pta(enum pta_type type, u8 role, u8 process)
{
	u32 param_buf[3];

	param_buf[0] = (u32)type;
	param_buf[1] = (u32)role;
	param_buf[2] = (u32)process;
	inic_api_host_message_send(INIC_API_WIFI_COEX_SET_PTA, param_buf, 3);
}

void wifi_btcoex_set_bt_ant(u8 bt_ant)
{
	u32 param_buf[1];

	param_buf[0] = (u32)bt_ant;
	inic_api_host_message_send(INIC_API_WIFI_SET_BT_SEL, param_buf, 1);
}

int wifi_set_wpa_mode(enum rtw_wpa_mode_type wpa_mode)
{
	u32 param_buf[1];
	int ret = 0;

	param_buf[0] = (u32)wpa_mode;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_WPA_MODE, param_buf, 1);
	return ret;
}

int wifi_set_pmf_mode(u8 pmf_mode)
{
	u32 param_buf[1];
	int ret = 0;

	param_buf[0] = (u32)pmf_mode;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_PMF_MODE, param_buf, 1);
	return ret;
}

int wifi_btcoex_bt_rfk(struct bt_rfk_param *rfk_param)
{
	int ret = 0;
	u32 param_buf[1] = {0};
	u32 len = sizeof(struct bt_rfk_param);
	void *rfk_param_temp = (void *)rtos_mem_zmalloc(len);

	if (rfk_param_temp == NULL) {
		return -1;
	}
	memcpy(rfk_param_temp, rfk_param, len);

	DCache_Clean((u32)rfk_param_temp, len);

	param_buf[0] = (u32)rfk_param_temp;

	ret = inic_api_host_message_send(INIC_API_WIFI_COEX_BT_RFK, param_buf, 1);
	rtos_mem_free((u8 *)rfk_param_temp);

	return ret;
}

void wifi_btcoex_bt_hci_notify(u8 *pdata, u16 len, u8 type)
{
	u32 param_buf[3] = {0};
	u8 *pdata_temp = (u8 *)rtos_mem_zmalloc(len);
	if (pdata_temp == NULL) {
		return;
	}
	memcpy(pdata_temp, pdata, len);

	DCache_Clean((u32)pdata_temp, (u32)len);
	param_buf[0] = (u32)pdata_temp;
	param_buf[1] = (u32)len;
	param_buf[2] = (u32)type;

	inic_api_host_message_send(INIC_API_COEX_BT_HCI_NOTIFY, param_buf, 3);
	rtos_mem_free((u8 *)pdata_temp);
}

int wifi_extchip_coex_notify(u32 type, u32 data, u32 data_len)
{
	int ret = 0;
	u32 param_buf[3];

	param_buf[0] = type;
	param_buf[1] = data;
	param_buf[2] = data_len;

	DCache_Clean((u32)data, data_len);
	ret = inic_api_host_message_send(INIC_API_WIFI_COEX_EXTCHIP, param_buf, 3);
	DCache_Invalidate((u32)data, data_len);

	return ret;
}

int wifi_zigbee_coex_zb_rfk(void)
{
	int ret = 0;
	inic_api_host_message_send(INIC_API_WIFI_COEX_ZB_RFK, NULL, 0);
	return ret;
}

void wifi_btcoex_vendor_info_set(void *p_vendor_info, u8 length)
{
	u32 param_buf[2] = {0};
	void *p_vendor_info_temp = (void *)rtos_mem_zmalloc(length);

	if (p_vendor_info_temp == NULL) {
		return;
	}
	memcpy(p_vendor_info_temp, p_vendor_info, length);

	DCache_Clean((u32)p_vendor_info_temp, length);

	param_buf[0] = (u32)length;
	param_buf[1] = (u32)p_vendor_info_temp;

	inic_api_host_message_send(INIC_API_WIFI_COEX_VENDOR_INFO_SET, param_buf, 2);
	rtos_mem_free((u8 *)p_vendor_info_temp);
}

void wifi_wpa_4way_status_indicate(struct rtw_wpa_4way_status *rpt_4way)
{
	u32 param_buf[1] = {0};

	DCache_Clean((u32)rpt_4way, sizeof(struct rtw_wpa_4way_status));
	param_buf[0] = (u32)rpt_4way;
	inic_api_host_message_send(INIC_API_WPA_4WAY_REPORT, param_buf, 1);
}

void wifi_wpa_add_key(struct rtw_crypt_info *crypt)
{
	u32 param_buf[1] = {0};

	DCache_Clean((u32)crypt, sizeof(struct rtw_crypt_info));
	param_buf[0] = (u32)crypt;
	inic_api_host_message_send(INIC_API_WIFI_ADD_KEY, param_buf, 1);
}

void wifi_wpa_pmksa_ops(struct rtw_pmksa_ops_t *pmksa_ops)
{
	u32 param_buf[1] = {0};

	DCache_Clean((u32)pmksa_ops, sizeof(struct rtw_pmksa_ops_t));
	param_buf[0] = (u32)pmksa_ops;
	inic_api_host_message_send(INIC_API_WPA_PMKSA_OPS, param_buf, 1);
}

int wifi_sae_status_indicate(u8 wlan_idx, u16 status, u8 *mac_addr)
{
	u32 param_buf[3] = {0};

	param_buf[0] = (u32)wlan_idx;
	param_buf[1] = (u32)status;
	param_buf[2] = (u32)mac_addr;

	if (mac_addr) {
		DCache_Clean((u32)mac_addr, 6);
	}
	inic_api_host_message_send(INIC_API_WIFI_SAE_STATUS, param_buf, 3);
	return 0;
}

int wifi_ft_status_indicate(struct rtw_kvr_param_t *kvr_param, u16 status)
{
#ifdef CONFIG_IEEE80211R
	u32 param_buf[2] = {0};

	if (kvr_param) {
		DCache_Clean((u32)kvr_param, sizeof(struct rtw_kvr_param_t));
		param_buf[0] = (u32)kvr_param;
		param_buf[1] = (u32)status;
	}
	inic_api_host_message_send(INIC_API_WIFI_FT_STATUS, param_buf, 2);
	return 0;
#else
	UNUSED(kvr_param);
	UNUSED(status);
	return -1;
#endif
}

int wifi_send_raw_frame(struct raw_frame_desc_t *raw_frame_desc)
{
	int ret;
	int idx = 0;
	struct skb_raw_para raw_para;

	struct eth_drv_sg sg_list[2];
	int sg_len = 0;

	if (raw_frame_desc == NULL) {
		return -1;
	}

	raw_para.rate = raw_frame_desc->tx_rate;
	raw_para.retry_limit = raw_frame_desc->retry_limit;
	raw_para.ac_queue = raw_frame_desc->ac_queue;
	raw_para.sgi = raw_frame_desc->sgi;
	raw_para.agg_en = raw_frame_desc->agg_en;
	raw_para.device_id = raw_frame_desc->device_id;

	idx = raw_frame_desc->wlan_idx;

	sg_list[sg_len].buf = (unsigned int)raw_frame_desc->buf;
	sg_list[sg_len++].len = raw_frame_desc->buf_len;
	ret = inic_host_send(idx, sg_list, sg_len, raw_frame_desc->buf_len, &raw_para, 0);

	return ret;
}

int wifi_get_ccmp_key(u8 wlan_idx, u8 *mac_addr, unsigned char *uncst_key, unsigned char *group_key)
{
	int ret;
	u32 param_buf[4] = {0};
	unsigned char *uncst_key_temp = NULL;
	unsigned char *group_key_temp = NULL;

	uncst_key_temp = (unsigned char *)rtos_mem_zmalloc(16);
	group_key_temp = (unsigned char *)rtos_mem_zmalloc(16);
	if (uncst_key_temp == NULL || group_key_temp == NULL) {
		return -1;
	}
	DCache_Clean((u32)uncst_key_temp, 16);
	DCache_Clean((u32)group_key_temp, 16);
	if (mac_addr) {
		DCache_Clean((u32)mac_addr, 6);
	}
	param_buf[0] = (u32)wlan_idx;
	param_buf[1] = (u32)mac_addr;
	param_buf[2] = (u32)uncst_key_temp;
	param_buf[3] = (u32)group_key_temp;

	ret = inic_api_host_message_send(INIC_API_WIFI_GET_CCMP_KEY, param_buf, 4);
	DCache_Invalidate((u32)uncst_key_temp, 16);
	DCache_Invalidate((u32)group_key_temp, 16);
	memcpy(uncst_key, uncst_key_temp, 16);
	memcpy(group_key, group_key_temp, 16);

	rtos_mem_free(uncst_key_temp);
	rtos_mem_free(group_key_temp);
	return ret;
}

void wifi_speaker_setting(enum SPEAKER_SET_TYPE set_type, union speaker_set *settings)
{
#ifdef CONFIG_WIFI_SPEAKER_ENABLE
	u32 param_buf[2] = {0};

	param_buf[0] = (u32)set_type;

	DCache_Clean((u32)settings, sizeof(union speaker_set));
	param_buf[1] = (u32)settings;
	inic_api_host_message_send(INIC_API_WIFI_SPEAKER, param_buf, 2);
#else
	UNUSED(set_type);
	UNUSED(settings);
#endif
}

void wifi_set_owe_param(struct rtw_owe_param_t *owe_param)
{
#ifdef CONFIG_OWE_SUPPORT
	u32 param_buf[1] = {0};

	DCache_Clean((u32)owe_param, sizeof(struct rtw_owe_param_t));
	param_buf[0] = (u32)owe_param;
	inic_api_host_message_send(INIC_API_WIFI_SET_OWE_PARAM, param_buf, 1);
#else
	UNUSED(owe_param);
#endif
}

int wifi_set_tx_power(struct rtw_tx_power_ctl_info_t *txpwr_ctrl_info)
{
	int ret = 0;
	u32 param_buf[1];

	DCache_Clean((u32)txpwr_ctrl_info, sizeof(struct rtw_tx_power_ctl_info_t));
	param_buf[0] = (u32)txpwr_ctrl_info;
	ret = inic_api_host_message_send(INIC_API_WIFI_SET_TX_POWER, param_buf, 1);
	return ret;
}

int wifi_get_tx_power(u8 rate, s8 *txpwr)
{
	int ret = 0;
	u32 param_buf[2];
	s8 *txpwr_temp = (s8 *)rtos_mem_zmalloc(sizeof(int));

	if (txpwr_temp == NULL) {
		return -1;
	}

	param_buf[0] = (u32)rate;
	param_buf[1] = (u32)txpwr_temp;
	DCache_CleanInvalidate((u32)txpwr_temp, sizeof(int));

	ret = inic_api_host_message_send(INIC_API_WIFI_GET_TX_POWER, param_buf, 2);
	DCache_Invalidate((u32)txpwr_temp, sizeof(int));
	*txpwr = *txpwr_temp;
	rtos_mem_free(txpwr_temp);

	return ret;
}

#endif	//#if CONFIG_WLAN

