/**
  ******************************************************************************
  * @file    inic_ipc_host_trx.c
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

#define __INIC_IPC_HOST_TRX_C__

/* -------------------------------- Includes -------------------------------- */
/* external head files */

/* internal head files */
#include "inic_ipc_host_trx.h"
#include "inic_ipc_msg_queue.h"
#include "wifi_conf.h"
#ifdef CONFIG_PLATFORM_TIZENRT_OS
#include <tinyara/netmgr/netdev_mgr.h>
#include <ifaddrs.h>
#include <netdev_mgr_internal.h>
#endif //CONFIG_PLATFORM_TIZENRT_OS

#define CONFIG_ENABLE_CACHE

/* -------------------------------- Defines --------------------------------- */

#ifdef CONFIG_PLATFORM_TIZENRT_OS
#ifndef GET_NETIF_FROM_NETDEV
#define GET_NETIF_FROM_NETDEV(dev) (struct netif *)(((struct netdev_ops *)(dev)->ops)->nic)
#endif //#ifndef GET_NETIF_FROM_NETDEV
#endif //CONFIG_PLATFORM_TIZENRT_OS

/* -------------------------------- Macros ---------------------------------- */

/* ------------------------------- Data Types ------------------------------- */
/* recv buffer to store the data from IPC to queue. */
struct host_recv_buf {
	struct list_head list;
	int idx_wlan; /* index for wlan */
	struct pbuf *p_buf; /* rx data for ethernet buffer*/
};

/* recv structure */
struct host_priv {
	rtos_sema_t recv_sema; /* sema to wait allloc skb from device */
	rtos_sema_t alloc_skb_sema; /* sema to wait allloc skb from device */
	rtos_sema_t host_send_sema; /* sema to protect inic ipc host send */
	struct __queue recv_queue; /* recv queue */
	u32 rx_bytes; /* recv bytes */
	u32 rx_pkts; /* recv number of packets */
	u32 tx_bytes; /* xmit bytes */
	u32 tx_pkts; /* xmit number of packets */
};

/* -------------------------- Function declaration -------------------------- */

/* ---------------------------- Global Variables ---------------------------- */

/* --------------------------- Private Variables ---------------------------- */
struct host_priv g_inic_host_priv __attribute__((aligned(64)));
struct sk_buff *host_skb_buff;
int skb_buf_max_size;

rtos_task_t inic_host_rx_task_handle;

#ifndef INIC_SKIP_RX_TASK
/* ---------------------------- Private Functions --------------------------- */
/**
 * @brief  to enqueue the precvbuf into the queue.
 * @param  precvbuf[inout]: the recv buffer enqueued into the queue.
 * @param  queue[inout]: the recv queue.
 * @return if is OK, return _SUCCESS, failed return _FAIL.
 */
static sint inic_enqueue_recvbuf(struct host_recv_buf *precvbuf, struct __queue *queue)
{
#ifdef CONFIG_PLATFORM_TIZENRT_OS
	irqstate_t flags = tizenrt_critical_enter();
#else
	rtos_critical_enter();
#endif //CONFIG_PLATFORM_TIZENRT_OS

	rtw_list_insert_tail(&precvbuf->list, get_list_head(queue));

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	tizenrt_critical_exit(flags);
#else
	rtos_critical_exit();
#endif //CONFIG_PLATFORM_TIZENRT_OS

	return _SUCCESS;
}

/**
 * @brief  to get the recv buffer from the recv queue.
 * @param  queue[inout]: the recv queue.
 * @return return recv buffer. if is NULL, the queue is empty.
 */
static struct host_recv_buf *inic_dequeue_recvbuf(struct __queue *queue)
{
	struct host_recv_buf *precvbuf;
	struct list_head *plist, *phead;

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	irqstate_t flags = tizenrt_critical_enter();
#else
	rtos_critical_enter();
#endif //CONFIG_PLATFORM_TIZENRT_OS

	if (rtw_queue_empty(queue) == _TRUE) {
		precvbuf = NULL;
	} else {
		phead = get_list_head(queue);
		plist = get_next(phead);
		precvbuf = LIST_CONTAINOR(plist, struct host_recv_buf, list);
		rtw_list_delete(&precvbuf->list);
	}

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	tizenrt_critical_exit(flags);
#else
	rtos_critical_exit();
#endif //CONFIG_PLATFORM_TIZENRT_OS

	return precvbuf;
}

/**
 * @brief  rx task to handle the rx data, get the data from the rx queue and send
 *	to upper layer.
 * @param  none.
 * @return none.
 */
static void inic_host_rx_tasklet(void)
{
#ifndef CONFIG_MP_SHRINK
	struct host_recv_buf *precvbuf = NULL;
	struct __queue *recv_queue = NULL;
	struct pbuf *p_buf = NULL;
	int index = 0;
	recv_queue = &g_inic_host_priv.recv_queue;
#endif
	do {
		rtos_sema_take(g_inic_host_priv.recv_sema, 0xFFFFFFFF);
#ifndef CONFIG_MP_SHRINK
		while ((precvbuf = inic_dequeue_recvbuf(recv_queue))) {
			p_buf = precvbuf->p_buf;

			g_inic_host_priv.rx_bytes += p_buf->len;
			g_inic_host_priv.rx_pkts++;

#ifdef CONFIG_PLATFORM_TIZENRT_OS
			/* TizenRT gets netif from netdev */
			/* Currently TizenRT only uses idx 0 */
			// index = precvbuf->idx_wlan;

			struct netdev *dev_tmp = NULL;
			dev_tmp = (struct netdev *)rtk_get_netdev(index);
			struct netif *netif = GET_NETIF_FROM_NETDEV(dev_tmp);
			if (netif->input(p_buf, netif) != ERR_OK) {
				LWIP_DEBUGF(NETIF_DEBUG, ("input processing error\n"));
				LINK_STATS_INC(link.err);
				pbuf_free(p_buf);
			} else {
				LINK_STATS_INC(link.recv);
			}
#else
			index = precvbuf->idx_wlan;
			LwIP_ethernetif_recv_inic(index, p_buf);
#endif //CONFIG_PLATFORM_TIZENRT_OS

			/* release the memory for this packet. */
			rtos_mem_free((u8 *)precvbuf);
		}
#endif
	} while (1);
	rtos_task_delete(NULL);
}
#endif

/**
 * @brief  to send skb to device for port idx.
 * @param  idx[in]: which port of wifi to tx.
 * @param  skb[inout]: skb to send.
 * @return -1 failed, 0 seccessful.
 */
static int inic_host_send_skb(int idx, struct sk_buff *skb)
{
	if (idx == -1) {
		RTK_LOGS(TAG_WLAN_INIC, "wlan index is wrong\n");
		return -1;
	}

	inic_ipc_send_msg(IPC_WIFI_CMD_XIMT_PKTS, (u32)skb, 0, idx);

	return 0;
}

/* ---------------------------- Public Functions ---------------------------- */
/**
 * @brief  to initialize the skb in host.
 * @param  none
 * @return none.
 */
void inic_host_init_skb(void)
{
	int i;

	if (host_skb_buff) {
#ifndef CONFIG_PLATFORM_TIZENRT_OS
		RTK_LOGE(TAG_WLAN_INIC, "host_skb_xx not free\n");
#endif //#ifndef CONFIG_PLATFORM_TIZENRT_OS
		return;
	}

	skb_buf_max_size = MAX_SKB_BUF_SIZE;
	if (wifi_user_config.skb_buf_size) {
		skb_buf_max_size = ((wifi_user_config.skb_buf_size + (SKB_CACHE_SZ - 1)) & ~(SKB_CACHE_SZ - 1));
	}

	host_skb_buff = (struct sk_buff *)rtos_mem_zmalloc(wifi_user_config.skb_num_ap * sizeof(struct sk_buff));
	if (!host_skb_buff) {
		RTK_LOGE(TAG_WLAN_INIC, "%s=>skb malloc fail!\n\r", __func__);
	}

	for (i = 0; i < wifi_user_config.skb_num_ap; i++) {
		INIT_LIST_HEAD(&host_skb_buff[i].list);
	}

	/*make sure the real memory is set to zero, or DCache_Invalidate in inic_host_send will get wrong values*/
	DCache_Clean((u32)host_skb_buff, (wifi_user_config.skb_num_ap * sizeof(struct sk_buff)));
}

void inic_host_deinit_skb(void)
{
	if (host_skb_buff) {
		rtos_mem_free((u8 *)host_skb_buff);
	}
}

/**
 * @brief  to initialize the parameters of recv.
 * @param  none
 * @return none.
 */
void inic_host_init_priv(void)
{
	memset(&g_inic_host_priv, 0, sizeof(struct host_priv));

	/* initialize semaphores. */
	rtos_sema_create_static(&(g_inic_host_priv.recv_sema), 0, 0xFFFFFFFF);
	rtos_sema_create_static(&(g_inic_host_priv.alloc_skb_sema), 0, 0xFFFFFFFF);
	rtos_sema_create_static(&(g_inic_host_priv.host_send_sema), 0, 0xFFFFFFFF);
	rtos_sema_give(g_inic_host_priv.host_send_sema);

	/* initialize the Rx queue. */
	rtw_init_queue(&(g_inic_host_priv.recv_queue));

	g_inic_host_priv.rx_bytes = 0;
	g_inic_host_priv.rx_pkts = 0;

	g_inic_host_priv.tx_bytes = 0;
	g_inic_host_priv.tx_pkts = 0;

#ifndef INIC_SKIP_RX_TASK
	/* Initialize the RX task */
	if (SUCCESS != rtos_task_create(&inic_host_rx_task_handle, (const char *const)"inic_host_rx_tasklet", (rtos_task_function_t)inic_host_rx_tasklet, NULL,
									WIFI_STACK_SIZE_INIC_TRX_HST, 4)) {
		RTK_LOGE(TAG_WLAN_INIC, "Create inic_host_rx_tasklet Err!!\n");
	}
#endif
}

/**
 * @brief  to put the Rx data from rx buffer into Rx queue.
 * @param  idx_wlan[in]: which port of wifi to rx.
 * @param  skb[inout]: data from the ipc bus, its structure is sk_buff.
 * @return none.
 */
void inic_host_rx_handler(int idx_wlan, struct sk_buff *skb)
{
	(void)idx_wlan;
	(void)skb;
#ifndef CONFIG_MP_SHRINK
	struct pbuf *p_buf = NULL, *temp_buf = NULL;
#ifndef INIC_SKIP_RX_TASK
	struct __queue *recv_queue = NULL;
	struct host_recv_buf *precvbuf = NULL;
#endif

#ifdef CONFIG_ENABLE_CACHE
	DCache_Invalidate(((u32)skb), sizeof(struct sk_buff));
#endif /* CONFIG_ENABLE_CACHE */

	/* allocate pbuf to store ethernet data from IPC. */
	p_buf = pbuf_alloc(PBUF_RAW, skb->len, PBUF_POOL);
	if (p_buf == NULL) {

		//just send rsp when pbuf alloc fail
		goto RSP;
	}

	/* cpoy data from skb(ipc data) to pbuf(ether net data) */
	temp_buf = p_buf;
	while (temp_buf) {
		/* If tot_len > PBUF_POOL_BUFSIZE_ALIGNED, the skb will be
		 * divided into several pbufs. Therefore, there is a while to
		 * use to assigne data to pbufs.
		 */
		memcpy(temp_buf->payload, skb->data, temp_buf->len);
		skb_pull(skb, temp_buf->len);
		temp_buf = temp_buf->next;
	}

#ifndef INIC_SKIP_RX_TASK
	recv_queue = &(g_inic_host_priv.recv_queue);
	/* allocate host_recv_buf and associate to the p_buf */
	precvbuf = (struct host_recv_buf *)rtos_mem_zmalloc(sizeof(struct host_recv_buf));
	if (!precvbuf) {
		goto RSP;
	}
	precvbuf->p_buf = p_buf;
	precvbuf->idx_wlan = idx_wlan;

	/* enqueue recv buffer  */
	inic_enqueue_recvbuf(precvbuf, recv_queue);
#endif

RSP:
#ifdef CONFIG_ENABLE_CACHE
	/*need cache clean here even if NP only need free skb,
	because AP may occur cache full issue and flush to skb to memory, but list in skb is old*/
	DCache_CleanInvalidate(((u32)skb), sizeof(struct sk_buff));
#endif /* CONFIG_ENABLE_CACHE */

	inic_ipc_send_msg(IPC_WIFI_MSG_RECV_DONE, (u32)skb, 0, 0);

#ifndef INIC_SKIP_RX_TASK
	/* wakeup recv task */
	rtos_sema_give(g_inic_host_priv.recv_sema);
#else
	if (p_buf != NULL) {
		g_inic_host_priv.rx_bytes += p_buf->len;
		g_inic_host_priv.rx_pkts++;

#ifdef CONFIG_PLATFORM_TIZENRT_OS
		/* TizenRT gets netif from netdev */
		/* Currently TizenRT only uses idx 0 */
		int index = 0;

		struct netdev *dev_tmp = NULL;
		dev_tmp = (struct netdev *)rtk_get_netdev(index);
		struct netif *netif = GET_NETIF_FROM_NETDEV(dev_tmp);
		if (netif->input(p_buf, netif) != ERR_OK) {
			LWIP_DEBUGF(NETIF_DEBUG, ("input processing error\n"));
			LINK_STATS_INC(link.err);
			pbuf_free(p_buf);
		} else {
			LINK_STATS_INC(link.recv);
		}
#else
		LwIP_ethernetif_recv_inic(idx_wlan, p_buf);
#endif //CONFIG_PLATFORM_TIZENRT_OS
	}
#endif
#endif
}

/**
 * @brief  to put the Rx data from rx buffer into Rx queue.
 * @param  idx[in]: which port of wifi to tx.
 * @param  sg_list[in]: pbuf list to send.
 * @param  sg_len[in]: the length of sg_list.
 * @param  total_len[in]: the length of data to send.
 * @return result.
 */
int inic_host_send(int idx, struct eth_drv_sg *sg_list, int sg_len,
				   int total_len, struct skb_raw_para *raw_para, u8 is_special_pkt)
{
	struct sk_buff *skb = NULL;
	struct eth_drv_sg *psg_list;
	int ret = 0, i = 0;
	static int used_skb_num = 0;
	int size = 0;
	u8 special_times = 0;

	rtos_sema_take(g_inic_host_priv.host_send_sema, 0xFFFFFFFF);
	/* allocate the skb buffer */

RETRY:
	skb = &host_skb_buff[used_skb_num];
	DCache_Invalidate((u32)skb, sizeof(struct sk_buff));
	if (skb->busy) {
		/*JIRA: https://jira.realtek.com/browse/RSWLANDIOT-8584 */
		if (is_special_pkt && (special_times < 9)) {
			special_times++;
			rtos_time_delay_ms(1);
			goto RETRY;
		}
		rtos_sema_give(g_inic_host_priv.host_send_sema);
		return ERR_BUF;
	}
	/* skb->list cannot be zeroed, and to save time on rx path, skb->buf is also not zeroed. */
	memset(&(skb->head), '\0', ((u32)(skb->buf) - (u32)&(skb->head)));
	size = SKB_DATA_ALIGN(total_len + SKB_DATA_ALIGN(SKB_WLAN_TX_EXTRA_LEN));
	skb->head = skb->buf;
	skb->end = skb->buf + size;
	skb->data = skb->buf + SKB_DATA_ALIGN(SKB_WLAN_TX_EXTRA_LEN);
	skb->tail = skb->buf + SKB_DATA_ALIGN(SKB_WLAN_TX_EXTRA_LEN);
	skb->busy = 1;
	skb->no_free = 1;
	ATOMIC_SET(&skb->ref, 1);

	if (raw_para) {
		skb->tx_raw.enable = TRUE;
		skb->tx_raw.rate = raw_para->rate;
		skb->tx_raw.retry_limit = raw_para->retry_limit;
		skb->tx_raw.ac_queue = raw_para->ac_queue;
		skb->tx_raw.agg_en = raw_para->agg_en;
		skb->tx_raw.sgi = raw_para->sgi;
		skb->tx_raw.device_id = raw_para->device_id;
	}

	used_skb_num++;
	used_skb_num = used_skb_num % wifi_user_config.skb_num_ap;

	psg_list = sg_list;
	for (i = 0; i < sg_len; i++) {
		psg_list = &sg_list[i];
		memcpy(skb->tail, (void *)(psg_list->buf), psg_list->len);
		skb_put(skb, psg_list->len);
	}

#ifdef CONFIG_ENABLE_CACHE
	DCache_CleanInvalidate((u32)skb, sizeof(struct sk_buff));
#endif /* CONFIG_ENABLE_CACHE */

	inic_host_send_skb(idx, skb);
	rtos_sema_give(g_inic_host_priv.host_send_sema);

	return ret;
}

/**
* @brief  haddle the message of IPC.
* @param  none.
* @return none.
*/
void inic_host_trx_event_hdl(u8 event_num, u32 msg_addr, u8 wlan_idx)
{
	switch (event_num) {
	/* receive the data from device */
	case IPC_WIFI_EVT_RECV_PKTS:
		inic_host_rx_handler(wlan_idx,
							 (struct sk_buff *)msg_addr);
		break;
	/* other contrl operations */
	default:
		RTK_LOGE(TAG_WLAN_INIC, "Host Unknown event(%lx)!\n\r", event_num);
		break;
	}
}

/* ---------------------------- Public Functions ---------------------------- */
/**
* @brief  to haddle the ipc message interrupt. If the message queue is
*  initialized, it will enqueue the ipc message and wake up the message
*  task to haddle the message. If last send message cannot be done, I will
*  set pending for next sending message.
* @param  Data[inout]: IPC data.
* @param  IrqStatus[in]: interrupt status.
* @param  ChanNum[in]: IPC channel number.
* @return none.
*/
void inic_host_trx_int_hdl(void *Data, u32 IrqStatus, u32 ChanNum)
{
	(void) Data;
	(void) IrqStatus;
	(void) ChanNum;

	struct inic_ipc_ex_msg *p_ipc_msg = NULL;
	sint ret = FAIL;

#ifdef IPC_DIR_MSG_RX
	PIPC_MSG_STRUCT p_ipc_recv_msg = ipc_get_message(IPC_DIR_MSG_RX, \
									 IPC_D2H_WIFI_TRX_TRAN);
	p_ipc_msg = (struct inic_ipc_ex_msg *)p_ipc_recv_msg->msg;
#else
	p_ipc_msg = (struct inic_ipc_ex_msg *)ipc_get_message(IPC_INT_CHAN_WIFI_TRX_TRAN);
#endif /* IPC_DIR_MSG_RX */

#ifdef CONFIG_ENABLE_CACHE
	DCache_Invalidate((u32)p_ipc_msg, sizeof(struct inic_ipc_ex_msg));
#endif /* CONFIG_ENABLE_CACHE */

	if (inic_msg_get_queue_status()) {
		/* put the ipc message to the queue */
		ret = inic_msg_enqueue(p_ipc_msg);
	} else {
		/* the message queue does't work, call haddle function
		* directly */
		inic_host_trx_event_hdl(p_ipc_msg->event_num, p_ipc_msg->msg_addr, p_ipc_msg->wlan_idx);
		ret = _SUCCESS;
	}

	if (ret == _SUCCESS) {
		p_ipc_msg->msg_queue_status = 0;
	} else {
		p_ipc_msg->msg_queue_status = IPC_WIFI_MSG_MEMORY_NOT_ENOUGH;
	}
	/* enqueuing message is seccussful, send acknowledgement to another port*/
	p_ipc_msg->event_num = IPC_WIFI_MSG_READ_DONE;
#ifdef CONFIG_ENABLE_CACHE
	DCache_Clean((u32)p_ipc_msg, sizeof(struct inic_ipc_ex_msg));
#endif /* CONFIG_ENABLE_CACHE */
}

