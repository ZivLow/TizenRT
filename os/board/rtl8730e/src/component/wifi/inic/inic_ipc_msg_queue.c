/**
  ******************************************************************************
  * @file    inic_ipc_msg_queue.c
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

#define __INIC_IPC_MSG_QUEUE_C__

/* -------------------------------- Includes -------------------------------- */
/* external head files */

#include "platform_autoconf.h"
#include "rtw_skbuff.h"


/* internal head files */
#include "inic_ipc_msg_queue.h"
#ifdef CONFIG_AS_INIC_NP
#include "wifi_intf_drv_to_upper.h"

extern struct wifi_user_conf wifi_user_config;
#endif
extern void inic_host_trx_event_hdl(u8 event_num, u32 msg_addr, u8 wlan_idx);
extern void inic_dev_trx_event_hdl(u8 event_num, u32 msg_addr, u8 wlan_idx);

/* ---------------------------- Global Variables ---------------------------- */

/* --------------------------- Private Variables ---------------------------- */

static struct ipc_msg_q_priv g_ipc_msg_q_priv;
#ifdef IPC_DIR_MSG_TX
struct inic_ipc_ex_msg g_inic_ipc_ex_msg __attribute__((aligned(64)));
#else
static struct inic_ipc_ex_msg g_inic_ipc_ex_msg = {0};
#endif

rtos_task_t inic_msg_q_task_handler;

/* ---------------------------- Private Functions --------------------------- */
/**
 * @brief  put the ipc message to queue.
 * @param  p_node[in]: the pointer for the ipc message node that need to be
 * 	pushed into the queue.
 * @param  p_queue[in]: the queue used to store the p_node.
 * @return status, always _SUCCESS.
 */
static sint enqueue_ipc_msg_node(struct ipc_msg_node *p_node, struct __queue *p_queue)
{
#ifdef CONFIG_PLATFORM_TIZENRT_OS
	irqstate_t flags = tizenrt_critical_enter();
#else
	rtos_critical_enter();
#endif //CONFIG_PLATFORM_TIZENRT_OS

	/* put the ipc message to the tail of the queue */
	rtw_list_insert_tail(&(p_node->list), get_list_head(p_queue));

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	tizenrt_critical_exit(flags);
#else
	rtos_critical_exit();
#endif //CONFIG_PLATFORM_TIZENRT_OS

	return _SUCCESS;
}

/**
 * @brief  get the ipc message from queue.
 * @param  p_ipc_msg[in]: the queue used to store the p_node.
 * @return the ipc_msg_node got from message queue.
 */
static struct ipc_msg_node *dequeue_ipc_msg_node(struct __queue *p_queue)
{
	struct ipc_msg_node *p_node;
	struct list_head *plist, *phead;

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	irqstate_t flags = tizenrt_critical_enter();
#else
	rtos_critical_enter();
#endif //CONFIG_PLATFORM_TIZENRT_OS

	if (rtw_queue_empty(p_queue) == _TRUE) {
		p_node = NULL;
	} else {
		phead = get_list_head(p_queue);
		plist = get_next(phead);
		p_node = LIST_CONTAINOR(plist, struct ipc_msg_node, list);
		rtw_list_delete(&(p_node->list));
	}

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	tizenrt_critical_exit(flags);
#else
	rtos_critical_exit();
#endif //CONFIG_PLATFORM_TIZENRT_OS

	return p_node;
}

/**
 * @brief  task to operation the queue when the queue is not empty.
 * @param  none
 * @return none
 */
void inic_msg_q_task(void)
{
	struct ipc_msg_node *p_node = NULL;
	struct __queue *p_queue = NULL;
	static u8  continus_handle = 0;
	u32	msg_addr;
	u8	wlan_idx;
	u8	event_num;

	p_queue = &g_ipc_msg_q_priv.msg_queue;
#ifndef INIC_SKIP_NP_MSG_TASK
	do {
		//rtos_sema_take(g_ipc_msg_q_priv.msg_q_sema, RTOS_MAX_TIMEOUT);
		rtos_sema_take(g_ipc_msg_q_priv.msg_q_sema, RTOS_MAX_TIMEOUT);
		UNUSED(continus_handle);
#else
	continus_handle = 0;
#endif
		/* get the data from tx queue. */
		while (1) {
#ifdef INIC_SKIP_NP_MSG_TASK
			continus_handle++;
			if (continus_handle == 50) {
				// Prevent from blocking other processes due to Continuous handle
				rtw_single_thread_wakeup();
				break;
			}
#endif
			p_node = dequeue_ipc_msg_node(p_queue);
			if (p_node == NULL) {
				break;
			}

			event_num = p_node->event_num;
			msg_addr = p_node->msg_addr;
			wlan_idx = p_node->wlan_idx;

			/* release the memory for this ipc message. */
#ifdef CONFIG_PLATFORM_TIZENRT_OS
			irqstate_t flags = tizenrt_critical_enter();
#else
			rtos_critical_enter();
#endif //CONFIG_PLATFORM_TIZENRT_OS

			p_node->is_used = 0;

#ifdef CONFIG_PLATFORM_TIZENRT_OS
			tizenrt_critical_exit(flags);
#else
			rtos_critical_exit();
#endif //CONFIG_PLATFORM_TIZENRT_OS

			/* haddle the message */
#ifdef CONFIG_AS_INIC_NP
			inic_dev_trx_event_hdl(event_num, msg_addr, wlan_idx);
#elif CONFIG_AS_INIC_AP
			inic_host_trx_event_hdl(event_num, msg_addr, wlan_idx);
#endif
		}
#ifndef INIC_SKIP_NP_MSG_TASK
	} while (g_ipc_msg_q_priv.b_queue_working);
	rtos_task_delete(NULL);
#endif
}

/* ---------------------------- Public Functions ---------------------------- */
/**
 * @brief  to initialize the message queue.
 * @param  task_func[in]: the pointer to the task function to operate this
 * 	queue.
 * @return none
 */
void inic_msg_q_init(void)
{
	int i = 0;

	if (g_ipc_msg_q_priv.ipc_msg_pool) {/*https://jira.realtek.com/browse/RSWLANDIOT-10146*/
		return;
	}

	memset(&g_ipc_msg_q_priv, 0, sizeof(struct ipc_msg_q_priv));
	memset(&g_inic_ipc_ex_msg, 0, sizeof(struct inic_ipc_ex_msg));

	/* initialize queue. */
	rtw_init_queue(&(g_ipc_msg_q_priv.msg_queue));

	/* initialize the sema to wakeup the message queue task */
	rtos_sema_create_static(&g_ipc_msg_q_priv.msg_q_sema, 0, RTOS_MAX_TIMEOUT);
	rtos_sema_create_static(&g_ipc_msg_q_priv.msg_send_sema, 0, RTOS_MAX_TIMEOUT);
	rtos_sema_give(g_ipc_msg_q_priv.msg_send_sema);


#ifdef CONFIG_AS_INIC_NP
	g_ipc_msg_q_priv.ipc_msg_node_max = wifi_user_config.skb_num_np + wifi_user_config.skb_num_ap;
#else
	g_ipc_msg_q_priv.ipc_msg_node_max = wifi_user_config.skb_num_np;
#endif
	g_ipc_msg_q_priv.ipc_msg_pool = (struct ipc_msg_node *)rtos_mem_zmalloc(g_ipc_msg_q_priv.ipc_msg_node_max * sizeof(struct ipc_msg_node));
	for (i = 0; i < g_ipc_msg_q_priv.ipc_msg_node_max; i++) {
		g_ipc_msg_q_priv.ipc_msg_pool[i].is_used = 0;
	}

#ifndef INIC_SKIP_NP_MSG_TASK
	/* Initialize the queue task */
	if (SUCCESS != rtos_task_create(&inic_msg_q_task_handler, (const char *const)"inic_msg_q_task", (rtos_task_function_t)inic_msg_q_task, NULL, WIFI_STACK_SIZE_INIC_MSG_Q,
									CONFIG_INIC_IPC_MSG_Q_PRI)) {
		RTK_LOGE(TAG_WLAN_INIC, "Create msg_q_task Err!\n");
	}
#endif
	/* sign the queue is working */
	g_ipc_msg_q_priv.b_queue_working = 1;
}

/**
 * @brief  put the ipc message to queue.
 * @param  p_node[in]: the pointer for the ipc message that need to be
 * 	pushed into the queue.
 * @return status, always _SUCCESS.
 */
sint inic_msg_enqueue(struct inic_ipc_ex_msg *p_ipc_msg)
{
	struct ipc_msg_node *p_node = NULL;
	struct __queue *p_queue = &(g_ipc_msg_q_priv.msg_queue);
	sint ret = FAIL;
	int i = 0;

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	irqstate_t flags = tizenrt_critical_enter();
#else
	rtos_critical_enter();
#endif //CONFIG_PLATFORM_TIZENRT_OS

	/* allocate memory for message node */
	for (i = 0; i < g_ipc_msg_q_priv.ipc_msg_node_max; i++) {
		if (g_ipc_msg_q_priv.ipc_msg_pool[i].is_used == 0) {
			p_node = &(g_ipc_msg_q_priv.ipc_msg_pool[i]);
			/* a node is used, the free node will decrease */
			p_node->is_used = 1;
			break;
		}
	}

#ifdef CONFIG_PLATFORM_TIZENRT_OS
	tizenrt_critical_exit(flags);
#else
	rtos_critical_exit();
#endif //CONFIG_PLATFORM_TIZENRT_OS

	if (p_node == NULL) {
		RTK_LOGE(TAG_WLAN_INIC, "NO buf for new nodes!\n");
		goto func_out;
	}

	/* To store the ipc message to queue's node. */
	p_node->event_num = p_ipc_msg->event_num;
	p_node->msg_addr = p_ipc_msg->msg_addr;
	p_node->wlan_idx = p_ipc_msg->wlan_idx;

	/* put the ipc message to the queue */
	ret = enqueue_ipc_msg_node(p_node, p_queue);


func_out:
	/* wakeup task */
#ifdef INIC_SKIP_NP_MSG_TASK
	rtw_single_thread_wakeup();
#else
	rtos_sema_give(g_ipc_msg_q_priv.msg_q_sema);
#endif
	return ret;
}

/**
 * @brief  to deinitialize the message queue.
 * @param  none.
 * @return none
 */
void inic_msg_q_deinit(void)
{
	/* sign the queue is stop */
	g_ipc_msg_q_priv.b_queue_working = 0;

	/* free sema to wakeup the message queue task */
	rtos_sema_delete_static(g_ipc_msg_q_priv.msg_q_sema);
	/* de initialize queue, todo */
}

/**
 * @brief  to get the status of queue, working or stop.
 * @param  none.
 * @return the status of queue, 1 means working, 0 means stop.
 */
u8 inic_msg_get_queue_status(void)
{
	return g_ipc_msg_q_priv.b_queue_working;
}

/**
 * @brief  to send the ipc message. It will wait when the last message is not
 * 	read.
 * @param  p_ipc_msg[inout]: the message to send.
 * @return none.
 */
void inic_ipc_send_msg(u32 event_num, u32 msg_addr, u32 msg_queue_status, u32 wlan_idx)
{
	IPC_MSG_STRUCT g_inic_ipc_msg = {0};

	u32 cnt = 100000;

	/* wifi_hal_interrupt_handle(little_thread) will call rtos_critical_enter(close cpu scheduling), before call this func.
	if another thread(single_thread) hasn't up_sema, little_thread and single_thread will deadlock */
	/* LINUX_TODO: better method? */
#ifdef CONFIG_AS_INIC_NP
	if (wifi_user_config.cfg80211) {
		rtos_critical_enter();
	} else {
		rtos_sema_take(g_ipc_msg_q_priv.msg_send_sema, RTOS_MAX_TIMEOUT);
	}
#else
	rtos_sema_take(g_ipc_msg_q_priv.msg_send_sema, RTOS_MAX_TIMEOUT);
#endif

	/* Wait for another port ack acknowledgement last message sending */
	while (g_inic_ipc_ex_msg.event_num != IPC_WIFI_MSG_READ_DONE) {
		DelayUs(2);
		DCache_Invalidate((u32)&g_inic_ipc_ex_msg, sizeof(struct inic_ipc_ex_msg));
		cnt--;
		if (cnt == 0) {
			RTK_LOGS(TAG_WLAN_INIC, "inic ipc wait timeout\n");
			break;
		}
	}
	/* Get the warning of queue's depth not enough after recv MSG_READ_DONE,
	delay send the next message */
	if (g_inic_ipc_ex_msg.msg_queue_status == IPC_WIFI_MSG_MEMORY_NOT_ENOUGH) {
		rtos_time_delay_ms(1);
	}

	/* Send the new message after last one acknowledgement */
	g_inic_ipc_ex_msg.event_num = event_num;
	g_inic_ipc_ex_msg.msg_addr = msg_addr;
	g_inic_ipc_ex_msg.msg_queue_status = msg_queue_status;
	g_inic_ipc_ex_msg.wlan_idx = wlan_idx;
	DCache_Clean((u32)&g_inic_ipc_ex_msg, sizeof(struct inic_ipc_ex_msg));

#ifdef IPC_DIR_MSG_TX
	g_inic_ipc_msg.msg_type = IPC_USER_POINT;
	g_inic_ipc_msg.msg = (u32)&g_inic_ipc_ex_msg;
	g_inic_ipc_msg.msg_len = sizeof(struct inic_ipc_ex_msg);
	ipc_send_message(IPC_DIR_MSG_TX, IPC_INT_CHAN_WIFI_TRX_TRAN, \
					 (PIPC_MSG_STRUCT)&g_inic_ipc_msg);
#else
	ipc_send_message(IPC_INT_CHAN_WIFI_TRX_TRAN, (PIPC_MSG_STRUCT)&g_inic_ipc_ex_msg);
#endif /* IPC_DIR_MSG_TX */

#ifdef CONFIG_AS_INIC_NP
	if (wifi_user_config.cfg80211) {
		rtos_critical_exit();
	} else {
		rtos_sema_give(g_ipc_msg_q_priv.msg_send_sema);
	}
#else
	rtos_sema_give(g_ipc_msg_q_priv.msg_send_sema);
#endif
}
