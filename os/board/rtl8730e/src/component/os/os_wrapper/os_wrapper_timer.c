/*
 * Copyright (c) 2024 Realtek Semiconductor Corp.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ameba.h"
#include "os_wrapper.h"

struct os_wrapper_timer_entry {
	struct list_head list;
	struct os_wrapper_timer_list *timer;
};

static _list os_wrapper_timer_table;
bool os_wrapper_timer_table_init = 0;

/* FreeRTOS Static Implementation */
#if( configSUPPORT_STATIC_ALLOCATION == 1 )
extern StaticTimer_t *__reserved_get_timer_from_poll(void);
extern void __reserved_release_timer_to_poll(void *buf);
#endif

int rtos_timer_create_static(rtos_timer_t *pp_handle, const char *p_timer_name, uint32_t timer_id,
							 uint32_t interval_ms, uint8_t reload, void (*p_timer_callback)(void *))
{
#if( configSUPPORT_STATIC_ALLOCATION == 1 )
	StaticTimer_t *timer;
	TickType_t timer_ticks;

	timer = __reserved_get_timer_from_poll();

	if (timer == NULL) {
		return rtos_timer_create(pp_handle, p_timer_name, timer_id, interval_ms, reload, p_timer_callback);
	} else {
		timer_ticks = (TickType_t)((interval_ms + portTICK_PERIOD_MS - 1) / portTICK_PERIOD_MS);

		*pp_handle = xTimerCreateStatic(p_timer_name, timer_ticks, (BaseType_t)reload,
										(void *)timer_id, (TimerCallbackFunction_t)p_timer_callback, timer);

		if (*pp_handle == NULL) {
			return FAIL;
		}
	}
	return SUCCESS;
#else
	return rtos_timer_create(pp_handle, p_timer_name, timer_id, interval_ms, reload, p_timer_callback);
#endif
}

int rtos_timer_delete_static(rtos_timer_t p_handle, uint32_t wait_ms)
{
#if( configSUPPORT_STATIC_ALLOCATION == 1 )
	rtos_timer_t handle_for_delete = p_handle;
	while (rtos_timer_delete(handle_for_delete, wait_ms) != SUCCESS) {};
	// wait timer until inactive in __reserved_release_timer_to_poll
	__reserved_release_timer_to_poll(p_handle);
	return SUCCESS;
#else
	return rtos_timer_delete(p_handle, wait_ms);
#endif
}

void os_wrapper_timer_wrapper(void *timer)
{
	_list *plist;
	struct os_wrapper_timer_entry *timer_entry = NULL;

	irqstate_t flags = tizenrt_critical_enter();

	plist = get_next(&os_wrapper_timer_table);
	while ((rtw_end_of_queue_search(&os_wrapper_timer_table, plist)) == FALSE) {
		timer_entry = LIST_CONTAINOR(plist, struct os_wrapper_timer_entry, list);
		if (timer_entry->timer == timer) {
			break;
		}
		plist = get_next(plist);
	}

	tizenrt_critical_exit(flags);

	if (plist == &os_wrapper_timer_table) {
		dbg("find timer_entry fail\n");
		return;
	}

	if (timer_entry->timer->reload) {
		if (work_queue(LPWORK, timer_entry->timer->work_hdl, os_wrapper_timer_wrapper, (void *)(timer_entry->timer), (timer_entry->timer->timeout * TICK_PER_SEC / 1000L)) != OK) {
			dbg("work queue fail\n");
			timer_entry->timer->live = 0;
		}
	} else {
		timer_entry->timer->live = 0;
	}

	if (timer_entry->timer->function) {
		timer_entry->timer->function(timer);
	}
}

int rtos_timer_create(rtos_timer_t *pp_handle, const char *p_timer_name, uint32_t timer_id,
					  uint32_t interval_ms, uint8_t reload, void (*p_timer_callback)(void *))
{
	struct os_wrapper_timer_list *timer;
	struct os_wrapper_timer_entry *timer_entry;

	if (!pp_handle) {
		dbg("pp_handle is NULL\n");
		return FAIL;
	}

	if (*pp_handle) {
		dbg("timer already init\n");
		return FAIL;
	}

	timer = (struct os_wrapper_timer_list *)kmm_zalloc(sizeof(struct os_wrapper_timer_list));
	if (timer == NULL) {
		dbg("alloc os_wrapper_timer_list fail\n");
		return FAIL;
	}

#ifdef CONFIG_DEBUG_MM_HEAPINFO
	DEBUG_SET_CALLER_ADDR(timer);
#endif

	timer->work_hdl = (struct work_s *)kmm_zalloc(sizeof(struct work_s));
	if (timer->work_hdl == NULL) {
		dbg("alloc work_s fail\n");
		rtos_mem_free(timer);
		return FAIL;
	}

#ifdef CONFIG_DEBUG_MM_HEAPINFO
	DEBUG_SET_CALLER_ADDR(timer->work_hdl);
#endif

	timer->timer_hdl = timer;
	memcpy(timer->timer_name, p_timer_name, TMR_NAME_SIZE);
	timer->timer_id = timer_id;
	timer->timeout = interval_ms;
	timer->reload = reload;
	timer->live = 0;
	timer->function = p_timer_callback;

	*pp_handle = timer;

	if (!os_wrapper_timer_table_init) {
		INIT_LIST_HEAD(&os_wrapper_timer_table);
		os_wrapper_timer_table_init = 1;
	}

	timer_entry = rtos_mem_zmalloc(sizeof(struct os_wrapper_timer_entry));
	if (timer_entry == NULL) {
		dbg("alloc os_wrapper_timer_entry fail\n");
		rtos_mem_free(timer->work_hdl);
		rtos_mem_free(timer);
		return FAIL;
	}

#ifdef CONFIG_DEBUG_MM_HEAPINFO
	DEBUG_SET_CALLER_ADDR(timer_entry);
#endif

	timer_entry->timer = timer;

	irqstate_t flags = tizenrt_critical_enter();
	rtw_list_insert_head(&(timer_entry->list), &os_wrapper_timer_table);
	tizenrt_critical_exit(flags);

	return SUCCESS;
}

int rtos_timer_delete(rtos_timer_t p_handle, uint32_t wait_ms)
{
	int ret;
	_list *plist;
	struct os_wrapper_timer_list *timer;
	struct os_wrapper_timer_entry *timer_entry;

	if (p_handle == NULL) {
		dbg("p_handle is NULL\n");
		return FAIL;
	}

	timer = (struct os_wrapper_timer_list *)p_handle;
	ret = work_cancel(LPWORK, timer->work_hdl);
	if (ret != OK && ret != -ENOENT) {
		dbg("work cancel fail\n");
		return FAIL;
	}

	irqstate_t flags = tizenrt_critical_enter();

	plist = get_next(&os_wrapper_timer_table);
	while ((rtw_end_of_queue_search(&os_wrapper_timer_table, plist)) == FALSE) {
		timer_entry = LIST_CONTAINOR(plist, struct os_wrapper_timer_entry, list);
		if (timer_entry->timer == timer) {
			rtw_list_delete(plist);
			rtos_mem_free(timer_entry);
			break;
		}
		plist = get_next(plist);
	}

	tizenrt_critical_exit(flags);

	if (plist == &os_wrapper_timer_table) {
		dbg("find timer_entry fail\n");
		return FAIL;
	}

	timer->data = NULL;
	timer->function = NULL;
	timer->live = 0;
	timer->reload = 0;
	timer->timeout = 0;
	timer->timer_id = 0;
	memset(timer->timer_name, 0, TMR_NAME_SIZE);
	rtos_mem_free(timer->work_hdl);
	timer->work_hdl = NULL;
	rtos_mem_free(timer);
	timer = NULL;

	return SUCCESS;
}

int rtos_timer_start(rtos_timer_t p_handle, uint32_t wait_ms)
{
	int ret;
	struct os_wrapper_timer_list *timer;

	if (p_handle == NULL) {
		dbg("p_handle is NULL\n");
		return FAIL;
	}

	timer = (struct os_wrapper_timer_list *)p_handle;
	ret = work_queue(LPWORK, timer->work_hdl, os_wrapper_timer_wrapper, (void *)timer, (timer->timeout * TICK_PER_SEC / 1000L));
	if (ret == -EALREADY) {
		if (work_cancel(LPWORK, timer->work_hdl) != OK) {
			dbg("work cancel fail\n");
			return FAIL;
		}

		if (work_queue(LPWORK, timer->work_hdl, os_wrapper_timer_wrapper, (void *)timer, (timer->timeout * TICK_PER_SEC / 1000L)) != OK) {
			dbg("work queue fail\n");
			return FAIL;
		}
	} else if (ret != OK) {
		dbg("work queue fail\n");
		return FAIL;
	}

	timer->live = 1;

	return SUCCESS;
}

int rtos_timer_stop(rtos_timer_t p_handle, uint32_t wait_ms)
{
	struct os_wrapper_timer_list *timer;

	if (p_handle == NULL) {
		dbg("p_handle is NULL\n");
		return FAIL;
	}

	timer = (struct os_wrapper_timer_list *)p_handle;
	if (work_cancel(LPWORK, timer->work_hdl) != OK) {
		dbg("work cancel fail\n");
		return FAIL;
	}

	timer->live = 0;

	return SUCCESS;
}

int rtos_timer_change_period(rtos_timer_t p_handle, uint32_t interval_ms, uint32_t wait_ms)
{
	int ret;
	struct os_wrapper_timer_list *timer;

	if (p_handle == NULL) {
		dbg("p_handle is NULL\n");
		return FAIL;
	}

	timer = (struct os_wrapper_timer_list *)p_handle;
	ret = work_queue(LPWORK, timer->work_hdl, os_wrapper_timer_wrapper, (void *)timer, (interval_ms * TICK_PER_SEC / 1000L));
	if (ret == -EALREADY) {
		if (work_cancel(LPWORK, timer->work_hdl) != OK) {
			dbg("work cancel fail\n");
			return FAIL;
		}

		if (work_queue(LPWORK, timer->work_hdl, os_wrapper_timer_wrapper, (void *)timer, (interval_ms * TICK_PER_SEC / 1000L)) != OK) {
			dbg("work queue fail\n");
			return FAIL;
		}
	} else if (ret != OK) {
		dbg("work queue fail\n");
		return FAIL;
	}

	timer->timeout = interval_ms;
	timer->live = 1;

	return SUCCESS;
}

uint32_t rtos_timer_is_timer_active(rtos_timer_t p_handle)
{
	struct os_wrapper_timer_list *timer;

	if (p_handle == NULL) {
		dbg("p_handle is NULL\n");
		return 0;
	}

	timer = (struct os_wrapper_timer_list *)p_handle;

	return timer->live;
}

uint32_t rtos_timer_get_id(rtos_timer_t p_handle)
{
	struct os_wrapper_timer_list *timer;

	if (p_handle == NULL) {
		dbg("p_handle is NULL\n");
		return 0;
	}

	timer = (struct os_wrapper_timer_list *)p_handle;

	return timer->timer_id;
}

