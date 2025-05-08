/*
 * Copyright (c) 2024 Realtek Semiconductor Corp.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include "ameba.h"
#include "os_wrapper.h"

int rtos_mutex_create_static(rtos_mutex_t *pp_handle)
{
	return rtos_mutex_create(pp_handle);
}

int rtos_mutex_delete_static(rtos_mutex_t p_handle)
{
	return rtos_mutex_delete(p_handle);
}

int rtos_mutex_recursive_create_static(rtos_mutex_t *pp_handle)
{
	return rtos_mutex_recursive_create(pp_handle);
}

int rtos_mutex_recursive_delete_static(rtos_mutex_t p_handle)
{
	return rtos_mutex_delete_static(p_handle);
}

int rtos_mutex_create(rtos_mutex_t *pp_handle)
{
	return rtos_sema_create(pp_handle, 1, 1);
}

int rtos_mutex_delete(rtos_mutex_t p_handle)
{
	return rtos_sema_delete(p_handle);
}

int rtos_mutex_take(rtos_mutex_t p_handle, uint32_t wait_ms)
{
	return rtos_sema_take(p_handle, wait_ms);
}

int rtos_mutex_give(rtos_mutex_t p_handle)
{
	return rtos_sema_give(p_handle);
}

int rtos_mutex_recursive_create(rtos_mutex_t *pp_handle)
{
	return rtos_mutex_create(pp_handle);
}

int rtos_mutex_recursive_delete(rtos_mutex_t p_handle)
{
	return rtos_mutex_delete(p_handle);
}

int rtos_mutex_recursive_take(rtos_mutex_t p_handle, uint32_t wait_ms)
{
	return rtos_mutex_take(p_handle, wait_ms);
}

int rtos_mutex_recursive_give(rtos_mutex_t p_handle)
{
	return rtos_mutex_give(p_handle);
}
