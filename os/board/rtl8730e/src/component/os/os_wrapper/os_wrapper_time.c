/*
 * Copyright (c) 2024 Realtek Semiconductor Corp.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ameba.h"
//#include "ameba_pmu.h"
#include "os_wrapper.h"

void rtos_time_delay_ms(uint32_t ms)
{
	usleep((unsigned int)ms * 1000);
}

void rtos_time_delay_us(uint32_t us)
{
	usleep((unsigned int)us);
}

uint32_t rtos_time_get_current_system_time_ms(void)
{
	return (uint32_t)clock();
}

uint32_t rtos_time_get_current_system_time_us(void)
{
	return (rtos_time_get_current_system_time_ns() / 1000);
}

uint64_t rtos_time_get_current_system_time_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	return (uint64_t)ts.tv_nsec;
}
