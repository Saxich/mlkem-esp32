// SPDX-License-Identifier: Apache-2.0
#ifndef TASKPRIORITIES_H
#define TASKPRIORITIES_H

#include "freertos/FreeRTOS.h"

// Task stack size in words (4 bytes per word on ESP32)
#define TASK_STACK 40000

// Task priorities
#define MAIN_TASK_PRIORITY (tskIDLE_PRIORITY + 2)

#endif // TASKPRIORITIES_H
