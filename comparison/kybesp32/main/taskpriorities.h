#ifndef TASKPRIORITIES_H
#define TASKPRIORITIES_H

#include "freertos/FreeRTOS.h"

// Must stay above INDCPA_SUBTASK_PRIORITY (10, defined in components/common/taskpriorities.h)
// so both indcpa subtasks are created before either one preempts the calling task,
// allowing true parallel execution across both cores.
#define MAIN_TASK_PRIORITY      11

#if KYBER_K == 3
    #define TASK_STACK 25000
#elif KYBER_K == 4
    #define TASK_STACK 40000
#else
    #define TASK_STACK 20000
#endif

#endif
