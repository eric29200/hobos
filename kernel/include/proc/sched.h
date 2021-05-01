#ifndef _SCHED_H_
#define _SCHED_H_

#include <proc/task.h>

#define TASK_RETURN_ADDRESS               0xFFFFFFFF

extern struct task_t *init_task;
extern struct task_t *current_task;

int init_scheduler(void (*kinit_func)());
int spawn_init();
pid_t get_next_pid();
void schedule();

void task_sleep(void *chan);
void task_wakeup(void *chan);

#endif
