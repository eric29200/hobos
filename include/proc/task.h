#ifndef _TASK_H_
#define _TASK_H_

#include <stddef.h>
#include <list.h>

#define STACK_SIZE        0x2000

#define TASK_READY        1
#define TASK_TERMINATED   2

/*
 * Kernel task structure.
 */
struct task_t {
  uint32_t tid;
  uint32_t esp;
  uint32_t kernel_stack;
  uint8_t state;
  struct list_head_t list;
};

/*
 * Registers structure.
 */
struct task_registers_t {
	uint32_t edi, esi, ebp, esp, ebx, edx, ecx, eax;
	uint32_t eip;
  uint32_t return_address;
  uint32_t parameter1;
  uint32_t parameter2;
  uint32_t parameter3;
};

struct task_t *create_task(void (*func)(void));
void destroy_task(struct task_t *task);

#endif
