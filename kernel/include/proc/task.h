#ifndef _TASK_H_
#define _TASK_H_

#include <proc/elf.h>
#include <mm/paging.h>
#include <fs/fs.h>
#include <stddef.h>
#include <list.h>

#define STACK_SIZE        0x2000

#define TASK_RUNNING      1
#define TASK_SLEEPING     2
#define TASK_ZOMBIE       3

#define NR_OPEN           32

/*
 * Kernel task structure.
 */
struct task_t {
  pid_t                       pid;                /* process id */
  uint8_t                     state;              /* process state */
  uint16_t                    uid;                /* user id */
  uint8_t                     gid;                /* group id */
  uint16_t                    umask;              /* umask */
  int                         exit_code;          /* exit code */
  struct task_t *             parent;            /* parent process */
  uint32_t                    kernel_stack;       /* kernel stack */
  uint32_t                    esp;                /* kernel stack pointer */
  uint32_t                    user_entry;         /* user entry point */
  uint32_t                    user_stack;         /* user stack */
  uint32_t                    start_text;         /* user text segment start */
  uint32_t                    end_text;           /* user text segment end */
  uint32_t                    start_brk;          /* user data segment start */
  uint32_t                    end_brk;            /* user data segment end */
  void *                      waiting_chan;      /* waiting channel */
  struct inode_t *            cwd;               /* current working directory */
  struct registers_t          user_regs;          /* saved registers at syscall entry */
  struct page_directory_t *   pgd;               /* page directory */
  struct file_t *             filp[NR_OPEN];     /* opened files */
  struct list_head_t          list;               /* next process */
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

struct task_t *create_kinit_task(void (*func)(void));
struct task_t *create_init_task();
struct task_t *fork_task(struct task_t *parent);
void destroy_task(struct task_t *task);

#endif
