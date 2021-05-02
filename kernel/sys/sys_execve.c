#include <sys/syscall.h>
#include <proc/sched.h>
#include <proc/elf.h>
#include <x86/tss.h>
#include <mm/mm.h>
#include <stderr.h>
#include <string.h>

/* switch to user mode (defined in x86/scheduler.s) */
extern void enter_user_mode(uint32_t esp, uint32_t eip, uint32_t return_address);

/*
 * Copy an array from user memory to kernel memory.
 */
static char **copy_array_from_user_to_kernel(char *const src[], int len)
{
  char **ret;
  int i;

  if (len <= 0)
    return NULL;

  ret = (char **) kmalloc(sizeof(char *) * len);
  if (!ret)
    return NULL;

  for (i = 0; i < len; i++) {
    if (!src[i]) {
      ret[i] = NULL;
      continue;
    }

    ret[i] = strdup(src[i]);
    if (!ret[i])
      return NULL;
  }

  return ret;
}

/*
 * Copy an array from kernel memory to user memory.
 */
static char **copy_array_from_kernel_to_user(char **src, int len)
{
  int i, slen;
  char **ret;

  if (!src || len <= 0)
    return NULL;

  ret = (char **) sys_sbrk(sizeof(char *) * len);
  memset(ret, 0, sizeof(char *) * len);

  for (i = 0; i < len; i++) {
    if (!src[i]) {
      ret[i] = NULL;
      continue;
    }

    slen = strlen(src[i]);
    ret[i] = (char *) sys_sbrk(slen + 1);
    memset(ret[i], 0, slen + 1);
    memcpy(ret[i], src[i], slen);
  }

  return ret;
}

/*
 * Free an array of pointers.
 */
static void free_array(char **array, int len)
{
  int i;

  if (!array)
    return;

  for (i = 0; i < len; i++)
    if (array[i])
      kfree(array[i]);

  kfree(array);
}

/*
 * Execve system call.
 */
int sys_execve(const char *path, char *const argv[], char *const envp[])
{
  char **kernel_argv, **kernel_envp;
  char **user_argv, **user_envp;
  int ret, argv_len, envp_len;
  uint32_t stack;

  /* copy argv from user memory to kernel memory */
  argv_len = array_nb_pointers((void *) argv);
  kernel_argv = copy_array_from_user_to_kernel(argv, argv_len);

  /* copy argv from user memory to kernel memory */
  envp_len = array_nb_pointers((void *) envp);
  kernel_envp = copy_array_from_user_to_kernel(envp, envp_len);

  /* load elf binary */
  ret = elf_load(path);
  if (ret != 0)
    goto out;

  /* copy back argv and envp to user address space */
  user_argv = copy_array_from_kernel_to_user(kernel_argv, argv_len);
  user_envp = copy_array_from_kernel_to_user(kernel_envp, argv_len);

  /* free kernel memory */
  free_array(kernel_argv, argv_len);
  free_array(kernel_envp, envp_len);

  /* put argc, argv and envp in kernel stack */
  stack = current_task->user_stack;
  stack -= 4;
  *((uint32_t *) stack) = (uint32_t) user_envp;
  stack -= 4;
  *((uint32_t *) stack) = (uint32_t) user_argv;
  stack -= 4;
  *((uint32_t *) stack) = argv_len;

  /* go to user mode */
  tss_set_stack(0x10, current_task->kernel_stack);
  enter_user_mode(stack, current_task->user_entry, TASK_RETURN_ADDRESS);

out:
  free_array(kernel_argv, argv_len);
  free_array(kernel_envp, envp_len);
  return ret;
}
