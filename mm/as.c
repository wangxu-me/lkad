#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/syscalls.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/smp.h>
#include <linux/sem.h>
#include <linux/msg.h>
#include <linux/mman.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/personality.h>
#include <linux/random.h>
#include <linux/uaccess.h>
#include <asm/syscalls.h>

struct mmap_info;

SYSCALL_DEFINE0(as_create)
{
    return -ENOSYS;
}

SYSCALL_DEFINE2(as_mmap, unsigned int, fd, struct mmap_info __user *, info)
{
    return -ENOSYS;
}

SYSCALL_DEFINE3(as_munmap, unsigned  int, fd, unsigned long, addr, 
                unsigned long, len)
{
    return -ENOSYS;
}

SYSCALL_DEFINE4(as_mprotect, unsigned int, fd, unsigned long, addr,
                unsigned long, len, unsigned int, prot)
{
    return -ENOSYS;
}

SYSCALL_DEFINE1(as_switch_mm, unsigned int, fd)
{
    return -ENOSYS;
}

SYSCALL_DEFINE1(as_destroy, unsigned int, fd)
{
    return -ENOSYS;
}
