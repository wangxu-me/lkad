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
#include <linux/mmu_context.h>
#include <linux/vmacache.h>
#include <linux/anon_inodes.h>
#include <asm/syscalls.h>
#include <asm/mmu_context.h>
#include "as.h"

// static long mm_nr = 0;

static int as_release(struct inode *inode, struct file *file);
struct file_operations as_fops = {
    .release = as_release,
    };


static struct mm_struct *get_mm_from_fd(int fd)
{
    struct file *f;
    struct mm_struct *mm = ERR_PTR(-EBADF);

    f = fget(fd);
    if (!f) {
        return mm;
    }

    if (f->f_op != &as_fops) {
        mm = ERR_PTR(-EINVAL);
        goto out;
    }

    mm = f->private_data;

out:
    fput(f);
    return mm;
}

SYSCALL_DEFINE0(as_create)
{
    int fd;
    struct mm_struct *mm;

    mm = mm_alloc();
    if (!mm) {
        return -ENOMEM;
    }

    fd = anon_inode_getfd("[adress-space]", &as_fops, mm, 0);
    if (fd < 0) {
        mmput(mm);
        return fd;
    }


    /* add to mmlist? */
    spin_lock(&mmlist_lock);
    list_add(&mm->mmlist, &current->mm->mmlist);
    /* looks like we will never go back to the initial mm..
     * Therefore, let it vanish
     * */
#if 0
    if (!mm_nr) {
        mmget(current->mm);
        mm_nr++;
    }
#endif
    spin_unlock(&mmlist_lock);

    return fd;
}

SYSCALL_DEFINE2(as_mmap, unsigned int, fd, struct mmap_info __user *, info)
{
    struct mmap_info kinfo;
    struct mm_struct *mm;

    if (copy_from_user(&kinfo, info, sizeof(struct mmap_info))) {
        return -EFAULT;
    }

    mm = get_mm_from_fd(fd);
    if (IS_ERR(mm)) {
        return PTR_ERR(mm);
    }

    return ksys_mmap_pgoff2(mm, kinfo.addr, kinfo.len, kinfo.prot, kinfo.flags,
                                kinfo.fd, kinfo.offset >> PAGE_SHIFT);
}

SYSCALL_DEFINE3(as_munmap, unsigned  int, fd, unsigned long, addr,
                unsigned long, len)
{
    struct mm_struct *mm;
    int ret;

    mm = get_mm_from_fd(fd);
    if (IS_ERR(mm)) {
        return PTR_ERR(mm);
    }

    if (down_write_killable(&mm->mmap_sem)) {
        return -EINTR;
    }

    ret = do_munmap(mm, addr, len, NULL);

    up_write(&mm->mmap_sem);

    return ret;
}

SYSCALL_DEFINE4(as_mprotect, unsigned int, fd, unsigned long, addr,
                unsigned long, len, unsigned int, prot)
{
    struct mm_struct *mm;

    mm = get_mm_from_fd(fd);
    if (IS_ERR(mm)) {
        return PTR_ERR(mm);
    }

    return do_mprotect_pkey2(mm, addr, len, prot, -1);;
}

SYSCALL_DEFINE1(as_switch_mm, unsigned int, fd)
{
    struct mm_struct *mm, *old_mm, *active_mm;
    struct task_struct *tsk = current;

    mm = get_mm_from_fd(fd);
    if (IS_ERR(mm)) {
        return PTR_ERR(mm);
    }

    old_mm = tsk->mm;

    if (mm == old_mm || mm == tsk->active_mm) {
        return 0;
    }

    mm_release(tsk, old_mm);

    /* we are not kernel thread.
     * we definitely have task->mm and task->active_mm..
     * and mm == active_mm.
     * */
    if (old_mm) {
        sync_mm_rss(old_mm);
        down_read(&old_mm->mmap_sem);
        mmget(mm);
    } else {
        mmgrab(mm);
    }

    task_lock(tsk);
    active_mm = tsk->active_mm;
    tsk->mm = mm;
    tsk->active_mm = mm;
    activate_mm(active_mm, mm);
    tsk->mm->vmacache_seqnum = 0;
    vmacache_flush(tsk);
    task_unlock(tsk);

    /* simply mmput/mmdrop will cause the initial mm of this task
     * vanish.. hmmm.. Not sure if need to keep it.
     * */
    if (old_mm) {
        up_read(&old_mm->mmap_sem);
        BUG_ON(active_mm != old_mm);
        setmax_mm_hiwater_rss(&tsk->signal->maxrss, old_mm);
        mm_update_next_owner(old_mm);
        mmput(old_mm);
        return 0;
    }
    
    mmdrop(active_mm);
    return 0;
}

SYSCALL_DEFINE1(as_destroy, unsigned int, fd)
{
    struct mm_struct *mm;
    struct task_struct *task;

    task = current;
    mm = get_mm_from_fd(fd);
    if (IS_ERR(mm)) {
        return PTR_ERR(mm);
    }

    __close_fd(current->files, fd);

    return 0;
}

static int as_release(struct inode *inode, struct file *file)
{
    struct mm_struct *mm = file->private_data;

    mmput(mm);
    return 0;
}
