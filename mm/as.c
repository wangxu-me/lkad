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


#define DEBUG
// static long mm_nr = 0;

static int as_release(struct inode *inode, struct file *file);
#ifdef DEBUG
static void dump_pt_regs(struct pt_regs *reg);
#endif
static long do_as_switch_mm(unsigned int fd);
static long do_as_copy(unsigned int oldfd, int cow);

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

/* 0 to get mm struct currently in use.
 * 1 to create a new empty mm struct.
 * */
SYSCALL_DEFINE1(as_create, int, create)
{
    int fd;
    struct mm_struct *mm;

    if (create) {
        mm = mm_alloc();
        if (!mm) {
            return -ENOMEM;
        }
    } else {
        mm = current->mm;
        if (!mm) {
            return -EINVAL;
        }
        mmget(mm);
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

/* oldfd == -1, copy current mm
 * oldfd != -1, copy mm from fd
 * cow: indicate if cow
 * */
static long do_as_copy(unsigned int oldfd, int cow)
{
    int fd, ret __attribute__((__unused__));
    struct mm_struct *mm, *oldmm;
    struct task_struct *task;

    task = current;

    if (oldfd == -1) {
        if (cow) {
            mm = dup_mm(task);
        } else {
            mm = dup_mm_nocow(task);
        }
    } else {
        oldmm = get_mm_from_fd(oldfd);

        if (IS_ERR(oldmm)) {
            return PTR_ERR(oldmm);
        }

        if (cow) {
            mm = dup_mm2(task, oldmm);
        } else {
            mm = dup_mm_nocow2(task, oldmm);
        }
    }

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

#if 0
#ifdef DEBUG
    ret = do_as_switch_mm(fd);
    if (ret) {
        __close_fd(current->files, fd);
        return ret;
    }
#endif
#endif

    return fd;
}

/* copy mm struct from current mm struct.
 * used for test code. Or might be usefull..
 * However, this is COW. Therfore, If we switch to
 * this mm later, it results in weird execution path
 * and segv..
 * */
SYSCALL_DEFINE2(as_copy, unsigned int, oldfd, int, cow)
{
    return do_as_copy(oldfd, cow);
}

SYSCALL_DEFINE0(as_dup)
{
    return do_as_copy(-1, 1);
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

static long do_as_switch_mm(unsigned int fd)
{
    struct mm_struct *mm, *old_mm, *active_mm;
    struct task_struct *tsk = current;
    struct pt_regs *old, *new;
    mm_segment_t oldfs;
    unsigned long oldfs2, oldgs;
    unsigned int fsindex, gsindex;

//#undef SET_REGS
#define SET_REGS
#ifdef SET_REGS
    oldfs = get_fs();
    rdmsrl(MSR_FS_BASE, oldfs2);
    rdmsrl(MSR_KERNEL_GS_BASE, oldgs);
    savesegment(fs, fsindex);
    savesegment(gs, gsindex);
#endif
#if defined(DEBUG) && defined(SET_REGS)
    printk(KERN_INFO "oldfs[%lx], fsbase[%lx], gsbase[%lx]\n", oldfs.seg,
            oldfs2, oldgs);
    printk(KERN_INFO "fsindex[%x], gsindex[%x]\n", fsindex, gsindex);
#endif
    mm = get_mm_from_fd(fd);
    if (IS_ERR(mm)) {
        return PTR_ERR(mm);
    }

    old_mm = tsk->mm;

    if (mm == old_mm || mm == tsk->active_mm) {
        return 0;
    }

#ifdef DEBUG
    /* check pt_regs before and after switch mm.
     * looks like the return address is messed up.. 
     * */
    old = task_pt_regs(current);
    dump_pt_regs(old);
#endif

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
#ifdef DEBUG
    new = task_pt_regs(current);
    dump_pt_regs(new);
#endif
    if (old_mm) {
        up_read(&old_mm->mmap_sem);
        BUG_ON(active_mm != old_mm);
        setmax_mm_hiwater_rss(&tsk->signal->maxrss, old_mm);
        mm_update_next_owner(old_mm);
        mmput(old_mm);
        goto out;
    }
    
    mmdrop(active_mm);

out:
#ifdef SET_REGS
    /* Not sure why we need this..
     * lldt will not affect fs and gs..
     * maybe loadsegment(fs, 0) and load_gs_index(0) in
     * deactivate_mm() affects this? I don't know, just need
     * to set these to work. 
     * */
    set_fs(oldfs);
//    set_fs(USER_DS);
    loadsegment(fs, fsindex);
    wrmsrl(MSR_FS_BASE, oldfs2);
    load_gs_index(gsindex);
    wrmsrl(MSR_KERNEL_GS_BASE, oldgs);
#endif
    return 0;
}

SYSCALL_DEFINE1(as_switch_mm, unsigned int, fd)
{
    return do_as_switch_mm(fd);
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

#ifdef DEBUG
static void dump_pt_regs(struct pt_regs *reg)
{
    int i __attribute__((__unused__)) = 0;
    char *c __attribute__((__unused__)), ch __attribute__((__unused__));
    printk(KERN_INFO "r15[%lx], r14[%lx], r13[%lx], r12[%lx]\n",
            reg->r15, reg->r14, reg->r13, reg->r12);
    printk(KERN_INFO "bp[%lx], bx[%lx], r11[%lx], r10[%lx]\n",
            reg->bp, reg->bx, reg->r11, reg->r10);
    printk(KERN_INFO "r9[%lx], r8[%lx], ax[%lx], cx[%lx]\n",
            reg->r9, reg->r8, reg->ax, reg->cx);
    printk(KERN_INFO "dx[%lx], si[%lx], di[%lx], orig_ax[%lx]\n",
            reg->dx, reg->si, reg->di, reg->orig_ax);
    printk(KERN_INFO "ip[%lx], cs[%lx], flags[%lx], sp[%lx]\n",
            reg->ip, reg->cs, reg->flags, reg->sp);
    printk(KERN_INFO "ss[%lx]\n", reg->ss);

    printk(KERN_INFO "thread fsindex[%x], thread gsindex[%x], "
                     "thread fsbase[%lx], thread gsbase[%lx]\n", 
                     current->thread.fsindex, current->thread.gsindex,
                     current->thread.fsbase, current->thread.gsbase);
#if 0
    printk(KERN_INFO "dump instructions:\n");
    c = (char *)reg->ip;
    for (i = 0; i < 50; i++, c++) {
        if (get_user(ch, c)) {
            printk(KERN_INFO "bug ");
            continue;
        }
        printk(KERN_INFO "%02x ", ch);
        if (i % 10 == 9) {
            printk(KERN_INFO "\n");
        }
    }
#endif
    return;
}
#endif
