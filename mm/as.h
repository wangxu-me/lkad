#ifndef ___AS__H
#define ___AS__H

#include <linux/types.h>
#include <linux/kernel.h>

extern struct file *get_empty_filp(void);
extern struct mm_struct *dup_mm_nocow(struct task_struct *task);
extern struct mm_struct *dup_mm(struct task_struct *task);
extern struct mm_struct *dup_mm_nocow2(struct task_struct *task,
                                        struct mm_struct *oldmm);
extern struct mm_struct *dup_mm2(struct task_struct *task,
                                struct mm_struct *oldmm);

struct mmap_info {
    unsigned long addr;
    unsigned long len;
    unsigned long prot;
    unsigned long flags;
    unsigned long fd;
    unsigned long offset;
};

#endif
