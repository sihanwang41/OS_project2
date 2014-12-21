/*  linux/kernel/prinfo.c
 *
 *  Process tree system call
 *
 */

#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/prinfo.h>
#include <linux/slab.h>

#include <asm/uaccess.h>

/**
 * copy_task_info - copies info for a given task struct into a provided prinfo struct
 */
void copy_task_info(struct prinfo *info, struct task_struct *task)
{
	info->parent_pid = task_tgid_vnr(task->real_parent);
	info->pid = task_tgid_vnr(task);
	info->state = task->state;
	info->uid = task->cred->uid;
	get_task_comm(info->comm, task);

	if (!list_empty(&task->children))
		info->first_child_pid = task_tgid_vnr(list_entry(
						task->children.prev,
						struct task_struct,
						sibling));
	else
		info->first_child_pid = 0;

	if (task->sibling.prev != &task->parent->children)
		info->next_sibling_pid = task_tgid_vnr(list_entry(
						task->sibling.prev,
						struct task_struct,
						sibling));
	else
		info->next_sibling_pid = 0;
}

/**
 * sys_ptree - fills a user provider buffer with prinfo structs in a DFS
 * traversal of the process tree
 */
SYSCALL_DEFINE2(ptree, struct prinfo __user *, buf, int *, nr)
{
	struct task_struct *task;
	struct prinfo *kbuf;
	int i = 0;		/* Total number of processes */
	int c = 0;		/* Total number copied */
	int n = 0;		/* Size of buffer */

	if (nr == NULL)
		return -EINVAL;

	if (buf == NULL)
		return -EINVAL;

	if (copy_from_user(&n, nr, sizeof(int)))
		return -EFAULT;

	if (n < 1)
		return -EINVAL;

	kbuf = kcalloc(n, sizeof(struct prinfo), GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	read_lock(&tasklist_lock);
	task = &init_task;

	do {
		if (c < n)
			copy_task_info(kbuf + c++, task);

		if (!list_empty(&task->children)) {
			task = list_first_entry(&task->children,
						struct task_struct,
						sibling);
		} else {
			while (task->parent != task &&
					list_is_last(&task->sibling,
					&task->parent->children))
				task = task->parent;

			task = list_entry(task->sibling.next,
					struct task_struct,
					sibling);
		}

		i++;
	} while (task != &init_task);

	read_unlock(&tasklist_lock);

	if (copy_to_user(nr, &c, sizeof(int))) {
		kfree(kbuf);
		return -EFAULT;
	}

	if (copy_to_user(buf, kbuf, n * sizeof(struct prinfo))) {
		kfree(kbuf);
		return -EFAULT;
	}

	kfree(kbuf);

	return i;
}
