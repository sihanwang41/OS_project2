#include "errno.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "sys/syscall.h"
#include "unistd.h"

struct prinfo {
	pid_t parent_pid;
	pid_t pid;
	pid_t first_child_pid;
	pid_t next_sibling_pid;
	long state;
	long uid;
	char comm[64];
};

void init_indents(int *pids, int *indents, int nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		pids[i] = -1;
		indents[i] = -1;
	}
}

int get_indent(int *pids, int *indents, int nr, int pid)
{
	int i;

	for (i = 0; i < nr; i++) {
		if (pids[i] == pid)
			return indents[i];
	}

	return 0;
}

void set_indent(int *pids, int *indents, int nr, int pid, int indent)
{
	int i = 0;

	while (pids[i] != -1 && i < nr)
		i++;

	pids[i] = pid;
	indents[i] = indent;
}

int main(int argc, char **argv)
{
	struct prinfo *buf;
	int nr = 500;
	int i;
	int j;
	int indent;
	int *pids;
	int *indents;

	buf = (struct prinfo *) malloc(sizeof(struct prinfo) * nr);
	pids = (int *) malloc(sizeof(int) * nr);
	indents = (int *) malloc(sizeof(int) * nr);

	init_indents(pids, indents, nr);

	if (syscall(223, buf, &nr) < 0) {
		printf("error: %s\n", strerror(errno));
	} else {
		for (i = 0; i < nr; i++) {
			indent = get_indent(pids, indents, nr,
						buf[i].parent_pid);

			for (j = 0; j < indent; j++)
				printf("\t");

			printf("%s,%d,%ld,%d,%d,%d,%ld\n",
				buf[i].comm,
				buf[i].pid,
				buf[i].state,
				buf[i].parent_pid,
				buf[i].first_child_pid,
				buf[i].next_sibling_pid,
				buf[i].uid);

			if (buf[i].first_child_pid != 0)
				set_indent(pids, indents, nr,
						buf[i].pid, indent + 1);
		}
	}

	free(buf);
	free(pids);
	free(indents);

	return 0;
}
