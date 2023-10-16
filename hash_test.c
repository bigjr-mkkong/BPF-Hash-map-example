#include "stdio.h"
#include "fcntl.h"
#include "unistd.h"
#include "bpf/libbpf.h"
#include "bpf/bpf.h"
#include <sys/resource.h>

#include "hash_test.skel.h"
#include "shared_def.h"

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args){
    return vfprintf(stderr, format, args);
}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open("/sys/kernel/debug/tracing/trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int main(void){
	struct hash_test_bpf *hash_test_obj;
    int hash_map_fd;
    int err = 0;

    libbpf_set_print(libbpf_print_fn);

    bump_memlock_rlimit();

	/* Load and verify BPF application */
	hash_test_obj = hash_test_bpf__open_and_load();
	if (!hash_test_obj) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint */
	err = hash_test_bpf__attach(hash_test_obj);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		return 0;
	}


    printf("Program attached\n");

	int lookup_key = LOOKUP_KEY;
	struct value_t value;

	hash_map_fd = bpf_object__find_map_fd_by_name(hash_test_obj->obj, "my_hashmap");
    /* fetch the file descriptor of hashmap we defined in bpf program*/

	while(bpf_map_lookup_elem(hash_map_fd, &lookup_key, &value) != 0);

	printf("smp_id: %d, pid: %d, comm: %s\n", value.smp_id, value.pid, value.comm);
	/* immediatly print out and exit once we have something appear in the entry bounded by LOOKUP_KEY*/
    return EXIT_SUCCESS;

}
