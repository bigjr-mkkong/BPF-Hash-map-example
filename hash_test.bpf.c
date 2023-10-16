#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "shared_def.h"
/* This header share some common type definition across bpf program and user-side header */

struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, struct value_t);
} my_hashmap SEC(".maps");
/* This structure defined a data type called BPF_MAP_TYPE_HASH serve as amedium to share 
 * data between kernel-side bpf program and user-side bpf loader program*/

SEC("tracepoint/syscalls/sys_enter_execve")

int bpf_prog(void *ctx){
    struct value_t  new_info;
    struct value_t *exist_info;

    u32 lookup_key = LOOKUP_KEY;
    /* Here is the lookup key for our shared variable, and you can inspect the actual value in shared_def.h*/

    u64 nanosec = bpf_ktime_get_ns();
    u32 pid = (u32)bpf_get_current_pid_tgid();
    u32 current_smp_id = bpf_get_smp_processor_id();
    /* Above 3 lines fetched some kernel information*/

    exist_info = bpf_map_lookup_elem(&my_hashmap, &lookup_key);
    /*This line check whether the entry bounded with LOOKUP_KEY is available in hash_map, you can read
     * the document of bpf_map_lookup_elem() to have fully understand on the program*/

    if(!exist_info){//there's no element on given lookup_key
        new_info.time_stamp = nanosec;
        new_info.smp_id = current_smp_id;
        new_info.pid = pid;
        bpf_get_current_comm( new_info.comm, 32);
        
        bpf_map_update_elem(&my_hashmap, &lookup_key, & new_info, BPF_ANY);
        //create a new kv pare on given lookup_key
    }else{
        exist_info->time_stamp = nanosec;
        exist_info->smp_id = current_smp_id;
        exist_info->pid = pid;
        bpf_get_current_comm(exist_info->comm, 32);
        //directly update value field on hashmap
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
