#ifndef __SHARED_DEF_H__
#define __SHARED_DEF_H__

#ifndef __VMLINUX_H__
    #include "stdint.h"
#endif

#define u64 uint64_t
#define u32 uint32_t

struct value_t{
    u64 time_stamp;
    u32 smp_id;
    /* smp_id stand for which processor will a task been executed*/
    u32 pid;
    char comm[32];
};
#define LOOKUP_KEY  416

#endif
