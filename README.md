# BPF Hash map example

An simple BPF program uses BPF_MAP_TYPE_HASH to send a piece of data from kernel-side bpf program to user-side loader program.

## Pre-requisites:
- make sure your Linux distros support BPF system call
- libbpf and bpftool
  
## How to use
To make things easy and simple, this project uses bash script to compile instead of Makefile, you just need to execute

```
sudo ./make.sh
```

On command line, and after the message "program attached" appear at the last line of terminal, open second terminal. Then you will see a single line of message printed at the end of the first terminal window. This message should contains `smp_id`, `pid`, and `comm` fields.

You can try to modify the program(by using other data structure or do some fancy stuff) on the hash_map to let program keep receiving the message from the kernel until we kill it.