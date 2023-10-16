bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h #generate bpf info for host linux(in c-style)
clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c hash_test.bpf.c -o hash_test.bpf.o #compile to bpf bytecode
bpftool gen skeleton hash_test.bpf.o > hash_test.skel.h #generate "skeleton" header for current project
clang -g -O2 -Wall -I . -c hash_test.c -o hash_test.o #compile loader
clang -Wall -O2 -g hash_test.o /usr/lib/libbpf.a -lelf -lz -o hash_test #link loader with libbpf.a
sudo ./hash_test #execute loader to load bpf program
