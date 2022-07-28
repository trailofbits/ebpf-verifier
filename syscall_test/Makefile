pound := \#

KERNEL := /home/parallels/clang_compiled/linux-5.18.8/
LIBBPF_SRC := $(KERNEL)tools/lib/bpf/
CC := clang
LINK := ld.lld

CFLAGS := -g -fdebug-default-version=4

test:
	$(CC) $(CFLAGS) -Dsyscall=my_syscall bpf.c -c -o bpf.o
	$(CC) $(CFLAGS) syscall.c -c -o syscall.o
	$(LINK) syscall.o bpf.o -relocatable -o temp.o
	$(CC) $(CFLAGS) temp.o main.c -o prog

EBPF := /home/parallels/ebpf-verifier/
SYSCALL_SRC := $(EBPF)integrate/
SAMPLE_SRC := $(EBPF)sample/src/

real_test: libbpfa sample

sample:
	cd $(SAMPLE_SRC) && \
	make trivial
	
	


BPF_COMPILE_COMMAND := clang -Wp,-MD,staticobjs/.bpf.o.d -Wp,-MT,staticobjs/bpf.o -g -O2 -std=gnu89 -Wbad-function-cast -Wdeclaration-after-statement -Wformat-security -Wformat-y2k -Winit-self -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Wno-system-headers -Wold-style-definition -Wpacked -Wredundant-decls -Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wundef -Wwrite-strings -Wformat -Wno-type-limits -Wshadow -Wno-switch-enum -Werror -Wall -include/home/parallels/ebpf-verifier/integrate/my_unistd.h -I. -I/home/parallels/clang_compiled/linux-5.18.8/tools/include -I/home/parallels/clang_compiled/linux-5.18.8/tools/include/uapi -I/home/parallels/clang_compiled/linux-5.18.8/usr/include -fvisibility=hidden -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -D"BUILD_STR(s)=$(pound)s" -Dsyscall=my_syscall -c -o staticobjs/bpf.o bpf.c

libbpfa: syscall
	cd $(LIBBPF_SRC) && \
	make clean && \
	make LLVM=1 libbpf.a && \
	rm libbpf.a staticobjs/libbpf-in.o staticobjs/bpf.o && \
	$(BPF_COMPILE_COMMAND) && \
	$(LINK) staticobjs/bpf.o $(SYSCALL_SRC)/syscall.o -relocatable -o staticobjs/bpf.o && \
	make LLVM=1 libbpf.a

syscall:
	cd $(SYSCALL_SRC) && \
	rm syscall.o && \
	$(CC) $(CFLAGS) syscall.c -c -o syscall.o
