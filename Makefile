EBPF = $(HOME)/ebpf-verifier

BIN = $(EBPF)/bin
SRC = $(EBPF)/src

# build libbpf hooked into harness
LIBBPF := $(EBPF)/libbpf/src/src/build/libbpf.a
LIBBPFSRC := $(EBPF)/libbpf/src/src
# REGLIBBPF := reg_libbpf.a
KARCHIVE := $(EBPF)/linux/kernel.a

KERNEL := $(EBPF)/linux/src

# TODO: currently using my vmlinux.h generated from my /sys/kernel/btf/vmlinux
VMLINUX := $(EBPF)/linux/src/vmlinux.h

# INCLUDES := -I$(KERNEL)/tools/lib/ -I$(KERNEL)/usr/include/ -iquote$(KERNEL)
INCLUDES := -I$(LIBBPFSRC)/root/usr/include -iquote$(KERNEL)..
CC := clang
CFLAGS := -g -O2 -fdebug-default-version=4

APPS := sample

#ARCH???
# generate bpf bytecode
$(BIN)/%.bpf.o: $(SRC)/%.bpf.c $(LIBBPF) $(VMLINUX)
	$(CC) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
	-c $< -o $@

# generate libbpf skel.h TODO: change bpftool to kernel spec. one
$(SRC)/%.skel.h: $(BIN)/%.bpf.o
	bpftool gen skeleton $< > $@

# generate bpf loader executable (will call into my_syscall)
$(APPS): % : $(SRC)/%.c $(LIBBPF) $(SRC)/%.skel.h $(KARCHIVE)
	$(CC) $(CFLAGS) $(INCLUDES) \
	$(SRC)/my_syscall.c \
	$(SRC)/$@.c \
	runtime.c \
	$(LIBBPF) -lelf -lz \
	$(KARCHIVE) \
	-o $(BIN)/$@ \
	-mcmodel=large

# generate bpf loader executable using standard libbpf (will make actual syscalls)
# $(APPS)-reg: %-reg : $(SRC)/%.c $(REGLIBBPF) $(SRC)/%.skel.h $(BIN)/%.bpf.o
# 	$(CC) $(CFLAGS) $(INCLUDES) $(SRC)/$*.c \
# 	$(REGLIBBPF) -lelf -lz -o $(BIN)/$@
