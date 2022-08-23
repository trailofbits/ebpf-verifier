EBPF = $(HOME)/ebpf-verifier

BIN = $(EBPF)/bin
SRC = $(EBPF)/src
SAMPLES = $(EBPF)/samples

# build libbpf hooked into harness
REGLIBBPF := $(EBPF)/libbpf/build_reg/libbpf.a
LIBBPF := $(EBPF)/libbpf/build/libbpf.a
LIBBPFSRC := $(EBPF)/libbpf/
KARCHIVE := $(EBPF)/linux/kernel.a
KERNEL := $(EBPF)/linux/src

# TODO: currently using my vmlinux.h generated from my /sys/kernel/btf/vmlinux
VMLINUX := $(EBPF)/linux/vmlinux.h

INCLUDES := -I$(LIBBPFSRC)/root/usr/include -I$(LIBBPFSRC)/root_reg/usr/include -iquote$(KERNEL)/../

CC := clang
CFLAGS := -g -O2 -fdebug-default-version=4

APPS := s

#ARCH???
# generate bpf bytecode
$(BIN)/%.bpf.o: $(SAMPLES)/%.bpf.c $(VMLINUX)
	$(CC) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
	-c $< -o $@

# generate libbpf skel.h TODO: change bpftool to kernel spec. one
$(SAMPLES)/%.skel.h: $(BIN)/%.bpf.o
	bpftool gen skeleton $< > $@

HARNESS_SRC_FILES := 	$(SRC)/my_syscall.c \
											$(SRC)/runtime.c \
											$(SRC)/init.c \
											$(SRC)/fd.c \
											$(SRC)/current.c \
											$(SRC)/ptr_store.c \
											$(SRC)/memory.c

# generate bpf loader executable (will call into my_syscall)
$(APPS): % : $(LIBBPF) $(SAMPLES)/%.skel.h $(BIN)/%.bpf.o $(KARCHIVE)
	$(CC) $(CFLAGS) $(INCLUDES) \
	-DHARNESS \
	-iquote. \
	$(HARNESS_SRC_FILES) \
	$(LIBBPF) -lelf -lz \
	$(KARCHIVE) \
	-o $(BIN)/$@ \
	-mcmodel=large

# generate bpf loader executable using standard libbpf (will make actual syscalls)
local-$(APPS): local-% : $(REGLIBBPF) $(SRC)/%.skel.h
	$(CC) $(CLAGS) $(INCLUDES) \
	-UHARNESS \
	-iquote./src \
	init.c \
	$(REGLIBBPF) -lelf -lz -o $(BIN)/$@

clean:
	rm -f bin/*
	rm -f src/*.skel.h
	rm -f src/*.o
