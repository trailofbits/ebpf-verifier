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

APPS := s hello
LOCALAPPS := local-s local-hello

HARNESS_SRC_FILES := 	$(SRC)/my_syscall.c \
											$(SRC)/runtime.c \
											$(SRC)/init.c \
											$(SRC)/fd.c \
											$(SRC)/current.c \
											$(SRC)/ptr_store.c \
											$(SRC)/memory.c
#ARCH???
# generate bpf bytecode
$(SAMPLES)/%.bpf.o: $(SAMPLES)/%.bpf.c $(VMLINUX)
	$(CC) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
	-c $< -o $@

# generate libbpf skel.h TODO: change bpftool to kernel spec. one
$(SAMPLES)/%.skel.h: $(SAMPLES)/%.bpf.o
	echo $@
	bpftool gen skeleton $< > $@

$(SAMPLES)/%_loader.o: $(SAMPLES)/%.skel.h
	echo $<
	$(CC) $(CFLAGS) $(INCLUDES) \
	-c -o $@ $(SAMPLES)/$*_loader.c

# generate bpf loader executable (will call into my_syscall)
$(APPS): % : $(SAMPLES)/%_loader.o $(SAMPLES)/%.skel.h  $(SAMPLES)/%.bpf.o $(LIBBPF) $(KARCHIVE)
	$(CC) $(CFLAGS) \
	-DHARNESS \
	$<  \
	$(HARNESS_SRC_FILES) \
	$(LIBBPF) -lelf -lz \
	$(KARCHIVE) \
	-o $(BIN)/$@ \
	-mcmodel=large

# # generate bpf loader executable using standard libbpf (will make actual syscalls)
$(LOCALAPPS) : local-% : $(SAMPLES)/%_loader.o $(SAMPLES)/%.bpf.o $(REGLIBBPF)
	$(CC) $(CLAGS) \
	-UHARNESS \
	$< \
	$(SRC)/init.c \
	$(REGLIBBPF) -lelf -lz -o $(BIN)/$@

clean:
	rm -f bin/*
	rm -f samples/*.skel.h
	rm -f samples/*.o
