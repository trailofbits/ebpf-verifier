EBPF = $(HOME)/ebpf-verifier

BIN = $(EBPF)/bin
SRC = $(EBPF)/src

# build libbpf hooked into harness
REGLIBBPF := $(EBPF)/libbpf/src/src/build_reg/libbpf.a
LIBBPF := $(EBPF)/libbpf/src/src/build/libbpf.a
LIBBPFSRC := $(EBPF)/libbpf/src/src
# REGLIBBPF := reg_libbpf.a
KARCHIVE := $(EBPF)/linux/kernel.a

KERNEL := $(EBPF)/linux/src

# TODO: currently using my vmlinux.h generated from my /sys/kernel/btf/vmlinux
VMLINUX := $(EBPF)/linux/vmlinux.h

# INCLUDES := -I$(KERNEL)/tools/lib/ -I$(KERNEL)/usr/include/ -iquote$(KERNEL)
INCLUDES := -I$(LIBBPFSRC)/root/usr/include -I$(LIBBPFSRC)/root_reg/usr/include -iquote$(KERNEL)/../
CC := clang
CFLAGS := -g -O2 -fdebug-default-version=4

APPS := s

#ARCH???
# generate bpf bytecode
$(BIN)/%.bpf.o: $(SRC)/%.bpf.c $(VMLINUX)
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
	-c $< -o $@

# generate libbpf skel.h TODO: change bpftool to kernel spec. one
$(SRC)/%.skel.h: $(BIN)/%.bpf.o
	bpftool gen skeleton $< > $@


$(SRC)/%.o:
	$(CC) $(CFLAGS) $(INCLUDES) \
	-Dmain=real_main -c $(SRC)/$*.c -o $@


# generate bpf loader executable (will call into my_syscall)
$(APPS): % : $(SRC)/%.c $(LIBBPF) $(SRC)/%.skel.h $(KARCHIVE) $(SRC)/%.o
	$(CC) $(CFLAGS) $(INCLUDES) \
	$(SRC)/my_syscall.c \
	$(SRC)/$@.o \
	runtime.c \
	init.c \
	fd.c \
	$(LIBBPF) -lelf -lz \
	$(KARCHIVE) \
	-o $(BIN)/$@ \
	-mcmodel=large

# generate bpf loader executable using standard libbpf (will make actual syscalls)
local-$(APPS): local-% : $(SRC)/%.c $(REGLIBBPF) $(SRC)/%.skel.h $(SRC)/%.o
	$(CC) $(CLAGS) $(INCLUDES) $(SRC)/$*.o \
	init.c \
	$(REGLIBBPF) -lelf -lz -o $(BIN)/$@

clean:
	rm -f bin/*
	rm -f src/*.skel.h
	rm -f src/*.o
