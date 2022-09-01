EBPF = $(HOME)/ebpf-verifier

BIN = $(EBPF)/bin
SRC = $(EBPF)/src
SAMPLES = $(EBPF)/samples

# build libbpf hooked into harness
REGLIBBPF := $(EBPF)/libbpf/build_reg/libbpf.a
LIBBPF := $(EBPF)/libbpf/build/libbpf.a
LIBBPFSRC := $(EBPF)/libbpf/
KARCHIVE := $(EBPF)/linux/kernel.a
<<<<<<< .merge_file_DhbFPL
KARCHIVE18 := $(EBPF)/linux/kernel_5_18.a
=======
>>>>>>> .merge_file_7VHDmR
KERNEL := $(EBPF)/linux/src

# TODO: currently using my vmlinux.h generated from my /sys/kernel/btf/vmlinux
VMLINUX := $(EBPF)/linux/vmlinux.h

INCLUDES := -I$(LIBBPFSRC)/root/usr/include -I$(LIBBPFSRC)/root_reg/usr/include -iquote$(KERNEL)/../

CC := clang
CFLAGS := -g -O2 -fdebug-default-version=4

APPS := s \
				hello \
				bootstrap \
				stack_read \
				usdt \
				uprobe \
				sockfilter \
				profile \
				minimal_legacy \
<<<<<<< .merge_file_DhbFPL
				kprobe \
				fentry  \
				bounded_loop \
				infinite_loop
=======
				kprobe fentry
>>>>>>> .merge_file_7VHDmR

LOCALAPPS := 	local-s \
							local-hello \
							local-bootstrap \
							local-stack_read \
							local-usdt \
							local-uprobe \
							local-sockfilter \
							local-profile \
							local-minimal_legacy \
							local-kprobe \
<<<<<<< .merge_file_DhbFPL
							local-fentry \
							local-bounded_loop \
							local-infinite_loop
=======
							local-fentry
>>>>>>> .merge_file_7VHDmR

HARNESS_SRC_FILES := 	$(SRC)/my_syscall.c \
											$(SRC)/runtime.c \
											$(SRC)/init.c \
											$(SRC)/fd.c \
											$(SRC)/current.c \
											$(SRC)/ptr_store.c \
											$(SRC)/memory.c

ARCH := arm64

# generate bpf bytecode
$(SAMPLES)/%.bpf.o: $(SAMPLES)/%.bpf.c $(VMLINUX)
	$(CC) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
	-I $(KERNEL)/usr/include \
	-c $< -o $@

# generate libbpf skel.h TODO: change bpftool to kernel spec. one
$(SAMPLES)/%.skel.h: $(SAMPLES)/%.bpf.o
	echo $@
<<<<<<< .merge_file_DhbFPL
	bpftool gen skeleton $< > $@ --debug
=======
	bpftool gen skeleton $< > $@
>>>>>>> .merge_file_7VHDmR

$(SAMPLES)/%_loader.o: $(SAMPLES)/%.skel.h
	echo $<
	$(CC) $(CFLAGS) $(INCLUDES) \
	-c -o $@ $(SAMPLES)/$*_loader.c

<<<<<<< .merge_file_DhbFPL
# TODO: automated way to add kernel version macro. Right now manually modify
# the below variable
KVERSION := -D__v5_2__

#generate bpf loader executable (will call into my_syscall)
$(APPS): % : $(SAMPLES)/%_loader.o $(SAMPLES)/%.skel.h  $(SAMPLES)/%.bpf.o $(LIBBPF) $(KARCHIVE)
	$(CC) $(CFLAGS) \
	-I $(KERNEL)/usr/include/ \
	-iquote $(EBPF)/linux/include \
	-DHARNESS \
	$<  \
	$(KVERSION) \
=======
# generate bpf loader executable (will call into my_syscall)
$(APPS): % : $(SAMPLES)/%_loader.o $(SAMPLES)/%.skel.h  $(SAMPLES)/%.bpf.o $(LIBBPF) $(KARCHIVE)
	$(CC) $(CFLAGS) \
	-DHARNESS \
	$<  \
>>>>>>> .merge_file_7VHDmR
	$(HARNESS_SRC_FILES) \
	$(LIBBPF) -lelf -lz \
	$(KARCHIVE) \
	-o $(BIN)/$@ \
	-mcmodel=large

<<<<<<< .merge_file_DhbFPL
hello_18: %_18 : $(SAMPLES)/%_loader.o $(SAMPLES)/%.skel.h  $(SAMPLES)/%.bpf.o $(LIBBPF) $(KARCHIVE18)
		$(CC) $(CFLAGS) \
	-DHARNESS \
	$<  \
	-D__v5_18__ \
	$(HARNESS_SRC_FILES) \
	$(LIBBPF) -lelf -lz \
	$(KARCHIVE18) \
	-o $(BIN)/$@ \
	-mcmodel=large

# $(APPS): % : $(SAMPLES)/%_loader.o $(SAMPLES)/%.skel.h  $(SAMPLES)/%.bpf.o $(LIBBPF) $(KARCHIVE)
# 	$(CC) $(CFLAGS) \
# 	-I $(KERNEL)/usr/include/ \
# 	-iquote $(EBPF)/linux/include \
# 	-DHARNESS \
# 	$<  \
# 	$(KVERSION) \
# 	$(HARNESS_SRC_FILES) \
# 	$(KARCHIVE) \
# 	-o $(BIN)/$@ \
# 	-mcmodel=large

=======
>>>>>>> .merge_file_7VHDmR
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
