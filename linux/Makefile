KFILES=kernel_src_files.txt
HEADER_STUBS=included_headers.txt

# harness directory
EBPF = $(HOME)/ebpf-verifier

# kernel src directory (git submodule)
CURR = $(EBPF)/linux
KERNEL = $(CURR)/src

# BIN = $(EBPF)/$(KV)/bin
# SRC = $(EBPF)/src
# build libbpf hooked into harness
# LIBBPF := libbpf.a
# REGLIBBPF := reg_libbpf.a
# VMLINUX := vmlinux.h
INCLUDES := -I$(KERNEL)/tools/lib/ -I$(KERNEL)/usr/include/ -iquote.
CC := clang
CFLAGS := -g -O2 -fdebug-default-version=4

APPS := sample

kernel_object_files:
	cd $(KERNEL) && \
	make LLVM=1 $(shell cat $(CURR)/kernel_src_files.txt)

$(KERNEL)/compile_commands.json: kernel_object_files
	cd $(KERNEL) && \
	./scripts/clang-tools/gen_compile_commands.py \
	$(shell cat $(CURR)/kernel_src_files.txt)

# generate clang_cmds.sh
clang_cmds.sh: $(KERNEL) $(KFILES) $(HEADER_STUBS) $(KERNEL)/compile_commands.json
	cd $(KERNEL) && \
	python3 $(CURR)/scripts/clang_cmds.py \
	-K $(CURR)/kernel_src_files.txt \
	-H $(CURR)/included_headers.txt \
	-O $(CURR)/clang_cmds.sh
	chmod +x clang_cmds.sh

#ARCH???
# generate bpf bytecode
$(BIN)/%.bpf.o: $(SRC)/%.bpf.c $(LIBBPF) $(VMLINUX)
	$(CC) $(CFLAGS) -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) \
	-c $< -o $@

# generate libbpf skel.h TODO: change bpftool to kernel spec. one
$(SRC)/%.skel.h: $(BIN)/%.bpf.o
	bpftool gen skeleton $< > $@

objs_%: $(EBPF)/%/clang_cmds.sh $(KERNEL)
	cd $(KERNEL) && \
	$<

$(EBPF)/%/kernel.o: $(KERNEL) objs_%
	cd $< && \
	ld.lld -r -o $@ \
	$(shell cat $(EBPF)/$*/$(KFILES))

$(EBPF)/%/kernel.a: $(EBPF)/%/kernel.o
	llvm-ar rcs $@ $<

# generate bpf loader executable (will call into my_syscall)
$(APPS): % : $(SRC)/%.c $(LIBBPF) $(SRC)/%.skel.h $(EBPF)/$(KV)/kernel.a
	$(CC) $(CFLAGS) $(INCLUDES) \
	$(SRC)/my_syscall.c \
	$(SRC)/$@.c \
	$(KV)/runtime.c \
	$(LIBBPF) -lelf -lz \
	$(EBPF)/$(KV)/kernel.a \
	-o $(BIN)/$@ \
	-mcmodel=large

# generate bpf loader executable using standard libbpf (will make actual syscalls)
$(APPS)-reg: %-reg : $(SRC)/%.c $(REGLIBBPF) $(SRC)/%.skel.h $(BIN)/%.bpf.o
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC)/$*.c \
	$(REGLIBBPF) -lelf -lz -o $(BIN)/$@

build-all:
	for dir in $(KERNEL_VERSIONS) ; do \
		cd $$dir && make all ; \
		cd .. ; \
	done

clean-all:
	for dir in $(KERNEL_VERSIONS) ; do \
		cd $$dir && make clean ; \
		cd .. ; \
	done
