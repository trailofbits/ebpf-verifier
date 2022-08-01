KERNEL_VERSIONS = 5.18.8 5.15.51 5.15

BC_FILE=bitcode_files.txt

KERNEL = $(HOME)/clang_compiled/linux-
EBPF = $(HOME)/ebpf-verifier
BIN = $(EBPF)/bin
SRC = $(EBPF)/src

# generate clang_cmds.sh
clang_cmds_%: $(KERNEL)% %/bitcode_files.txt %/included_headers.txt
	cd $< && \
	python3 $(EBPF)/scripts/clang_cmds.py \
	-B $(EBPF)/$*/bitcode_files.txt \
	-H $(EBPF)/$*/included_headers.txt \
	-O $(EBPF)/$*/clang_cmds.sh
	chmod +x $*/clang_cmds.sh

# run clang_cmds.sh
bitcode_%: $(KERNEL)% %/clang_cmds.sh
	cd $< && \
	$(EBPF)/$*/clang_cmds.sh

# build libbpf hooked into harness
LIBBPF := libbpf.a
REGLIBBPF := reg_libbpf.a
VMLINUX := vmlinux.h
INCLUDES := -I$(KERNEL)5.18.8/tools/lib/ -I$(KERNEL)5.18.8/usr/include/ -iquote.
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

# generate bpf loader executable
$(APPS): % : $(SRC)/%.c $(LIBBPF) $(SRC)/%.skel.h $(BIN)/%.bpf.o
	$(CC) $(CFLAGS) $(INCLUDES) \
	-include $(SRC)/test.h \
	$(KERNEL)5.18.8/kernel/bpf/sysfs_btf.bc \
	$(KERNEL)5.18.8/kernel/bpf/btf.bc \
	$(KERNEL)5.18.8/kernel/bpf/tnum.bc  \
	$(KERNEL)5.18.8/kernel/bpf/disasm.bc \
	$(KERNEL)5.18.8/kernel/bpf/core.bc \
	$(KERNEL)5.18.8/kernel/bpf/helpers.bc \
	$(KERNEL)5.18.8/kernel/bpf/verifier.bc \
	$(KERNEL)5.18.8/kernel/bpf/syscall.bc \
	$(KERNEL)5.18.8/kernel/ksysfs.bc \
	$(KERNEL)5.18.8/lib/string.bc \
	$(KERNEL)5.18.8/lib/sha1.bc \
	$(KERNEL)5.18.8/net/core/filter.bc \
	$(KERNEL)5.18.8/lib/sort.bc \
	$(SRC)/test.c 5.18.8/runtime.c \
	$(SRC)/my_syscall.c \
	$(SRC)/$@.c \
	$(LIBBPF) -lelf -lz \
	-o $(BIN)/$@ \
	-mcmodel=large

$(APPS)-reg: %-reg : $(SRC)/%.c $(REGLIBBPF) $(SRC)/%.skel.h $(BIN)/%.bpf.o
	$(CC) $(CFLAGS) $(INCLUDES) $(SRC)/$*.c \
	$(REGLIBBPF) -lelf -lz -o $(BIN)/$@

# build harness
harness_%: $(KERNEL)% %/clang_cmds.sh %/bitcode_files.txt
	cd $< && \
	clang \
	-I $(KERNEL)$*/usr/include/ \
	$(shell cat $*/$(BC_FILE)) \
	-include $(SRC)/test.h \
	$(SRC)/test.c \
	$(EBPF)/$*/runtime.c \
	$(SRC)/main.c \
	-mcmodel=large \
	-g -O0 -v \
	-fdebug-default-version=4 \
	-o $(EBPF)/$*/harness

link_errors_%:
	-rm $(EBPF)/link_errors/error_output_raw.txt
	touch $(EBPF)/link_errors/error_output_raw.txt
	-make harness_$* 2> $(EBPF)/link_errors/error_output_raw.txt
	cd $(EBPF)/link_errors && \
	pwd && \
	python3 scripts/get_info.py
	cat link_errors/func_decls.txt

implicit_defs_%:
	touch $(EBPF)/scripts/raw.txt
	-make bitcode_$* 2> $(EBPF)/scripts/raw.txt
	cd $(EBPF)/scripts && \
	python3 implicit_def_scraper.py
	rm $(EBPF)/scripts/raw.txt


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
	rm $(BIN)/*
