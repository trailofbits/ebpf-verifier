BC_FILES = 	kernel/bpf/btf.bc \
						kernel/bpf/tnum.bc \
						kernel/bpf/disasm.bc \
						kernel/bpf/core.bc \
						kernel/bpf/helpers.bc \
						kernel/bpf/verifier.bc \
						kernel/bpf/syscall.bc \
						lib/string.bc \
						lib/sha1.bc \
						net/core/filter.bc \
						lib/sort.bc

HOME = /home/parallels
KERNEL = $(HOME)/clang_compiled/linux-5.18.8
CURR = $(HOME)/ebpf-verifier/5.18.8
MAIN = $(HOME)/ebpf-verifier/main.c

# generate clang_cmds.sh
clang_cmds: $(KERNEL) bitcode_files.txt included_headers.txt
	cd $< && \
	python3 ../../ebpf-verifier/scripts/clang_cmds.py \
	-B $(CURR)/bitcode_files.txt \
	-H $(CURR)/included_headers.txt \
	-O $(CURR)/clang_cmds.sh
	chmod +x clang_cmds.sh

# run clang_cmds.sh
bitcode: $(KERNEL) clang_cmds.sh
	cd $< && \
	$(CURR)/clang_cmds.sh

# build harness
harness: $(KERNEL) clang_cmds.sh
	cd $< && \
	clang \
	-I $(KERNEL)/usr/include/ \
	$(BC_FILES) \
	-include $(CURR)/../runtime.h \
	$(CURR)/runtime.c \
	$(MAIN) \
	-mcmodel=large \
	-g -O0 -v \
	-fdebug-default-version=4 \
	-o $(CURR)/harness

# just bitcode and harness (existing clang cmds)
test:
	make bitcode
	make harness

all:
	make clang_cmds
	make bitcode
	make harness


clean:
	rm -f harness
	rm -f clang_cmds.sh
