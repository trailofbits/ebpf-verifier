KVERSION = 5.15.51

BC_FILE=bitcode_files.txt
BC_FILES=$(shell cat $(BC_FILE))

HOME = /home/parallels
KERNEL = $(HOME)/clang_compiled/linux-$(KVERSION)
CURR = $(HOME)/ebpf-verifier/$(KVERSION)
EBPF = $(HOME)/ebpf-verifier

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
harness: $(KERNEL) clang_cmds.sh bitcode_files.txt
	cd $< && \
	clang \
	-I $(KERNEL)/usr/include/ \
	$(BC_FILES) \
	-include $(EBPF)/runtime.h \
	$(CURR)/runtime.c \
	$(EBPF)/main.c \
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
