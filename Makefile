KERNEL_VERSIONS = 5.18.8 5.15.51 5.15

BC_FILE=bitcode_files.txt

KERNEL = $(HOME)/clang_compiled/linux-
EBPF = $(HOME)/ebpf-verifier

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


# build harness
harness_%: $(KERNEL)% %/clang_cmds.sh %/bitcode_files.txt
	cd $< && \
	clang \
	-I $(KERNEL)$*/usr/include/ \
	$(shell cat $*/$(BC_FILE)) \
	-include $(EBPF)/runtime.h \
	$(EBPF)/$*/runtime.c \
	$(EBPF)/main.c \
	-mcmodel=large \
	-g -O0 -v \
	-fdebug-default-version=4 \
	-o $(EBPF)/$*/harness


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
