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

link_errors_%:
	rm $(EBPF)/link_errors/error_output_raw.txt
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
