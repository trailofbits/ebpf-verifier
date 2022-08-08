KFILES=kernel_src_files.txt
HEADER_STUBS=included_headers.txt

# harness directory
EBPF = $(HOME)/ebpf-verifier
# kernel src directory (git submodule)
CURR = $(EBPF)/linux
KERNEL = $(CURR)/src

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

objs_%: clang_cmds.sh $(KERNEL)
	cd $(KERNEL) && \
	$(CURR)/$<

kernel.o: $(KERNEL) objs_%
	cd $(KERNEL) && \
	ld.lld -r -o $(CURR)/$@ \
	$(shell cat $(CURR)/$(KFILES))

kernel.a: kernel.o
	llvm-ar rcs $@ $<
