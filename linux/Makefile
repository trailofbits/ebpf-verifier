KFILES=kernel_src_files.txt

# TODO: automate/systematize which kernel source files are used for each version.
# this was a first attempt at keeping track of which object files a kernel
# would actually be able to build from the list. It is not a good system.
FFILES=found_src_files.txt

# TODO: automate switching between these: (in general automate all config stuff)
# related to kernel version.
# for v5.2: 	./scripts/gen_compile_commands.py
# for v5.18: 	./scripts/clang-tools/gen_compile_commands.py
GEN_COMPILE_COMMANDS := 	./scripts/clang-tools/gen_compile_commands.py

# harness directory
EBPF = $(HOME)/ebpf-verifier
# kernel src directory (git submodule)
CURR = $(EBPF)/linux
KERNEL = $(CURR)/src


# TODO: generalize to also allow gcc or to just allow making choices
# to the kernel make stuff

# NOTE: the kernel must have a valid .config file (with the desired BPF options)
# enabled. should also run make prepare and make headers_install for kernels
# that support that target.

# this runs the default kernel build system for the needed files.
# this is important because otherwise the gen_compile_cmds.py script
# cannot run. These files are not used in the actual kernel.a.
kernel_object_files:
	-cd $(KERNEL) && \
	make LLVM=1 $(shell cat $(CURR)/kernel_src_files.txt) -k

# generate the default kernel compile commands.
$(KERNEL)/compile_commands.json: kernel_object_files
	cd $(KERNEL) && \
	$(GEN_COMPILE_COMMANDS)

# generate clang_cmds.sh. Look at the clang_cmds.py script for more deets.
clang_cmds.sh: $(KERNEL) $(KFILES) $(KERNEL)/compile_commands.json
	cd $(KERNEL) && \
	python3 $(CURR)/scripts/clang_cmds.py \
	-K $(CURR)/kernel_src_files.txt \
	-O $(CURR)/clang_cmds.sh \
	-F $(CURR)/found_src_files.txt
	chmod +x clang_cmds.sh

# run the customized compile commands to get the kernel static object files
objs_%: clang_cmds.sh $(KERNEL)
	cd $(KERNEL) && \
	$(CURR)/$<

# link them all together...
kernel.o: $(KERNEL) objs_%
	cd $(KERNEL) && \
	ld.lld -r -o $(CURR)/$@ \
	$(shell cat $(CURR)/$(FFILES))

# archive them
kernel.a: kernel.o
	llvm-ar rcs $@ $<


# TODO: call the appropriate kernel cleaning commands as well or add another
# target to do that. (It is annoying to have the .o files stick around)
clean:
	rm -f kernel.a
	rm -f kernel.o
	rm -f clang_cmds.sh
