KERNEL_VERSIONS = 5.18.8 5.15.51 5.15
BC_FILES_5.18.8 = kernel/bpf/btf.bc \
									kernel/bpf/tnum.bc \
									kernel/bpf/disasm.bc \
									kernel/bpf/core.bc \
									kernel/bpf/helpers.bc \
									kernel/bpf/verifier.bc \
									kernel/bpf/syscall.bc \
									lib/string.bc \
									lib/sha1.bc

PATH_TO_KERNEL = /home/parallels/clang_compiled/linux-

# make the bitcode for all of the kernel versions
# bitcode: backup/ $(filter $(KERNEL_VERSIONS), $(wildcard *))
bitcode: backup/ $(KERNEL_VERSIONS)


# generates clang_cmds_<version>.sh
$(KERNEL_VERSIONS): %: ../clang_compiled/linux-%/ bitcode_files_%.txt included_headers_%.txt
	cd $< && \
	pwd && \
	python3 ../../ebpf-verifier/scripts/clang_cmds.py \
	-B ../../ebpf-verifier/bitcode_files_$@.txt \
	-H ../../ebpf-verifier/included_headers_$@.txt \
	-O ../../ebpf-verifier/clang_cmds_$@.sh
	chmod +x clang_cmds_$@.sh
	cd $< && \
	../../ebpf-verifier/clang_cmds_$@.sh

# rebuilds the bitcode files from the existing clang_cmds.sh
clang_cmds_%: ../clang_compiled/linux-%/ clang_cmds_%.sh
	cd $< && \
	../../ebpf-verifier/clang_cmds_$*.sh

# currently only works for kernel version 18
# TODO: automate getting the bitcode files into the command
simple-harness-%: ../clang_compiled/linux-%/ clang_cmds_%.sh
	cd $< && \
	pwd && \
	clang \
	-I ../../ebpf-verifier/ \
	-I $(PATH_TO_KERNEL)$*/usr/include/ \
	$(BC_FILES_5.18.8) \
	../../ebpf-verifier/runtime_simple_$*.c \
	../../ebpf-verifier/main_simple_$*.c \
	-mcmodel=large \
	-g -O0 -v \
	-fdebug-default-version=4 \
	-o ../../ebpf-verifier/harness_simple_$*


# compiles both runtime.c and main.c together with all the other bc files
runmain-%: ../clang_compiled/linux-%/ clang_cmds_%.sh
	cd $< && \
	pwd && \
	clang \
	-I $(PATH_TO_KERNEL)$*/usr/include/ \
	$(BC_FILES_5.18.8) \
	../../ebpf-verifier/runtime_$*.c \
	../../ebpf-verifier/main_$*.c \
	-mcmodel=large \
	-g -O0 -v \
	-fdebug-default-version=4 \
	-o ../../ebpf-verifier/harness_$*

baby-test:
	clang \
	-I $(PATH_TO_KERNEL)5.18.8/usr/include/ \
	-nostdinc \
	sample.c \
	-v -g -O0 \
	-o sample

baby-test-2:
	clang \
	-I $(PATH_TO_KERNEL)5.18.8/usr/include/ \
	sample.c \
	-v -g -O0 \
	-o sample

test-%:
	make clang_cmds_$*
	make runmain-$*

test-fresh-%:
	make $*
	make runmain-$*

# compiles main.c with bc files and runtime.bc
# currently only works for kernel version 18
# TODO: automate getting the bitcode files into the command
harness-%: ../clang_compiled/linux-%/ clang_cmds_%.sh
	cd $< && \
	pwd && \
	clang \
	-I $(PATH_TO_KERNEL)$*/usr/include \
	$(BC_FILES_5.18.8) \
	/home/parallels/ebpf-verifier/runtime_5.18.8.bc \
	../../ebpf-verifier/main_$*.c \
	-mcmodel=large \
	-g -O0 -v \
	-fdebug-default-version=4  \
	-o ../../ebpf-verifier/harness_$*


# makes runtime.bc
runtime-%: ../clang_compiled/linux-%/ clang_cmds_%.sh
	cd $< && \
	pwd && \
	clang \
	../../ebpf-verifier/runtime_$*.c \
	-g -O0 -v \
	-c -emit-llvm \
	-fdebug-default-version=4 \
	-o ../../ebpf-verifier/runtime_$*.bc



clean:
	rm -f harness*
	rm -f clang_cmds*
