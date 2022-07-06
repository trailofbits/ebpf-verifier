KERNEL_VERSIONS = 5.18.8 5.15.51 5.15
BC_FILES_5.18.8 = kernel/bpf/btf.bc \
									kernel/bpf/tnum.bc \
									kernel/bpf/disasm.bc \
									kernel/bpf/core.bc \
									kernel/bpf/helpers.bc \
									kernel/bpf/verifier.bc

PATH_TO_KERNEL = /home/parallels/clang_compiled/linux-


# make the bitcode for all of the kernel versions
# bitcode: backup/ $(filter $(KERNEL_VERSIONS), $(wildcard *))
bitcode: backup/ $(KERNEL_VERSIONS)

# cd into linux source dir and call build_bitcode_needed.sh
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

clang_cmds_%: ../clang_compiled/linux-%/ clang_cmds_%.sh
	cd $< && \
	../../ebpf-verifier/clang_cmds_$*.sh


# currently only works for kernel version 18
# TODO: automate getting the bitcode files into the command
simple-harness-%: ../clang_compiled/linux-%/ clang_cmds_%.sh
	cd $< && \
	pwd && \
	clang \
	-I $(PATH_TO_KERNEL)$*/usr/include/ \
	$(BC_FILES_5.18.8) \
	../../ebpf-verifier/runtime_simple_$*.c \
	../../ebpf-verifier/main_simple_$*.c \
	-mcmodel=large \
	-g -O0 -v \
	-o ../../ebpf-verifier/harness_simple_$*

# currently only works for kernel version 18
# TODO: automate getting the bitcode files into the command
harness-%: ../clang_compiled/linux-%/ clang_cmds_%.sh
	cd $< && \
	pwd && \
	clang \
	-I $(PATH_TO_KERNEL)$*/usr/include/ \
	$(BC_FILES_5.18.8) \
	../../ebpf-verifier/runtime_$*.c \
	../../ebpf-verifier/main_$*.c \
	-mcmodel=large \
	-g -O0 -v \
	-o ../../ebpf-verifier/harness_$*


clean:
	rm -f harness*
	rm -f clang_cmds*
