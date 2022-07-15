KVERSION = 5.15.51

EBPF = $(HOME)/ebpf-verifier

# generate clang_cmds.sh
clang_cmds:
	cd $(EBPF) && \
	make clang_cmds_$(KVERSION)

# run clang_cmds.sh
bitcode:
	cd $(EBPF) && \
	make bitcode_$(KVERSION)


# build harness
harness: $(KERNEL)
	cd $(EBPF) && \
	make harness_$(KVERSION)

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
