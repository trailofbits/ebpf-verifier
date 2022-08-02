KVERSION = 5.15.51

EBPF := $(HOME)/ebpf-verifier
CURR := $(EBPF)/$(KVERSION)
SRC := $(EBPF)/src

# generate clang_cmds.sh
clang_cmds.sh:
	cd $(EBPF) && \
	make clang_cmds_$(KVERSION)

# run clang_cmds.sh and generate kernel library
kernel.a: clang_cmds.sh
	cd $(EBPF) && \
	make $(CURR)/kernel.a

%:
	cd $(EBPF) && \
	make $@ KV=$(KVERSION)


clean:
	rm -f clang_cmds.sh
	rm -f kernel.a
	rm -f kernel.o

