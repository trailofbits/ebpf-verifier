KVERSION = 5.18.8

EBPF = $(HOME)/ebpf-verifier
SRC = $(EBPF)/src

# generate clang_cmds.sh
clang_cmds:
	cd $(EBPF) && \
	make clang_cmds_$(KVERSION)

# run clang_cmds.sh
bitcode:
	cd $(EBPF) && \
	make bitcode_$(KVERSION)


# build harness
harness: $(KERNEL) runtime.c $(SRC)/test.h $(SRC)/main.c
	cd $(EBPF) && \
	make harness_$(KVERSION)

# just bitcode and harness (existing clang cmds)
test:
	make bitcode
	-rm -f harness
	make harness

all:
	make clang_cmds
	make bitcode
	-rm -f harness
	make harness

clean:
	rm -f harness
	rm -f clang_cmds.sh
