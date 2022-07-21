# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# loosely based on bpf-bootstrap makefile.
EBPF := /home/parallels/ebpf-verifier
CURR := $(EBPF)/sample/src
KERNEL := $(HOME)/clang_compiled/linux-5.15
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
LIBBPF_SRC := $(KERNEL)/tools/lib/bpf/
LIBBPF_OBJ := $(LIBBPF_SRC)/libbpf.a
BPFTOOL := /usr/local/bin/bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/')
VMLINUX := $(KERNEL)/vmlinux.h

INCLUDES := -I $(LIBBPF_SRC).. -I $(KERNEL)/usr/include/ -I $(dir $(VMLINUX))
CFLAGS := -g -Wall
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

APPS = minimal

.PHONY: all
all: $(APPS)

.PHONY: clean
clean:
	$(call msg,CLEAN)
	-rm $(APPS)
	-rm *.o
	-rm *.skel.h

# Build BPF code
%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info


# Generate BPF skeletons
%.skel.h: %.bpf.o | $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,%.o,$(APPS)): %.o: %.skel.h

%.o: %.c $(wildcard %.h)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@


# Build application binary
$(APPS): %: %.o $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# delete failed targets
.DELETE_ON_ERROR:
