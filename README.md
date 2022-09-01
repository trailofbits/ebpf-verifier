# Overview

The eBPF Verifier Harness project seeks to isolate the eBPF verifier from the
Linux kernel in order to allow efficient checks that an eBPF program will run
on various kernel versions and configurations. It will also allow for detecting
discrepencies in the eBPF verifier between different kernel versions.

## Architecture:

1. linux/src: git submodule of linux src
2. libbpf/src: git submodule of libbpf mirror src
3. samples: sample bpf programs
4. src: harness runtime files
5. scripts: miscellaneous scripts used to generate function declarations and such

# Build System:

This project uses cmake to an extent, but also heavily relies on Makefiles.
In the future the build system should definitely be streamlined by someone that
understands cmake.

Here are some of the more useful build commands, but they are not comprehensive.

Use the following cmake command to change the linux source version:
```cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DBPFVERIFIER_LINUX_VERSION="v5.2" ```
```cmake --build build --target linux_submodule_updater```

After updating kernel source version make

To build kernel object:
```cmake --build build --target kernel```

To build libbpf object:
```cmake --build build --target libbpf```

To build harness for a sample/hello.bpf.c:
```make hello```
