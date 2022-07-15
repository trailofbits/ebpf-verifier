# Overview

The eBPF Verifier Harness project seeks to isolate the eBPF verifier from the
Linux kernel in order to allow efficient checks that an eBPF program will run
on various kernel versions and configurations. It will also allow for detecting
discrepencies in the eBPF verifier between different kernel versions.

## Important files:

* runtime.c contains stubbed out/reimplemented functions that verifier.c or a
dependency requires.

* main.c runs the actual harness.

* .h files include additional stubbed out functions/macros.

# General Workflow

Matches current implementation, not full harness yet.

## Get the compile commands:

1.  **compile the kernel with clang**
2.  from inside kernel source root dir **run
the scripts/clang-tools/gen_compile_commands.py**
3.  put the compile_commands.json file in backup/
4.  make compile_cmds to generate compile_cmds.sh

## Actually get the bitcode:

1. make bitcode to generate .bc files

## Build harness:

1. make harness
