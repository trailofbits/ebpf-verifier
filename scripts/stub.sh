#! /bin/bash

FILES="/home/parallels/clang_compiled/linux-5.18.8/arch/arm64/include/asm/*"
DEST="/home/parallels/ebpf-verifier/asm_stubs/"
SINGLE="/home/parallels/ebpf-verifier/asm_stubs.h"

for f in $FILES
do
  echo "Processing $f"
  base_name=$(basename $f)
  touch $DEST${base_name}
  xpref=${base_name%.*}
  echo \#define __ASM_${xpref^^}_H | tr .- _ > $DEST${base_name}
  echo \#define __ASM_${xpref^^}_H | tr .- _ >> $SINGLE
done
