#TODO add more comments
#TODO add support for gcc vs. clang

import argparse
import sys
import json
from os import listdir
from os.path import isfile, join

def get_file_macro(output_file):
  macro = ""
  words = output_file.strip().split('/')
  for w in words:
    macro += w.upper()
    macro += "_"
  return macro[:-3]


def main():
  # TODO: cleanup these options
  parser = argparse.ArgumentParser()
  parser.add_argument("-S","--emit_ir", help="emit llvm IR instead of bitcode", action="store_true")
  parser.add_argument("-B", "--emit_bc", help="emit llvm bitcode instead of machine code", action="store_true")
  parser.add_argument("-K","--kernel_files", help="file with list of kernel src files needed", action="store", dest="kernel_src_files")
  parser.add_argument("-O","--output_file", help="where to write compile commands", action="store", dest="output_file")
  parser.add_argument("-F", "--found_src_files", help="write the kernel files commands found for", action="store", dest="found_src_file")

  args = parser.parse_args()

  print(args.output_file)
  output_filef = open(args.output_file, 'w+')

  found_files = open(args.found_src_file, 'w')

  path_to_compile_commands = "compile_commands.json"
  print("Using: ", path_to_compile_commands)


  kf = open(args.kernel_src_files)
  kfs = kf.readlines()

  f = open(path_to_compile_commands)
  raw_commands = json.loads(f.read())
  final_commands = []

  for entry in raw_commands:
    cflag_index = entry["command"].find("-c ")
    prefix = entry["command"][0:cflag_index]
    suffix = entry["command"][cflag_index:]
    suff_list = suffix.split()
    # gives list of form ['-c', '-o', 'path/file.o', 'path/file.c']
    path = suff_list[2]

    # for llvm IR (-S)
    if (args.emit_ir):
      output_file = suff_list[2][:-1] + "ll"
      new_suffix = "-emit-llvm -S -o " + output_file + " " + suff_list[3]
    elif args.emit_bc:
      # for llvm bitcode (-c)
      output_file = suff_list[2][:-1] + "bc"
      new_suffix = "-emit-llvm -c -o " + output_file + " " + suff_list[3]
    else: # regular object files
      output_file = suff_list[2][:-1] + "o"
      new_suffix = "-c -o " + output_file + " " + suff_list[3] # this is redundant

    first_I = prefix.find("-I")
    new_cmd = prefix[0:first_I]
    # new_cmd = new_cmd.replace("gcc", "clang")

    if output_file + "\n" in kfs:
      new_cmd += prefix[first_I:]
      kernel_macro = " -D__v5_18__ "
      file_macro = get_file_macro(output_file)
      print(file_macro)
      new_cmd += " -D" + file_macro
      new_cmd += " -iquote /home/parallels/ebpf-verifier/linux/header_stubs "
      new_cmd +=  " -include /home/parallels/ebpf-verifier/linux/header_stubs/header_stubs.h "
      new_cmd += kernel_macro

      # change O2 to O0
      new_cmd = new_cmd.replace("O2", "Og")

      # remove unwanted compile flags
      new_cmd = new_cmd.replace("-fno-PIE", "")
      new_cmd = new_cmd.replace("-Wno-frame-address", "")
      new_cmd = new_cmd.replace("-Wframe-larger-than=2048", "")
      new_cmd = new_cmd.replace("-fstack-protector-strong", "")

      # from the v5.2 commands (could be diff in other kernel versions)
      new_cmd = new_cmd.replace("-mstack-protector-guard=sysreg -mstack-protector-guard-reg=sp_el0 -mstack-protector-guard-offset=1128 ", "")
      new_cmd = new_cmd.replace("-mstack-protector-guard=sysreg -mstack-protector-guard-reg=sp_el0 -mstack-protector-guard-offset=1184", "")

      if new_cmd.find("stack-protector") != -1:
        print("CHECK THAT STACK PROTECTOR IS NOT ENABLED!!!!!")

      new_cmd += " -g "
      #TODO: compiler diff : gcc-5 doesn't recognize fdebug-default-version
      if new_cmd.startswith("clang"):
        new_cmd += " -fdebug-default-version=4 " # otherwise valgrind doesn't understand
        new_cmd += " -mcmodel=large "
      libbpf = True
      if output_file == "kernel/bpf/btf.o" and libbpf:
        print("modifing btf.o for libbpf. change script if running old harness.")
        new_cmd += " -Dbtf_parse_vmlinux=btf_parse_vmlinux_og "
      if output_file == "kernel/bpf/verifier.o" and libbpf:
        new_cmd += " -Dbtf_parse_vmlinux=btf__load_vmlinux_btf "
      if output_file == "kernel/bpf/core.o":
        new_cmd += " -Dbpf_prog_select_runtime=bpf_prog_select_runtime_og "
        new_cmd += " -Dbpf_prog_kallsyms_add=bpf_prog_kallsyms_add_og "

      new_cmd += new_suffix


      final_commands.append(new_cmd)
      output_filef.write(new_cmd)
      output_filef.write("\n")
      found_files.write(output_file)
      found_files.write("\n")

  output_filef.close()
  found_files.close()

  print("Sucessfully found", len(final_commands), " commands out of ", len(kfs))

if __name__ == "__main__":
    main()
