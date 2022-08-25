# called from inside root of kernel source tree
# expects compile_commands.json to be there already
# [-B path/to/files.txt] needs a list of bitcode_files.txt --> which commands it cares about
# [-H path/to/headers.txt] needs a list of included_headers.txt --> which headers to include in compile commands

import argparse
import sys
import json
from os import listdir
from os.path import isfile, join

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-S","--emit_ir", help="emit llvm IR instead of bitcode", action="store_true")
  parser.add_argument("-B", "--emit_bc", help="emit llvm bitcode instead of machine code", action="store_true")
  parser.add_argument("-K","--kernel_files", help="file with list of kernel src files needed", action="store", dest="kernel_src_files")
  parser.add_argument("-H","--included_headers", help="file with list of headers needed when making bitcode files", action="store", dest="included_headers")
  parser.add_argument("-O","--output_file", help="where to write compile commands", action="store", dest="output_file")
  parser.add_argument("-F", "--found_src_files", help="write the kernel files commands found for", action="store", dest="found_src_file")

  args = parser.parse_args()

  print(args.output_file)
  output_filef = open(args.output_file, 'w+')

  found_files = open(args.found_src_file, 'w')

  path_to_compile_commands = "compile_commands.json"
  print("Using: ", path_to_compile_commands)

  include_header_file = open(args.included_headers)
  headers = include_header_file.readlines()

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

      include_prefix = " -include /home/parallels/ebpf-verifier/linux/header_stubs/"

      for header in headers:
        files = header.split()
        h = files[0].strip()
        if h == "SKIP":
          break
        if output_file in files[1:]:
          new_cmd += include_prefix + h
        elif len(files) > 1 and files[1] == "*":
          new_cmd += include_prefix + h

      # change O2 to O0
      new_cmd = new_cmd.replace("O2", "Og")

      # remove unwanted compile flags
      new_cmd = new_cmd.replace("-fno-PIE", "")
      new_cmd = new_cmd.replace("-Wno-frame-address", "")
      new_cmd = new_cmd.replace("-Wframe-larger-than=2048", "")
      new_cmd = new_cmd.replace("-fstack-protector-strong", "")

      new_cmd += " -g "
      #new_cmd += " -v "
      #TODO: compiler diff : gcc-5 doesn't recognize fdebug-default-version
      # new_cmd += " -fdebug-default-version=4 " # otherwise valgrind doesn't understand
      libbpf = True
      if output_file == "kernel/bpf/btf.o" and libbpf:
        print("modifing btf.o for libbpf. change script if running old harness.")
        new_cmd += " -Dbtf_parse_vmlinux=btf_parse_vmlinux_og "
        # new_cmd += " -Danon_inode_getfd=my_getfd "
      if output_file == "kernel/bpf/verifier.o" and libbpf:
        new_cmd += " -Dbtf_parse_vmlinux=btf__load_vmlinux_btf "
        # new_cmd += " -Danon_inode_getfd=my_getfd "
        # new_cmd += " -Dfdget=my_fdget "
      #   # new_cmd += " -Dfdput=my_fdput "
      # if output_file == "kernel/bpf/syscall.o":
      #   new_cmd += " -Dthis_cpu_inc=my_this_cpu_inc "
      #   new_cmd += " -Dthis_cpu_dec=my_this_cpu_dec "
        # new_cmd += " -Danon_inode_getfd=my_getfd "
      if output_file == "kernel/bpf/core.o":
        new_cmd += " -Dbpf_prog_select_runtime=bpf_prog_select_runtime_og "
        new_cmd += " -Dbpf_prog_kallsyms_add=bpf_prog_kallsyms_add_og "

      new_cmd += new_suffix
      new_cmd += " -mcmodel=large "

      final_commands.append(new_cmd)
      output_filef.write(new_cmd)
      output_filef.write("\n")
      found_files.write(output_file)
      found_files.write("\n")
      print("wrote to found file")

  output_filef.close()
  found_files.close()

  print("Sucessfully found", len(final_commands), " commands out of ", len(kfs))

if __name__ == "__main__":
    main()
