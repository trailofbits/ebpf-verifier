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
  parser.add_argument("-B","--bitcode_files", help="file with list of bitcode files needed", action="store", dest="bitcode_files")
  parser.add_argument("-H","--included_headers", help="file with list of headers needed when making bitcode files", action="store", dest="included_headers")
  parser.add_argument("-O","--output_file", help="where to write compile commands", action="store", dest="output_file")

  args = parser.parse_args()

  print(args.output_file)
  output_filef = open(args.output_file, 'w+')

  path_to_compile_commands = "compile_commands.json"
  print("Using: ", path_to_compile_commands)

  include_header_file = open(args.included_headers)
  headers = include_header_file.readlines()

  bf = open(args.bitcode_files)
  bfs = bf.readlines()

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
    else:
      # for llvm bitcode (-c)
      output_file = suff_list[2][:-1] + "bc"
      new_suffix = "-emit-llvm -c -o " + output_file + " " + suff_list[3]

    first_I = prefix.find("-I")
    new_cmd = prefix[0:first_I]


    if output_file + "\n" in bfs:
      # path = "../../ebpf-verifier/asm_stubs"
      # asm_stub_files = [f for f in listdir(path) if isfile(join(path, f))]
      # for f in asm_stub_files:
      #   new_cmd += " -include ../../ebpf-verifier/asm_stubs/" + f + " "



      for h in headers:
        new_cmd += " -include ../../ebpf-verifier/" + h.strip()

      new_cmd += prefix[first_I:]

      # change O2 to O0
      new_cmd = new_cmd.replace("O2", "O0")

      # remove unwanted compile flags
      new_cmd = new_cmd.replace("-fno-PIE", "")
      new_cmd = new_cmd.replace("-Wno-frame-address", "")
      new_cmd = new_cmd.replace("-Wframe-larger-than=2048", "")
      new_cmd = new_cmd.replace("-fstack-protector-strong", "")

      new_cmd += " -g "
      new_cmd += " -fdebug-default-version=4 " # otherwise valgrind doesn't understand
      new_cmd += new_suffix

      final_commands.append(new_cmd)
      output_filef.write(new_cmd)
      output_filef.write("\n")



  output_filef.close()

  print("Sucessfully found", len(final_commands), " commands out of ", len(bfs))

if __name__ == "__main__":
    main()
