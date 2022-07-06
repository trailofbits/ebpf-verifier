# called from inside root of kernel source tree
# expects compile_commands.json to be there already
# [-B path/to/files.txt] needs a list of bitcode_files.txt --> which commands it cares about
# [-H path/to/headers.txt] needs a list of included_headers.txt --> which headers to include in compile commands

import argparse
import sys
import json

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
    # print("hey")
    cflag_index = entry["command"].find("-c ")
    prefix = entry["command"][0:cflag_index]
    suffix = entry["command"][cflag_index:]
    suff_list = suffix.split()
    # print(suff_list)
    # gives list of form ['-c', '-o', 'path/file.o', 'path/file.c']
    path = suff_list[2]

    # for llvm IR (-S)
    if (args.emit_ir):
      output_file = suff_list[2][:-1] + "S"
      new_suffix = "-emit-llvm -S -o " + output_file + " " + suff_list[3]
    else:
      # for llvm bitcode (-c)
      output_file = suff_list[2][:-1] + "bc"
      new_suffix = "-emit-llvm -c -o " + output_file + " " + suff_list[3]

    new_cmd = prefix + new_suffix

    if output_file + "\n" in bfs:
      for h in headers:
        new_cmd += " -include ../../ebpf-verifier/" + h.strip() # + " -g -O0"
      #new_cmd += " -g -O0"
      new_cmd += " -g "
      final_commands.append(new_cmd)
      output_filef.write(new_cmd)
      output_filef.write("\n")
      # print(new_cmd, '/n')

  output_filef.close()

  print("Sucessfully found", len(final_commands), " commands out of ", len(bfs))







  # if (args.emit_ir):
  #   f = open("/tmp/compile_to_llvm_ir.sh")
  # else:
  #   f = open("/tmp/compile_to_llvm_bitcode.sh")

  # commands = f.readlines()

  # include_headers = open("included_headers.txt")
  # headers = include_headers.readlines()
  # bitcode_files = open("bitcode_files.txt")

  # res_cmds = []

  # for line in bitcode_files.readlines():
  #   for cmd in commands:
  #     if line.strip() in cmd:
  #       c = cmd.strip()
  #       for h in headers:
  #         c += " -include ../" + h.strip() # + " -g -O0"
  #       res_cmds.append(c)

  # res = open("build_bitcode_needed.sh", "w")
  # for line in res_cmds:
  #   res.write(line)
  #   res.write('\n')

  # res.close()

if __name__ == "__main__":
    main()
