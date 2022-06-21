# gen_llvm_bitcode.py
# converts compile_commands.json to commands that generate llvm bitcode.
# compile_commands.json gives commands in form of:
# "clang blah blah blah -c -o <path>.o <path>.c"
# convert to commands of form:
# "clang blah blah blah -emit-llvm -S -o <path>.S <path>.c"

import json
import sys
import argparse


def main():
  # read in the json file from path given as argument
  # convert the json into a python list
  #path_to_compile_commands = input("Path to compile_commands.json: ")
  path_to_compile_commands = "linux-5.18.4/compile_commands.json"

  parser = argparse.ArgumentParser()
  parser.add_argument("-p", help="path to compile_commands.json")
  parser.add_argument("-S","--emit_ir", help="emit llvm IR instead of bitcode", action="store_true")
  args = parser.parse_args()

  path_to_compile_commands = args.p


  print("Using: ", path_to_compile_commands)
  f = open(path_to_compile_commands)
  if (args.emit_ir):
    script = open("compile_to_llvm_ir.sh", "w")
  else:
    script = open("compile_to_llvm_bitcode.sh", "w")
  res = json.loads(f.read())
  locations = []
  for entry in res:
    cflag_index = entry["command"].find("-c ")
    prefix = entry["command"][0:cflag_index]
    suffix = entry["command"][cflag_index:]
    suff_list = suffix.split()

    # for llvm IR (-S)
    if (args.emit_ir):
      output_file = suff_list[2][:-1] + "S"
      new_suffix = "-emit-llvm -S -o " + output_file + " " + suff_list[3]
    else:
      # for llvm bitcode (-c)
      output_file = suff_list[2][:-1] + "bc"
      new_suffix = "-emit-llvm -c -o " + output_file + " " + suff_list[3]

    locations.append(output_file)

    new_cmd = prefix + new_suffix
    script.write(new_cmd)
    script.write('\n')
    # print(new_cmd)
    # print()
  # print("Total num entries processed: ", len(res))
  locations.sort()
  for l in locations:
    print(l)
  script.close()
  return 0


if __name__ == "__main__":
    main()