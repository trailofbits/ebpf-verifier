import argparse

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("-a", help="paths to files to include")
  parser.add_argument("-S","--emit_ir", help="emit llvm IR instead of bitcode", action="store_true")
  args = parser.parse_args()

  if (args.emit_ir):
    f = open("compile_to_llvm_if.sh")
  else:
    f = open("compile_to_llvm_bitcode.sh")

  commands = f.readlines()

  include_headers = open("included_headers.txt")
  headers = include_headers.readlines()
  bitcode_files = open("bitcode_files.txt")

  res_cmds = []

  for line in bitcode_files.readlines():
    for cmd in commands:
      if line.strip() in cmd:
        c = cmd.strip()
        for h in headers:
          c += " -include ../" + h
        res_cmds.append(c)

  res = open("build_bitcode_needed.sh", "w")
  for line in res_cmds:
    res.write(line)

  res.close()

if __name__ == "__main__":
    main()
