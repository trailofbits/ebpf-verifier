raw = open("error_output_raw.txt")
lines = raw.readlines()

func_decls = open("func_decls.txt", "w")
func_names = open("func_names.txt", "w")

funcs = []

for line in lines:
  if " in function to " in line:
    continue
  if "undefined reference to" not in line:
    continue
  start = line.find('`')
  end = line.find('\'')
  func = line[start+1:end]
  funcs.append(func)

funcs = list(dict.fromkeys(funcs)) # get rid of duplicates
funcs.sort()

for f in funcs:
  print(f)
  func_decls.write("void " + f + "(void) { abort(); } // TODO --> autogened\n")
  func_names.write(f + "\n")
