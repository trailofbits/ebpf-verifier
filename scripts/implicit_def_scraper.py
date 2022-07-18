raw = open("raw.txt")
lines = raw.readlines()

funcs = []
key = "implicit declaration of function '"

for line in lines:
  if key not in line:
    continue
  start = line.find(key) + len(key)
  end = line.find("'", start)
  func = line[start:end]
  funcs.append(func)

funcs = list(dict.fromkeys(funcs)) # get rid of duplicates
funcs.sort()

for f in funcs:
  print("extern void " + f + "(void); // TODO --> fix params + return")

for f in funcs:
  print("void " + f + "(void) { abort(); } // TODO --> autogened")
