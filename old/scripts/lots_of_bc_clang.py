import io

file = open("target_outputs.txt", "r")
lines = file.readlines()
res = "clang-12 "
for line in lines:
  res += line.rstrip('\n') + " "
res += "../runtime.c"
print(res)
