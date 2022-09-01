kernel_src_files = open("../linux/kernel_src_files.txt")
lines = kernel_src_files.readlines()

for line in lines:
  words = line.split('/')
  print("#ifdef ", end='' )
  print(words[0].upper(), end='')
  for word in words[1:]:
    print("_", end='')
    if word.endswith(".o\n"):
      print(word[:-3].upper(), end='')
    else:
      print(word.upper(), end='')
  print("\n#endif /* " + line[:-3] + " */\n")
