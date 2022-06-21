def main():
  file = open("verifier_deps.txt")
  raw = open("raw_verifier_deps.txt", "w")
  text = file.read()
  tokens = text.split()
  res = []
  for t in tokens:
    t.strip()
    if t != "\\" and t != "":
      res.append(t)
  res = res[2:]
  res.sort()
  for f in res:
    raw.write(f)
    raw.write('\n')
  file.close()
  raw.close()
  return 0

if __name__ == "__main__":
    main()
