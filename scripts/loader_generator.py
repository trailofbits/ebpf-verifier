#!/usr/bin/python3

from argparse import ArgumentParser

#TODO: There is a 16 character limit on the appname that is not yet enforced.

def main():
  template_path = "../src/loader_template.c"
  parser = ArgumentParser()
  parser.add_argument("-n", "--name", dest="appname", help="name of app to generate loader for")

  args = parser.parse_args()

  print("generating loader for: ", args.appname)
  dest_path = "../samples/" + args.appname + "_loader.c"
  dest = open(dest_path, "w")

  template = open(template_path)
  raw_template = template.read()


  dest.write(raw_template.replace("**APP**", args.appname))

  print("created: ", dest_path)

  dest.close()
  template.close()


if __name__ == "__main__":
  main()
