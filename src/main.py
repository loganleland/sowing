import argparse
import binaryninja
import sys
from analysis.sign.main import signAnalysis


if __name__ == '__main__':
  description = """Sowing: a suite of tools dedicated to the analysis of the
                 intermediate languages of binary ninja."""
  parser = argparse.ArgumentParser(description=description)
  parser.add_argument("-file", nargs="+",
                      help="Binary ninja database or binary for analysis",
                      type=str, required=True)
  parser.add_argument("-entry", nargs=1,
                      help="Entry symbol for analysis",
                      type=str, required=True)
  parser.add_argument("-sign", action='store_true', help="Execute signedness analysis")
  parser.add_argument("-out", nargs=1, help="Location of annotated bndb",
                       required=True)

  args = parser.parse_args()
  bv = binaryninja.load(args.file[0])
  if bv is None:
    print("[*] Failed to load bndb or binary")
    sys.exit(-1)

  print("[*] Locating: " + args.entry[0])
  syms = bv.get_functions_by_name(args.entry[0])
  print(f"  [+] Found {len(syms)} possible entry symbols")
  if len(syms) == 0:
    print("  [+] No entry symbol detected")
    sys.exit(-1)
  if len(syms) != 1:
    print("  [+] Not unique")
    sys.exit(-1)
  print(syms[0])
  entry = syms[0]

  if args.sign is not None:
    print("[*] Executing sign analysis")
    signAnalysis(bv, entry)

  bv.create_database(args.out[0])
  bv.file.close()