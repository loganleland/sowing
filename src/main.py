import argparse
import binaryninja
import sys
from analysis.domains.sign.main import signAnalysis


#==================================================================
# getEntry
#==================================================================
# Given a binaryview and function name as string return the unique
# function otherwise return none if not found or not unique.
#==================================================================
def getEntry(bv: binaryninja.binaryview.BinaryView, entryStr: str) -> binaryninja.function.Function:
  print("[*] Locating: " + args.entry[0])
  syms = bv.get_functions_by_name(args.entry[0])
  print(f"  [+] Found {len(syms)} possible entry symbols")
  if len(syms) == 0:
    print("  [+] No entry symbol detected")
    return None
  if len(syms) != 1:
    print("  [+] Not unique symbol name, provide address (not supported yet)")
    return None
  entry = syms[0]
  print(f"Entry: {entry}")
  return entry


if __name__ == '__main__':
  description = """Sowing: a suite of tools dedicated to the analysis of the
                 intermediate languages within binary ninja."""
  parser = argparse.ArgumentParser(description=description)
  parser.add_argument("-file", nargs="+",
                      help="Binary ninja database or binary for analysis",
                      type=str, required=True)
  parser.add_argument("-entry", nargs=1,
                      help="Entry symbol for analysis",
                      type=str, required=True)
  parser.add_argument("-out", nargs=1, help="Location of annotated bndb",
                       required=True)

  args = parser.parse_args()
  bv = binaryninja.load(args.file[0], options={'analysis.signatureMatcher.autorun': True})
  if bv is None:
    print(f"[*] Failed to load {args.file[0]}")
    sys.exit(-1)

  print("[*] Detected external libraries: ")
  list(map(lambda l: print(f"  [+] {l}"), bv.get_external_libraries()))

  entry = getEntry(bv, args.entry[0])

  # Sign Analysis
  bv.create_tag_type("Sign Analysis", "+")
  bv.create_tag_type("Fixup", "🔨")
  print("[*] Executing sign analysis")
  signAnalysis(bv, entry)

  bv.create_database(args.out[0])
  bv.file.close()
