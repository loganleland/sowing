import binaryninja
import importlib
from typing import Optional

# Dynamic import of sign module
signModule = importlib.import_module("analysis.sign.main")
signTag = "Sign Analysis"


#==================================================================
# detection
#==================================================================
# Execute all detections available for sign analysis
#==================================================================
def detection(bv: binaryninja.binaryview.BinaryView,
              expr: binaryninja.commonil.Call):
  detectionMem(bv, expr)
  detectionString(bv, expr)
  detectionCPPContainer(bv, expr) 


#==================================================================
# justSign
#==================================================================
# Given a binja call expr and desired argument index return the
# Sign of argument on inspection or None
#
# If desired argument is out of range add a fixup tag
#==================================================================
def justSign(bv: binaryninja.binaryview.BinaryView, expr: binaryninja.commonil.Call,
             paramIndex: int):
  if len(expr.params) < paramIndex+1:
    print(f"expr: {expr}, {len(expr.params)}, paramIndex: {paramIndex}")
    bv.add_tag(expr.address, "Fixup", f"Expected minimum {paramIndex} arguments")
    return None
  return signModule.getSign(expr.params[paramIndex])


#==================================================================
# prologue
#==================================================================
# Common prologue for detection functions
#==================================================================
def prologue(bv: binaryninja.binaryview.BinaryView,
             expr: binaryninja.commonil.Call):
  if isinstance(expr.dest, binaryninja.mediumlevelil.MediumLevelILVar):
    funcs = bv.get_functions_by_name(expr.dest.var.name)
    if funcs is None:
      return None
    if len(funcs) != 1:
      print(f"Multiple functions found by name: {expr.dest.var.name}")
      return None
    return funcs[0]
  elif isinstance(expr.dest, binaryninja.mediumlevelil.MediumLevelILConstPtr):
    func = bv.get_function_at(expr.dest.constant)
    if func is None:
      print(f"TODO: No ConstPtr function found at {expr.dest.constant}")
      return None
    return func
  elif isinstance(expr.dest, binaryninja.mediumlevelil.MediumLevelILImport):
    return None

 
#==================================================================
# detectionMem
#==================================================================
# Find and annotate memory errors
#==================================================================
def detectionMem(bv: binaryninja.binaryview.BinaryView,
              expr: binaryninja.commonil.Call):
  func = prologue(bv, expr)
  if func is None:
    return

  match func.name:
    case "malloc":
      signArg0 = justSign(bv, expr, 0)
      if signArg0 is None:
        return
      if signArg0 is signModule.Sign.neg or signArg0 is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"malloc(size := {signArg0})")
    case "calloc":
      signArg0 = justSign(bv, expr, 0)
      signArg1 = justSign(bv, expr, 1)
      if signArg0 is None or signArg1 is None:
        return
      if signArg0 is signModule.Sign.neg or signArg0 is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"calloc(num := {signArg0})")
      if signArg1 is signModule.Sign.neg or signArg1 is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"calloc(size := {signArg1})")
    case "aligned_alloc":
      signArg0 = justSign(bv, expr, 0)
      signArg1 = justSign(bv, expr, 1)
      if signArg0 is None or signArg1 is None:
        return
      if signArg0 is signModule.Sign.neg or signArg0 is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"aligned_alloc(alignment := {signArg0})")
      if signArg1 is signModule.Sign.neg or signArg1 is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"aligned_alloc(size := {signArg1})")
    case "realloc":
      signArg1 = justSign(bv, expr, 1)
      if signArg1 is None:
        return
      if signArg1 is signModule.Sign.neg or signArg1 is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"realloc(new_size := {signArg1})")
    case "free_sized":
      signArg1 = justSign(bv, expr, 1)
      if signArg1 is None:
        return
      if signArg1 is signModule.Sign.neg or signArg1 is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"free_sized(new_size := {signArg1})")
    case default:
      return


#==================================================================
# detectionString
#==================================================================
# Find and annotate common string function errors
#==================================================================
def detectionString(bv: binaryninja.binaryview.BinaryView,
                    expr: binaryninja.commonil.Call):
  func = prologue(bv, expr)
  if func is None:
    return

  match func.name:
    case "strncpy":
      sign = justSign(bv, expr, 2)
      if sign is None:
        return
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"strncpy(n := {sign})")
    case "strncat":
      sign = justSign(bv, expr, 2)
      if sign is None:
        return
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"strncat(n := {sign})")
    case "strncmp":
      sign = justSign(bv, expr, 2)
      if sign is None:
        return
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"strncmp(n := {sign})")
    case "wcsncmp":
      sign = justSign(bv, expr, 2)
      if sign is None:
        return
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"wcsncmp(count := {sign})")
    case default:
      return


#==================================================================
# detectionCPPContainer
#==================================================================
# Find and annotate common cpp container errors
#==================================================================
def detectionCPPContainer(bv: binaryninja.binaryview.BinaryView,
                          expr: binaryninja.commonil.Call):
  func = prologue(bv, expr)
  if func is None:
    return

  match func.name:
    case "_ZNSt6vectorIiSaIiEE6resizeEm":
      signArg1 = justSign(bv, expr, 1)
      if signArg1 is None:
        return
      if signArg1 is signModule.Sign.neg:
        bv.add_tag(expr.address, signTag, f"vector::resize(n := {signArg1})")
    case "_ZNSt6vectorIi6NAllocIiEE7reserveEm":
      signArg1 = justSign(bv, expr, 1)
      if signArg1 is None:
        return
      if signArg1 is signModule.Sign.neg or signArg1 is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"vector::reserve(n := {signArg1})")
    case "_ZNSt5dequeIiSaIiEE6resizeEm":
      signArg1 = justSign(bv, expr, 1)
      if signArg1 is None:
        return
      if signArg1 is signModule.Sign.neg or signArg1 is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"deque::resize(count := {signArg1})")
    case "_ZNSt12forward_listIiSaIiEE6resizeEm":
      signArg1 = justSign(bv, expr, 1)
      if signArg1 is None:
        return
      if signArg1 is signModule.Sign.neg or signArg1 is signModule.Sign.zero:
        bv.add_tag(expr.address, signTag, f"forward_list::resize(count := {signArg1})")
    case default:
      return
