import binaryninja
import importlib


# Dynamic import of sign module
signModule = importlib.import_module("analysis.sign.main")


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
# detectionMem
#==================================================================
# Find and annotate memory errors
#==================================================================
def detectionMem(bv: binaryninja.binaryview.BinaryView,
              expr: binaryninja.commonil.Call):
  if isinstance(expr.dest, binaryninja.mediumlevelil.MediumLevelILVar):
    funcs = bv.get_functions_by_name(expr.dest.var.name)
    if funcs is None:
      return
    if len(funcs) != 1:
      print(f"Multiple functions found by name: {expr.dest.var.name}")
      return
    func = funcs[0]
  elif isinstance(expr.dest, binaryninja.mediumlevelil.MediumLevelILConstPtr):
    func = bv.get_function_at(expr.dest.constant)
    if func is None:
      print(f"TODO: No ConstPtr function found at {expr.dest.constant}")
      return
  match func.name:
    case "malloc":
      sign = signModule.getSign(expr.params[0])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        bv.add_tag(expr.address, "Malloc", f"Malloc({sign})")
        print(f"Alarm: malloc with {sign} size input.")
    case "calloc":
      sign = signModule.getSign(expr.params[1])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        print(f"Alarm: calloc with {sign} size input.")
    case "aligned_alloc":
      signAlignment = signModule.getSign(expr.params[0])
      signSize = signModule.getsign(expr.params[1])
      if signSize is signModule.Sign.neg or signSize is signModule.Sign.zero:
        print(f"Alarm: aligned_alloc with {sign} size input.")
      if signAlignment is signModule.Sign.neg or signSize is signModule.Sign.zero:
        print(f"Alarm: aligned_alloc with {sign} alignment input.")
    case "realloc":
      sign = signModule.getSign(expr.params[1])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        print(f"Alarm: realloc with {sign} new size input.")
    case "free_sized":
      sign = signModule.getSign(expr.params[1])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        print(f"Alarm: free_sized with {sign} new size input.")
    case default:
      return


#==================================================================
# detectionString
#==================================================================
# Find and annotate common string function errors
#==================================================================
def detectionString(bv: binaryninja.binaryview.BinaryView,
                    expr: binaryninja.commonil.Call):
  if isinstance(expr.dest, binaryninja.mediumlevelil.MediumLevelILVar):
    funcs = bv.get_functions_by_name(expr.dest.var.name)
    if funcs is None:
      return
    if len(funcs) != 1:
      print(f"Multiple functions found by name: {expr.dest.var.name}")
      return
    func = funcs[0]
  elif isinstance(expr.dest, binaryninja.mediumlevelil.MediumLevelILConstPtr):
    func = bv.get_function_at(expr.dest.constant)
    if func is None:
      print(f"TODO: No ConstPtr function found at {expr.dest.constant}")
      return
  match func.name:
    case "strncpy":
      sign = signModule.getSign(expr.params[2])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        print(f"Alarm: strncpy with {sign} size input.")
    case "strncat":
      sign = signModule.getSign(expr.params[2])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        print(f"Alarm: strncat with {sign} size input.")
    case "strncmp":
      sign = signModule.getSign(expr.params[2])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        print(f"Alarm: strncmp with {sign} size input.")
    case "wcsncmp":
      sign = signModule.getSign(expr.params[2])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        print(f"Alarm: wcsncmp with {sign} size input.")
    case default:
      return


#==================================================================
# detectionCPPContainer
#==================================================================
# Find and annotate common cpp container errors
#==================================================================
def detectionCPPContainer(bv: binaryninja.binaryview.BinaryView,
                          expr: binaryninja.commonil.Call):
  if isinstance(expr.dest, binaryninja.mediumlevelil.MediumLevelILVar):
    funcs = bv.get_functions_by_name(expr.dest.var.name)
    if funcs is None:
      return
    if len(funcs) != 1:
      print(f"Multiple functions found by name: {expr.dest.var.name}")
      return
    func = funcs[0]
  elif isinstance(expr.dest, binaryninja.mediumlevelil.MediumLevelILConstPtr):
    func = bv.get_function_at(expr.dest.constant)
    if func is None:
      print(f"TODO: No ConstPtr function found at {expr.dest.constant}")
      return
  match func.name:
    case "_ZNSt6vectorIiSaIiEE6resizeEm":
      sign = signModule.getSign(expr.params[1])
      if sign is signModule.Sign.neg:
        print(f"Alarm: vector resize with {sign} size input.")
    case "_ZNSt6vectorIi6NAllocIiEE7reserveEm":
      sign = signModule.getSign(expr.params[1])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        print(f"Alarm: vector reserve with {sign} size input.")
    case "_ZNSt5dequeIiSaIiEE6resizeEm":
      if len(expr.params) < 2:
        print(f"Non-standard amount of function arguments. Manual inspection required.")
        bv.add_tag(expr.address, "Fixup", "Expected: Two arguments, this pointer and size_t count")
        return
      sign = signModule.getSign(expr.params[1])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        print(f"Alarm: deque resize with {sign} size input.")
    case "_ZNSt12forward_listIiSaIiEE6resizeEm":
      if len(expr.params) < 2:
        print(f"Non-standard amount of function arguments. Manual inspection required.")
        bv.add_tag(expr.address, "Fixup", "Expected: Two arguments, this pointer and size_t count")
        return
      sign = signModule.getSign(expr.params[1])
      if sign is signModule.Sign.neg or sign is signModule.Sign.zero:
        print(f"Alarm: forward list resize with {sign} size input.")
    case default:
      print(expr)
      return
