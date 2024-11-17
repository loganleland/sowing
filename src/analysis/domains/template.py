import binaryninja
from enum import Enum

# Abstract domain
class Lattice(Enum):
  top = 1
  bottom = 2

global context
global view
global tags
context = dict()
view = None
tags = set()

#==================================================================
# initLattice
#==================================================================
#==================================================================
def init(bv):
  global view
  view = bv

#==================================================================
# processVar
#==================================================================
# Derive lattice of variable (by identifier) from context
#==================================================================
def processVar(op: str) -> Lattice:
  if op not in context.keys():
    return Lattice.bottom
  return context[op]


#==================================================================
# updateContext
#==================================================================
# Write variable identifier to lattice mapping into context
#==================================================================
def updateContext(expr: binaryninja.commonil.SetVar, state: Lattice):
  if expr.dest.name not in context.keys():
    context[expr.dest.name] = state
  else:
    context[expr.dest.name] = state


#==================================================================
# processSetVar
#==================================================================
# Update context via binaryninja.commonil.SetVar instruction
#==================================================================
def processSetVar(expr: binaryninja.commonil.SetVar):
  updateContext(expr, getLattice(expr.src))


#==================================================================
# processAnd
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILAnd
#==================================================================
def processAnd(expr: binaryninja.mediumlevelil.MediumLevelILAnd) -> Lattice:
  pass


#==================================================================
# processOr
#==================================================================
# Derive Lattice of binaryninja.mediumlevelil.MediumLevelILOr
#==================================================================
def processOr(expr: binaryninja.mediumlevelil.MediumLevelILOr) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processAddition
#==================================================================
# Derive Lattice of binaryninja.mediumlevelil.MediumLevelILAdd
#==================================================================
def processAddition(expr: binaryninja.mediumlevelil.MediumLevelILAdd) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processSubtraction
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILSub
#==================================================================
def processSubtraction(expr: binaryninja.mediumlevelil.MediumLevelILSub) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processXor
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILXor
#==================================================================
def processXor(expr: binaryninja.mediumlevelil.MediumLevelILXor) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processMul
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILMul
#==================================================================
def processMul(expr: binaryninja.mediumlevelil.MediumLevelILMul) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processAsr
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILAsr
#==================================================================
def processAsr(expr: binaryninja.mediumlevelil.MediumLevelILAsr) -> Lattice:
  return getLattice(expr.left)


#==================================================================
# processNot
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILNot
#==================================================================
def processNot(expr: binaryninja.mediumlevelil.MediumLevelILNot) -> Lattice:
  lattice = getLattice(expr.src)
  pass


#==================================================================
# processArith
#==================================================================
# Derive lattice of binaryninja.commonil.Arithmetic
#==================================================================
def processArith(expr: binaryninja.commonil.Arithmetic):
  match type(expr):
    case binaryninja.mediumlevelil.MediumLevelILZx:
      return getLattice(expr.src)
    case binaryninja.mediumlevelil.MediumLevelILSx:
      return getLattice(expr.src)
    case binaryninja.mediumlevelil.MediumLevelILAdd:
      return processAddition(expr)
    case binaryninja.mediumlevelil.MediumLevelILAddOverflow:
      return processAddition(expr)
    case binaryninja.mediumlevelil.MediumLevelILSub:
      return processSubtraction(expr)
    case binaryninja.mediumlevelil.MediumLevelILAnd:
      return processAnd(expr)
    case binaryninja.mediumlevelil.MediumLevelILOr:
      return processOr(expr)
    case binaryninja.mediumlevelil.MediumLevelILLsr:
      pass
    case binaryninja.mediumlevelil.MediumLevelILLsl:
      pass
    case binaryninja.mediumlevelil.MediumLevelILXor:
      return processXor(expr)
    case binaryninja.mediumlevelil.MediumLevelILLowPart:
      return getLattice(expr.src)
    case binaryninja.mediumlevelil.MediumLevelILDivu:
      leftLattice = getLattice(expr.left)
      rightLattice = getLattice(expr.right)
      pass
    case binaryninja.mediumlevelil.MediumLevelILMul:
      return processMul(expr)
    case binaryninja.mediumlevelil.MediumLevelILMulsDp:
      return processMul(expr)
    case binaryninja.mediumlevelil.MediumLevelILAsr:
      return processAsr(expr)
    case binaryninja.mediumlevelil.MediumLevelILNot:
      return processNot(expr)
    case binaryninja.mediumlevelil.MediumLevelILIntToFloat:
      return getLattice(expr.src)
    case binaryninja.mediumlevelil.MediumLevelILFloatConv:
      return getLattice(expr.src)

  print(f"Unimplemented: processArith({expr}) of ty {type(expr)}")


#==================================================================
# processConstant
#==================================================================
# Derive lattice of binaryninja.commonil.Constant
#==================================================================
def processConstant(expr: binaryninja.commonil.Constant) -> Lattice:
  if isinstance(expr, binaryninja.mediumlevelil.MediumLevelILConst):
    return getLattice(expr.constant)
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILConstPtr):
    pass
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILImport):
    return getLattice(expr.constant)
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILConstData):
    return getLattice(expr.constant_data.value)
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILFloatConst):
    return getLattice(expr.constant)
  else:
    print(f"Unimplemented constant expression: {expr} of ty: {type(expr)}")
    return None


#==================================================================
# processRawConst
#==================================================================
# Derive lattice of raw python int/float
#==================================================================
def processRawConst(expr) -> Lattice:
  pass


#==================================================================
# processVar
#==================================================================
# Derive lattice of binaryninja.commonil.VariableInstruction
# from context
#==================================================================
def processVar(expr: binaryninja.commonil.VariableInstruction) -> Lattice:
  if expr.var.name not in context.keys():
    return Lattice.bottom
  return context[expr.var.name]


#==================================================================
# processCmpE
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILCmpE
#==================================================================
def processCmpE(expr: binaryninja.mediumlevelil.MediumLevelILCmpE) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processCmpNe
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILCmpNe
#==================================================================
def processCmpNe(expr: binaryninja.mediumlevelil.MediumLevelILCmpNe) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processCmpSge
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILCmpSge
#==================================================================
def processCmpSge(expr: binaryninja.mediumlevelil.MediumLevelILCmpSge) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processCmpUgt
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILCmpUgt
#==================================================================
def processCmpUgt(expr: binaryninja.mediumlevelil.MediumLevelILCmpUgt) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processCmpSlt
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILCmpSlt
#==================================================================
def processCmpSlt(expr: binaryninja.mediumlevelil.MediumLevelILCmpSlt) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processCmpSle
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILCmpSle
#==================================================================
def processCmpSle(expr: binaryninja.mediumlevelil.MediumLevelILCmpSle) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processCmpSgt
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILCmpSgt
#==================================================================
def processCmpSgt(expr: binaryninja.mediumlevelil.MediumLevelILCmpSgt) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processCmpUge
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILCmpUge
#==================================================================
def processCmpUge(expr: binaryninja.mediumlevelil.MediumLevelILCmpUge) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processCmpUle
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILCmpUle
#==================================================================
def processCmpUle(expr: binaryninja.mediumlevelil.MediumLevelILCmpUle) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processCmpUlt
#==================================================================
# Derive lattice of binaryninja.mediumlevelil.MediumLevelILCmpUle
#==================================================================
def processCmpUlt(expr: binaryninja.mediumlevelil.MediumLevelILCmpUlt) -> Lattice:
  leftLattice = getLattice(expr.left)
  rightLattice = getLattice(expr.right)
  pass


#==================================================================
# processComparison
#==================================================================
# Derive lattice of binaryninja.commonil.Comparison
#==================================================================
def processComparison(expr: binaryninja.commonil.Comparison) -> Lattice:
  match type(expr):
    case binaryninja.mediumlevelil.MediumLevelILCmpE | \
         binaryninja.mediumlevelil.MediumLevelILFcmpE:
      return processCmpE(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpNe | \
         binaryninja.mediumlevelil.MediumLevelILFcmpNe:
      return processCmpNe(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpUgt | \
         binaryninja.mediumlevelil.MediumLevelILFcmpGt:
      return processCmpUgt(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpUge | \
         binaryninja.mediumlevelil.MediumLevelILFcmpGe:
      return processCmpUge(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpUle | \
         binaryninja.mediumlevelil.MediumLevelILFcmpLe:
      return processCmpUle(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpUlt | \
         binaryninja.mediumlevelil.MediumLevelILFcmpLt:
      return processCmpUlt(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpSge:
      return processCmpSge(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpSlt:
      return processCmpSlt(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpSle:
      return processCmpSle(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpSgt:
      return processCmpSgt(expr)
    case default:
      print(f"unimpl comparison {type(expr)}")


#==================================================================
# processCall
#==================================================================
# Derive lattice of binaryninja.commonil.Call
#
# Introduce named function arguments into context while processing
# the function call
#
# Evaluate lattice of return values
#
# TODO: Support recursion
#==================================================================
def processCall(expr: binaryninja.commonil.Call) -> Lattice:
  # Setup function-specific context
  global context
  prevContext = context
  # List of states for each function parameter
  argLattices = list(map(lambda l: getLattice(l), expr.params))
  context = dict()
  returnLattice = set()

  match type(expr.dest):
    case binaryninja.mediumlevelil.MediumLevelILConstPtr:
      callTo = view.get_function_at(expr.dest.constant)
      # Need to check for variable arguments
      if len(callTo.parameter_vars) != len(argLattices):
        return
      # Introduce function arguments mapped to lattices into context
      for arg in list(zip(callTo.parameter_vars, argLattices)):
        context[arg[0].name] = arg[1]
      for inst in callTo.mlil.instructions:
        if isinstance(inst, binaryninja.commonil.Return):
          # Check if database contains any lists greater than 1
          if len(inst.src) > 0:
            returnLattice.add(getLattice(inst.src[0]))
        else:
          getLattice(inst)
        if isinstance(inst, binaryninja.commonil.Call):
          detectionLattice(view, inst)
      return Lattice.top
    case binaryninja.mediumlevelil.MediumLevelILImport:
      return
    case default:
      print(f"Unimplemented expression of type {type(expr)}")
  context = prevContext


#==================================================================
# getLattice
#==================================================================
# Derive type of mediumlevelIL instruction then derive lattice
#==================================================================
def getLattice(expr) -> Lattice:
  if isinstance(expr, binaryninja.commonil.Constant):
    return processConstant(expr)
  elif isinstance(expr, binaryninja.commonil.SetVar):
    processSetVar(expr)
  elif isinstance(expr, binaryninja.commonil.VariableInstruction):
    return processVar(expr)
  elif isinstance(expr, binaryninja.commonil.Arithmetic):
    return processArith(expr)
  elif isinstance(expr, binaryninja.commonil.Load):
    return getLattice(expr.src)
  elif isinstance(expr, binaryninja.commonil.Store):
    return Lattice.top
  elif isinstance(expr, binaryninja.commonil.Call):
    return processCall(expr)
  elif isinstance(expr, binaryninja.commonil.ControlFlow):
    return Lattice.top
  elif isinstance(expr, binaryninja.commonil.Comparison):
    return processComparison(expr)
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILBoolToInt):
    return getLattice(expr.src)
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILAddressOf):
    # Addresses are considered positive right now
    return Lattice.pos
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILAddressOfField):
    # Addresses are considered positive right now
    return Lattice.pos
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILVarField):
    lattice = Lattice.bottom
    if expr.src.name in context.keys():
      lattice = context[expr.src.name]
    if expr.offset == 0:
      return lattice.top
    return Lattice.top
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILIntrinsic):
    return Lattice.top;
  elif isinstance(expr, int) or isinstance(expr, float):
    return processRawConst(expr)
  elif isinstance(expr, str):
    if expr in context.keys():
      return context[expr]
    return Lattice.bottom
  else:
    print(f"getLattice unimpl expr: {expr}, ty: {type(expr)}")

