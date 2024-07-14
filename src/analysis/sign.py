import binaryninja
from enum import Enum

context = dict()
types = set()

class Sign(Enum):
  top = 1
  neg = 2 
  zero = 3
  pos = 4
  bottom = 5


# Derive sign of integer
def deriveSignInt(op: int) -> Sign:
  if op == 0: return Sign.zero
  if op > 0: return Sign.pos
  return Sign.neg


# Derive sign of variable identifier from context
def deriveSignVar(op: str) -> Sign:
  if op not in context.keys():
    return Sign.bottom
  return context[op]


def updateContext(expr, sign: Sign):
  if expr.dest.name not in context.keys():
    context[expr.dest.name] = sign
  else:
    context[expr.dest.name] = sign


def processSetVar(expr: binaryninja.commonil.SetVar):
  updateContext(expr, getSign(expr.src))


def processAnd(expr: binaryninja.mediumlevelil.MediumLevelILAnd) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  if leftSign == Sign.zero or rightSign == Sign.zero:
    return Sign.zero
  return Sign.top


def processOr(expr: binaryninja.mediumlevelil.MediumLevelILOr) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  if leftSign == Sign.zero and rightSign == Sign.zero:
    return Sign.zero
  return Sign.top


def processAddition(expr: binaryninja.mediumlevelil.MediumLevelILAdd) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  if leftSign == Sign.bottom or rightSign == Sign.bottom:
    # Unmodeled or weird behavior
    return Sign.bottom
  if leftSign == Sign.top or rightSign == Sign.top:
    return Sign.top
  if leftSign == Sign.zero:
    return rightSign
  match leftSign:
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          return Sign.pos
        case Sign.pos:
          return Sign.pos
        case Sign.neg:
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          return Sign.neg
        case Sign.pos:
          return Sign.top
        case Sign.neg:
          return Sign.pos


def processSubtraction(expr: binaryninja.mediumlevelil.MediumLevelILSub) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  if leftSign == Sign.bottom or rightSign == Sign.bottom:
    return Sign.bottom
  elif leftSign == Sign.top or rightSign == Sign.top:
    return Sign.top
  elif leftSign == Sign.zero:
    return rightSign
  match leftSign:
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          return Sign.pos
        case Sign.pos:
          return Sign.top
        case Sign.neg:
          return Sign.pos
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          return Sign.zero
        case Sign.pos:
          return Sign.neg
        case Sign.neg:
          return Sign.top


def processXor(expr: binaryninja.mediumlevelil.MediumLevelILXor) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  if leftSign == Sign.zero and rightSign == Sign.zero:
    return Sign.zero
  return Sign.top


def processArith(expr: binaryninja.commonil.Arithmetic):
  match type(expr):
    case binaryninja.mediumlevelil.MediumLevelILZx:
      match getSign(expr.src):
        case Sign.pos:
          return Sign.pos
        case Sign.neg:
          return Sign.top
        case Sign.zero:
          return Sign.zero
        case Sign.top:
          return Sign.top
        case Sign.bottom:
          return Sign.bottom
    case binaryninja.mediumlevelil.MediumLevelILSx:
      return getSign(expr.src)
    case binaryninja.mediumlevelil.MediumLevelILAdd:
      return processAddition(expr)
    case binaryninja.mediumlevelil.MediumLevelILSub:
      return processSubtraction(expr)
    case binaryninja.mediumlevelil.MediumLevelILAnd:
      return processAnd(expr)
    case binaryninja.mediumlevelil.MediumLevelILOr:
      return processOr(expr)
    case binaryninja.mediumlevelil.MediumLevelILLsr:
      if Sign.neg == getSign(expr.left):
        return Sign.neg
      return Sign.top
    case binaryninja.mediumlevelil.MediumLevelILLsl:
      if Sign.neg == getSign(expr.left):
        return Sign.neg
      return Sign.top
    case binaryninja.mediumlevelil.MediumLevelILXor:
      return processXor(expr)
  #print(f"Unimplemented: processArith({expr}) of ty {type(expr)}")


def processConstant(expr: binaryninja.commonil.Constant) -> Sign:
  if isinstance(expr, binaryninja.mediumlevelil.MediumLevelILConst):
    return getSign(expr.constant)
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILConstPtr):
    return Sign.bottom
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILImport):
    return getSign(expr.constant)
  else:
    print(f"Unimplemented expression: {expr} of ty: {type(expr)}")
    return None


def processInt(expr: int) -> Sign:
  match expr:
    case 0:
      return Sign.zero
    case _ if expr > 0:
      return Sign.pos
    case _ if expr < 0:
      return Sign.neg
 

def processVar(expr: binaryninja.commonil.VariableInstruction) -> Sign:
  if expr.var.name not in context.keys():
    return Sign.bottom
  return context[expr.var.name]


def processCmpE(expr: binaryninja.mediumlevelil.MediumLevelILCmpE) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  match leftSign:
    case Sign.zero:
      match rightSign:
        case Sign.zero:
          # 0 == 0 -> 1
          return Sign.pos
        case Sign.neg:
          # 0 == -n -> 0
          return Sign.zero
        case Sign.pos:
          # 0 == +n -> 0
          return Sign.zero
        case Sign.top:
          # 0 == T -> T
          return Sign.top
        case Sign.bottom:
          # 0 == B -> T
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          # -n == 0 -> 0
          return Sign.zero
        case Sign.neg:
          # -n == -v -> T
          return Sign.top
        case Sign.pos:
          # -n == +v -> 0
          return Sign.zero
        case Sign.top:
          # -n == T -> T
          return Sign.top
        case Sign.bottom:
          # -n == B -> T
          return Sign.top
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          # +n == 0 -> 0
          return Sign.zero
        case Sign.neg:
          # +n == -v -> 0
          return Sign.zero
        case Sign.pos:
          # +n == +v -> T
          return Sign.top
        case Sign.top:
          # +n == T -> T
          return Sign.top
        case Sign.bottom:
          # +n == B -> T
          return Sign.top
    case Sign.top:
      return Sign.top
    case Sign.bottom:
      return Sign.top


def processCmpNe(expr: binaryninja.mediumlevelil.MediumLevelILCmpNe) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  match leftSign:
    case Sign.zero:
      match rightSign:
        case Sign.zero:
          # 0 != 0 -> 0
          return Sign.zero
        case Sign.neg:
          # 0 == -n -> 1
          return Sign.pos
        case Sign.pos:
          # 0 == +n -> 1
          return Sign.pos
        case Sign.top:
          # 0 != T -> T
          return Sign.top
        case Sign.bottom:
          # 0 != B -> T
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          # -n != 0 -> 1
          return Sign.pos
        case Sign.neg:
          # -n != -v -> T
          return Sign.top
        case Sign.pos:
          # -n != +v -> 1
          return Sign.pos
        case Sign.top:
          # -n != T -> T
          return Sign.top
        case Sign.bottom:
          # -n != B -> T
          return Sign.top
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          # +n != 0 -> 1
          return Sign.pos
        case Sign.neg:
          # +n != -v -> 1
          return Sign.pos
        case Sign.pos:
          # +n != +v -> T
          return Sign.top
        case Sign.top:
          # +n != T -> T
          return Sign.top
        case Sign.bottom:
          # +n != B -> T
          return Sign.top
    case Sign.top:
      return Sign.top
    case Sign.bottom:
      return Sign.top


def processCmpSge(expr: binaryninja.mediumlevelil.MediumLevelILCmpSge) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  match leftSign:
    case Sign.zero:
      match rightSign:
        case Sign.zero:
          # 0 >= 0 -> 1
          return Sign.pos
        case Sign.neg:
          # 0 >= -n -> 1
          return Sign.pos
        case Sign.pos:
          # 0 >= +n -> 0
          return Sign.zero
        case Sign.top:
          # 0 >= T -> T
          return Sign.top
        case Sign.bottom:
          # 0 >= B -> T
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          # -n >= 0 -> 0
          return Sign.neg
        case Sign.neg:
          # -n >= -v -> T
          return Sign.top
        case Sign.pos:
          # -n >= +v -> 0
          return Sign.zero
        case Sign.top:
          # -n >= T -> T
          return Sign.top
        case Sign.bottom:
          # -n >= B -> T
          return Sign.top
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          # +n >= 0 -> 1
          return Sign.pos
        case Sign.neg:
          # +n >= -v -> 1
          return Sign.pos
        case Sign.pos:
          # +n >= +v -> T
          return Sign.top
        case Sign.top:
          # +n >= T -> T
          return Sign.top
        case Sign.bottom:
          # +n >= B -> T
          return Sign.top
    case Sign.top:
      return Sign.top
    case Sign.bottom:
      return Sign.top


def processCmpUgt(expr: binaryninja.mediumlevelil.MediumLevelILCmpUgt) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  match leftSign:
    case Sign.zero:
      match rightSign:
        case Sign.zero:
          # 0 > 0 -> 0
          return Sign.zero
        case Sign.neg:
          # 0 > -n -> 1
          return Sign.pos
        case Sign.pos:
          # 0 > +n -> 0
          return Sign.zero
        case Sign.top:
          # 0 > T -> T
          return Sign.top
        case Sign.bottom:
          # 0 > B -> T
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          # -n > 0 -> 0
          return Sign.zero
        case Sign.neg:
          # -n > -v -> T
          return Sign.top
        case Sign.pos:
          # -n > +v -> 0
          return Sign.zero
        case Sign.top:
          # -n > T -> T
          return Sign.top
        case Sign.bottom:
          # -n > B -> T
          return Sign.top
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          # +n > 0 -> 1
          return Sign.pos
        case Sign.neg:
          # +n > -v -> 1
          return Sign.pos
        case Sign.pos:
          # +n > +v -> T
          return Sign.top
        case Sign.top:
          # +n > T -> T
          return Sign.top
        case Sign.bottom:
          # +n > B -> T
          return Sign.top
    case Sign.top:
      # forall a, T > a -> T
      return Sign.top
    case Sign.bottom:
      # forall a, B > a -> T
      return Sign.top


def processCmpSlt(expr: binaryninja.mediumlevelil.MediumLevelILCmpSlt) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  match leftSign:
    case Sign.zero:
      match rightSign:
        case Sign.zero:
          # 0 < 0 -> 0
          return Sign.zero
        case Sign.neg:
          # 0 < -n -> 0
          return Sign.zero
        case Sign.pos:
          # 0 < +n -> 1
          return Sign.pos
        case Sign.top:
          # 0 < T -> T
          return Sign.top
        case Sign.bottom:
          # 0 < B -> T
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          # -n < 0 -> 0
          return Sign.pos
        case Sign.neg:
          # -n < -v -> T
          return Sign.top
        case Sign.pos:
          # -n < +v -> 1
          return Sign.pos
        case Sign.top:
          # -n < T -> T
          return Sign.top
        case Sign.bottom:
          # -n < B -> T
          return Sign.top
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          # +n < 0 -> 0
          return Sign.zero
        case Sign.neg:
          # +n < -v -> 0
          return Sign.zero
        case Sign.pos:
          # +n < +v -> T
          return Sign.top
        case Sign.top:
          # +n < T -> T
          return Sign.top
        case Sign.bottom:
          # +n < B -> T
          return Sign.top
    case Sign.top:
      # forall a, T < a -> T
      return Sign.top
    case Sign.bottom:
      # forall a, B < a -> T
      return Sign.top


def processCmpSle(expr: binaryninja.mediumlevelil.MediumLevelILCmpSle) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  match leftSign:
    case Sign.zero:
      match rightSign:
        case Sign.zero:
          # 0 <= 0 -> 1
          return Sign.pos
        case Sign.neg:
          # 0 <= -n -> 0
          return Sign.zero
        case Sign.pos:
          # 0 <= +n -> 1
          return Sign.pos
        case Sign.top:
          # 0 <= T -> T
          return Sign.top
        case Sign.bottom:
          # 0 <= B -> T
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          # -n <= 0 -> 1
          return Sign.pos
        case Sign.neg:
          # -n <= -v -> T
          return Sign.top
        case Sign.pos:
          # -n <= +v -> 1
          return Sign.pos
        case Sign.top:
          # -n <= T -> T
          return Sign.top
        case Sign.bottom:
          # -n <= B -> T
          return Sign.top
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          # +n <= 0 -> 0
          return Sign.zero
        case Sign.neg:
          # +n <= -v -> 0
          return Sign.zero
        case Sign.pos:
          # +n <= +v -> T
          return Sign.top
        case Sign.top:
          # +n <= T -> T
          return Sign.top
        case Sign.bottom:
          # +n <= B -> T
          return Sign.top
    case Sign.top:
      # forall a, T <= a -> T
      return Sign.top
    case Sign.bottom:
      # forall a, B <= a -> T
      return Sign.top


def processCmpSgt(expr: binaryninja.mediumlevelil.MediumLevelILCmpSgt) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  match leftSign:
    case Sign.zero:
      match rightSign:
        case Sign.zero:
          # 0 < 0 -> 0
          return Sign.zero
        case Sign.neg:
          # 0 < -n -> 0
          return Sign.zero
        case Sign.pos:
          # 0 < +n -> 1
          return Sign.pos
        case Sign.top:
          # 0 < T -> T
          return Sign.top
        case Sign.bottom:
          # 0 < B -> T
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          # -n < 0 -> 1
          return Sign.pos
        case Sign.neg:
          # -n < -v -> T
          return Sign.top
        case Sign.pos:
          # -n < +v -> 1
          return Sign.pos
        case Sign.top:
          # -n < T -> T
          return Sign.top
        case Sign.bottom:
          # -n < B -> T
          return Sign.top
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          # +n < 0 -> 0
          return Sign.zero
        case Sign.neg:
          # +n < -v -> 0
          return Sign.zero
        case Sign.pos:
          # +n < +v -> T
          return Sign.top
        case Sign.top:
          # +n < T -> T
          return Sign.top
        case Sign.bottom:
          # +n < B -> T
          return Sign.top
    case Sign.top:
      # forall a, T < a -> T
      return Sign.top
    case Sign.bottom:
      # forall a, B < a -> T
      return Sign.top


def processCmpUge(expr: binaryninja.mediumlevelil.MediumLevelILCmpUge) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  match leftSign:
    case Sign.zero:
      match rightSign:
        case Sign.zero:
          # 0 >= 0 -> 1
          return Sign.pos
        case Sign.neg:
          # 0 >= -n -> 1
          return Sign.pos
        case Sign.pos:
          # 0 >= +n -> 0
          return Sign.zero
        case Sign.top:
          # 0 >= T -> T
          return Sign.top
        case Sign.bottom:
          # 0 >= B -> T
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          # -n >= 0 -> 0
          return Sign.zero
        case Sign.neg:
          # -n >= -v -> T
          return Sign.top
        case Sign.pos:
          # -n >= +v -> 0
          return Sign.zero
        case Sign.top:
          # -n >= T -> T
          return Sign.top
        case Sign.bottom:
          # -n >= B -> T
          return Sign.top
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          # +n >= 0 -> 1
          return Sign.pos
        case Sign.neg:
          # +n >= -v -> 1
          return Sign.pos
        case Sign.pos:
          # +n >= +v -> T
          return Sign.top
        case Sign.top:
          # +n >= T -> T
          return Sign.top
        case Sign.bottom:
          # +n >= B -> T
          return Sign.top
    case Sign.top:
      # forall a, T >= a -> T
      return Sign.top
    case Sign.bottom:
      # forall a, B >= a -> T
      return Sign.top


def processCmpUle(expr: binaryninja.mediumlevelil.MediumLevelILCmpUge) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  match leftSign:
    case Sign.zero:
      match rightSign:
        case Sign.zero:
          # 0 <= 0 -> 1
          return Sign.pos
        case Sign.neg:
          # 0 <= -n -> 0
          return Sign.zero
        case Sign.pos:
          # 0 <= +n -> 1
          return Sign.pos
        case Sign.top:
          # 0 <= T -> T
          return Sign.top
        case Sign.bottom:
          # 0 <= B -> T
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          # -n <= 0 -> 1
          return Sign.pos
        case Sign.neg:
          # -n <= -v -> T
          return Sign.top
        case Sign.pos:
          # -n <= +v -> 1
          return Sign.pos
        case Sign.top:
          # -n <= T -> T
          return Sign.top
        case Sign.bottom:
          # -n <= B -> T
          return Sign.top
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          # +n <= 0 -> 0
          return Sign.zero
        case Sign.neg:
          # +n <= -v -> 0
          return Sign.zero
        case Sign.pos:
          # +n <= +v -> T
          return Sign.top
        case Sign.top:
          # +n <= T -> T
          return Sign.top
        case Sign.bottom:
          # +n <= B -> T
          return Sign.top
    case Sign.top:
      # forall a, T <= a -> T
      return Sign.top
    case Sign.bottom:
      # forall a, B <= a -> T
      return Sign.top


def processCmpUlt(expr: binaryninja.mediumlevelil.MediumLevelILCmpUge) -> Sign:
  leftSign = getSign(expr.left)
  rightSign = getSign(expr.right)
  match leftSign:
    case Sign.zero:
      match rightSign:
        case Sign.zero:
          # 0 < 0 -> 0
          return Sign.zero
        case Sign.neg:
          # 0 < -n -> 0
          return Sign.zero
        case Sign.pos:
          # 0 < +n -> 1
          return Sign.pos
        case Sign.top:
          # 0 < T -> T
          return Sign.top
        case Sign.bottom:
          # 0 < B -> T
          return Sign.top
    case Sign.neg:
      match rightSign:
        case Sign.zero:
          # -n < 0 -> 1
          return Sign.pos
        case Sign.neg:
          # -n < -v -> T
          return Sign.top
        case Sign.pos:
          # -n < +v -> 1
          return Sign.pos
        case Sign.top:
          # -n < T -> T
          return Sign.top
        case Sign.bottom:
          # -n < B -> T
          return Sign.top
    case Sign.pos:
      match rightSign:
        case Sign.zero:
          # +n < 0 -> 0
          return Sign.zero
        case Sign.neg:
          # +n < -v -> 0
          return Sign.zero
        case Sign.pos:
          # +n < +v -> T
          return Sign.top
        case Sign.top:
          # +n < T -> T
          return Sign.top
        case Sign.bottom:
          # +n < B -> T
          return Sign.top
    case Sign.top:
      # forall a, T < a -> T
      return Sign.top
    case Sign.bottom:
      # forall a, B < a -> T
      return Sign.top


def processComparison(expr: binaryninja.commonil.Comparison) -> Sign:
  match type(expr):
    case binaryninja.mediumlevelil.MediumLevelILCmpE:
      return processCmpE(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpNe:
      return processCmpNe(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpUgt:
      return processCmpUgt(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpUge:
      return processCmpUge(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpUle:
      return processCmpUle(expr)
    case binaryninja.mediumlevelil.MediumLevelILCmpUlt:
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


def getSign(expr) -> Sign:
  if isinstance(expr, binaryninja.commonil.Constant):
    return processConstant(expr)
  elif isinstance(expr, binaryninja.commonil.SetVar):
    processSetVar(expr)
  elif isinstance(expr, binaryninja.commonil.VariableInstruction):
    return processVar(expr)
  elif isinstance(expr, binaryninja.commonil.Arithmetic):
    return processArith(expr)
  elif isinstance(expr, binaryninja.commonil.Load):
    return getSign(expr.src)
  elif isinstance(expr, binaryninja.commonil.Store):
    return Sign.top
  elif isinstance(expr, binaryninja.commonil.Call):
    # Future work: support call instructions
    return Sign.top
  elif isinstance(expr, binaryninja.commonil.ControlFlow):
    return Sign.top
  elif isinstance(expr, binaryninja.commonil.Comparison):
    return processComparison(expr)
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILBoolToInt):
    return getSign(expr.src)
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILAddressOf):
    # Addresses are considered positive right now
    return Sign.pos
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILAddressOfField):
    # Addresses are considered positive right now
    return Sign.pos
  elif isinstance(expr, binaryninja.mediumlevelil.MediumLevelILVarField):
    sign = Sign.bottom
    if expr.src.name in context.keys():
      sign = context[expr.src.name]
    if sign == Sign.zero:
      # Regardless of offset into expr.src 0 will be 0
      return Sign.zero
    if expr.offset == 0:
      return sign
    return Sign.top
  elif isinstance(expr, int):
    return processInt(expr)
  else:
    print(f"getSign unimpl expr: {expr}, ty: {type(expr)}")


def signAnalysis(bv: binaryninja.binaryview.BinaryView,
             entry: binaryninja.function.Function):
  for func in bv.functions:
    for inst in func.mlil.instructions:
      getSign(inst)