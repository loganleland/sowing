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


def updateContext(inst, sign: Sign):
  if inst.dest.name not in context.keys():
    context[inst.dest.name] = sign
  else:
    context[inst.dest.name] = sign


def processSetVar(inst: binaryninja.mediumlevelil.MediumLevelILSetVar):
  if isinstance(inst.dest.type, binaryninja.types.IntegerType):
    if isinstance(inst.src, binaryninja.commonil.Constant):
      updateContext(inst, deriveSignInt(inst.src.constant))
    elif isinstance(inst.src, binaryninja.commonil.VariableInstruction):
      updateContext(inst, deriveSignVar(inst.src.src.name))
    elif isinstance(inst.src, binaryninja.commonil.Arithmetic):
      match type(inst.src):
        case binaryninja.mediumlevelil.MediumLevelILZx:
          print(inst.src)


def getSign(expr) -> Sign:
  match type(expr):
    case binaryninja.commonil.SetVar:
      print("set var")


def test(bv: binaryninja.binaryview.BinaryView,
         entry: binaryninja.function.Function):
  for inst in entry.mlil.instructions:
    getSign(inst)
    #if isinstance(inst, binaryninja.commonil.SetVar):
    #  processSetVar(inst)
