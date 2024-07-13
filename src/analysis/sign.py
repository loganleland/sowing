from email.policy import default
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
  updateContext(inst, getSign(inst.src))
  return None


def processArith(inst: binaryninja.commonil.Arithmetic):
  print(inst)

def processConstant(expr: binaryninja.commonil.Constant) -> Sign:
  if isinstance(expr, binaryninja.mediumlevelil.MediumLevelILConst):
    print(f"constant: {type(expr.constant)}")


def getSign(expr) -> Sign:
  if isinstance(expr, binaryninja.commonil.Constant):
    processConstant(expr)
  if isinstance(expr, binaryninja.commonil.SetVar):
    processSetVar(expr)
  else:
    pass


def test(bv: binaryninja.binaryview.BinaryView,
         entry: binaryninja.function.Function):
  for inst in entry.mlil.instructions:
    getSign(inst)
    #if isinstance(inst, binaryninja.commonil.SetVar):
    #  processSetVar(inst)
