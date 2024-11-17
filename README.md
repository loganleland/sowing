<div align="center">

![sowing-removebg-preview](https://github.com/user-attachments/assets/ca5e7326-5d1f-40d2-8170-5b404a84d83e)


*verb: plant (seed) by scattering it on or in the earth*

</div>

**Sowing** is a suite of tools dedicated to the analysis of any loader and architecture supported by [Binary Ninja](https://binary.ninja/). Currently all analysis operates over [Medium Level IL](https://docs.binary.ninja/dev/bnil-mlil.html).

---

<div align="center">
  
| Analysis | Maturity | Path | Tag 
| -------- | -------- | -------- | -------- |
| Sign     | Initial  | src/analysis/sign | ```+``` Sign Analysis

---
</div>

# Usage
Sowing can be used from the command line by specifying:
- Entry function symbol name
- Input path to binary ninja database or binary
- Output path where to save annotated binary ninja database
  
```python3 main.py -entry main -file "/usr/bin/sudo" -out "./result.bndb"```

Analysis starting at symbol main in file /usr/bin/sudo with results in new binja database results.bndb

## Fixups
If a symbol being considered by an analysis has incorrect function argument recovery the calls to the symbol will be marked with the tag "🔨 Fixup" including a detailed comment on the expected arguments.

# Installation
Simply have the binary ninja api in your path (execute [install_api.py](https://github.com/Vector35/binaryninja-api/blob/dev/scripts/install_api.py) and clone this repo.
Once a threshold maturity has been reached this code should be downloadable via the binary ninja plugin manager.

# Documentation of Binary Ninja
- [BNIL](https://docs.binary.ninja/dev/bnil-overview.html)
- [mediumlevelil module](https://api.binary.ninja/binaryninja.mediumlevelil-module.html#mediumlevelil-module)
- [commonil module](https://api.binary.ninja/binaryninja.commonil-module.html#commonil-module)
