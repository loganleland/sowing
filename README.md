# Sowing

<img src="https://github.com/loganleland/sow/assets/6620612/4ef6608d-195d-4a8c-9498-a8ecfa2d73d2" alt="drawing" width="300"/>

*verb: plant (seed) by scattering it on or in the earth*

**Sowing** is a suite of tools dedicated to the analysis of any loader and architecture supported by [Binary Ninja](https://binary.ninja/). Currently all analysis operates over [Medium Level IL](https://docs.binary.ninja/dev/bnil-mlil.html).

| Analysis | Maturity | Path | Tag 
| -------- | -------- | -------- | -------- |
| Sign     | Initial  | src/analysis/sign | ```+``` Sign Analysis

# Usage
Sowing can be used from the command line by specifying:
- Analysis to be executed
- Entry function symbol name
- Input path to binary ninja database or binary
- Output path where to save annotated binary ninja database
  
```python3 main.py -sign -entry main -file "/usr/bin/sudo" -out "./result.bndb"```
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
