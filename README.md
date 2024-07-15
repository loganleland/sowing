# Sowing

<img src="https://github.com/loganleland/sow/assets/6620612/4ef6608d-195d-4a8c-9498-a8ecfa2d73d2" alt="drawing" width="300"/>

*verb: plant (seed) by scattering it on or in the earth*

**Sowing** is a suite of tools dedicated to the analysis of any loader and architecture supported by [Binary Ninja](https://binary.ninja/)

| Analysis | Maturity | Path |
| -------- | -------- | -------- |
| Sign     | Initial  | [Implementation](https://github.com/loganleland/sowing/blob/main/src/analysis/sign.py) |

# Usage
Presently Sowing can be used from the command line by specifying:
- Analysis to be executed
- Entry function symbol name
- Path to binary ninja database (bndb)
  
```python3 main.py -sign -entry main -bndb ../sudo.bndb```

The bndb specified will contain tags to be reviewed.

# Documentation of Binary Ninja
- [BNIL](https://docs.binary.ninja/dev/bnil-overview.html)
- [mediumlevelil module](https://api.binary.ninja/binaryninja.mediumlevelil-module.html#mediumlevelil-module)
- [commonil module](https://api.binary.ninja/binaryninja.commonil-module.html#commonil-module)
