## 2025-05-18 - Pre-computed Hex Lookup Table for Byte Conversions
**Learning:** Using `Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')` in hot crypto operations causes excessive string and array allocations per byte. A pre-computed 256-element lookup table with a simple `for` loop speeds up byte-to-hex formatting by ~10x.
**Action:** Use pre-computed lookup tables for byte-array to hex string formatting across hot cryptographic and hashing paths.
