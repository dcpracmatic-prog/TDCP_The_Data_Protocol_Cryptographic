## 2025-05-18 - Pre-computed Hex Lookup Table for Byte Conversions
**Learning:** Using `Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')` in hot crypto operations causes excessive string and array allocations per byte. A pre-computed 256-element lookup table with a simple `for` loop speeds up byte-to-hex formatting by ~10x.
**Action:** Use pre-computed lookup tables for byte-array to hex string formatting across hot cryptographic and hashing paths.

## 2025-05-19 - Fast Base64 Encoding/Decoding for Binary Payloads
**Learning:** Single-byte string concatenation loops (`binary += String.fromCharCode(bytes[i])`) in Base64 conversions cause excessive string allocations, taking ~680ms for 5MB binary packages. Leveraging native `Buffer.from()` in Node environments delivers a >100x speedup (~5ms for 5MB), and using 32KB chunking with `String.fromCharCode.apply()` in browser fallbacks provides a ~10x–50x speedup while avoiding call stack limits.
**Action:** Use Node `Buffer` fast-paths when available and chunked `String.fromCharCode.apply` for browser binary-to-Base64 conversions in cryptographic and file-processing utilities.

## 2025-05-20 - Map Insertion-Order Iteration for Cache Eviction
**Learning:** Using `Array.from(map.entries()).sort(...)` during bounded cache eviction creates large array allocations and O(N log N) overhead per request when capacity is reached (~9ms per call at 50,000 items). JavaScript `Map` preserves insertion order natively, allowing O(1) eviction in ~0.001ms with zero allocations by iterating Map keys/entries directly.
**Action:** Use native `Map` insertion-order iteration for bounded cache/registry eviction instead of converting to arrays and sorting.

## 2025-05-21 - Top-level Static Imports in Hot Crypto Signing Paths
**Learning:** Invoking dynamic `await import(...)` calls inside hot execution paths (such as grant signing or policy binding generation) adds Promise creation and module map resolution overhead (~18% latency overhead under load) even when the module is already cached. Using top-level static imports eliminates dynamic import overhead entirely.
**Action:** Always import cryptographic primitives and helpers statically at top-level rather than dynamically importing them inside method bodies.
