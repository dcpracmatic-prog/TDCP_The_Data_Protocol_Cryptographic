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

## 2025-05-22 - Memoize In-Render Iteration and Lift Static Array Allocations
**Learning:** Re-evaluating inline array operations like `Array.from({ length: 24 })`, `filteredLogs.slice().reverse()`, and category filtering during React render cycles creates unnecessary garbage collection overhead and redundant computations on every state update or progress event. Lifting static arrays to module scope and wrapping derived array lists in `useMemo` prevents unnecessary allocations and keeps UI render ticks lightweight.
**Action:** Lift constant UI arrays to top-level module scope and wrap derived filtering/reversing operations in `useMemo` with minimal dependency arrays.

## 2025-05-23 - Buffer Fast-Path for Base64 and Base64Url Byte Decoding
**Learning:** Decoding Base64 strings to `Uint8Array` by looping over `binaryString.charCodeAt(i)` creates substantial single-byte iteration overhead (~276ms for 1,000 runs of 64KB payloads). Creating a direct `Uint8Array` view onto `Buffer.from(base64, 'base64')` achieves a ~3.2x–5.7x speedup (~48ms for 1,000 runs) and eliminates redundant `.slice()` array buffer clones when consumers need a `Uint8Array`.
**Action:** Standardize Base64/Base64Url decoding onto `base64ToUint8Array` across security key, integrity seal, and preference utilities.

## 2025-05-24 - Zero-Allocation Base64 Decoded Byte Length Calculation
**Learning:** Decoding Base64 strings to `ArrayBuffer` or `Uint8Array` solely to check `.byteLength` (e.g. validating cryptographic parameter lengths in package headers) causes needless allocations and GC pressure (~146ms for 100k operations). Validating the Base64 format and calculating byte length via bitwise arithmetic `(len * 3 >>> 2) - padding` eliminates allocations entirely and yields a ~14x speedup (~10ms for 100k operations).
**Action:** Use zero-allocation `base64ToByteLength` whenever validating Base64 parameter lengths without needing the actual decoded bytes.
