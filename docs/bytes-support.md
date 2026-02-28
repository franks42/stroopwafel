# CEDN Bytes Support — Request for Feature

## Context

Stroopwafel is a capability-based authorization token library for Clojure
that uses CEDN (`com.github.franks42/cedn`) for deterministic serialization
of block payloads before Ed25519 signing and SHA-256 hashing.

Block payloads contain byte arrays (SHA-256 hashes linking blocks in a chain).
Currently CEDN throws `unsupported-type!` on byte arrays, forcing stroopwafel
to manually convert byte arrays to hex strings before calling
`cedn/canonical-bytes`. This workaround should not be necessary.

## What We Need

Add native byte array support to CEDN using a tagged literal:

```
#bytes "48656c6c6f"
```

- **Tag**: `#bytes`
- **Payload**: lowercase hex string, no prefix, no separators
- **Clojure type**: `byte[]` (JVM), `js/Uint8Array` (ClojureScript)

## Canonical Form

The canonical text representation of a byte array must be:

```
#bytes "0a1b2c3d"
```

Rules:
- Lowercase hex digits only (`0-9a-f`)
- No `0x` prefix
- No separators (no spaces, colons, or dashes)
- Empty byte array: `#bytes ""`
- Always even number of hex characters (each byte = 2 hex chars)

## Precedent

Biscuit (the authorization token spec that stroopwafel implements) uses
`hex:01A2` notation for byte arrays in its text representation. We adapt this
to EDN's tagged literal convention with `#bytes "..."`.

## Changes Required in CEDN

### 1. Emit (`cedn/emit.cljc`)

Add a clause in the `emit` function (before the `:else` fallthrough) to
handle byte arrays:

```clojure
;; JVM
(bytes? value)
(do
  (.append sb "#bytes \"")
  (.append sb (bytes->hex value))
  (.append sb \"))

;; ClojureScript — detect Uint8Array
```

The `bytes?` predicate already exists in Clojure core (checks for `byte[]`).
For ClojureScript, check `(instance? js/Uint8Array value)`.

### 2. Ordering (`cedn/order.cljc`)

Add byte arrays to the type ordering in `rank`. Suggested position:

```
nil < boolean < number < string < bytes < keyword < symbol < ...
```

For comparing two byte arrays: lexicographic unsigned byte comparison
(compare byte-by-byte as unsigned values, shorter array < longer array
if all shared bytes are equal).

### 3. Validation (`cedn/validate.cljc`)

Add byte arrays as a valid CEDN-P type. No size restrictions needed.

### 4. Data readers (optional but recommended)

Register `#bytes` as a data reader so that `clojure.edn/read-string` can
round-trip byte arrays:

```clojure
;; data_readers.cljc or equivalent
{bytes cedn.readers/read-bytes}
```

Where `read-bytes` parses a hex string into a byte array.

## Cross-Platform

This must work on all CEDN target platforms:

| Platform | Byte array type | `bytes?` check |
|----------|----------------|----------------|
| JVM | `byte[]` | `(bytes? x)` |
| Babashka | `byte[]` | `(bytes? x)` |
| ClojureScript/nbb | `js/Uint8Array` | `(instance? js/Uint8Array x)` |
| Scittle (browser) | `js/Uint8Array` | `(instance? js/Uint8Array x)` |

## Test Vectors

Add these to the CEDN compliance tests:

```clojure
;; empty
(cedn/canonical-str (byte-array []))
;=> "#bytes \"\""

;; single byte
(cedn/canonical-str (byte-array [0]))
;=> "#bytes \"00\""

;; typical SHA-256 hash (32 bytes)
(cedn/canonical-str (byte-array [0x2c 0xf2 0x4d 0xba]))
;=> "#bytes \"2cf24dba\""

;; high bytes (> 127, signed in Java)
(cedn/canonical-str (byte-array [0xff 0x00 0x80]))
;=> "#bytes \"ff0080\""

;; byte arrays in maps (sorted correctly relative to other types)
(cedn/canonical-str {:a 1 :b (byte-array [0xde 0xad])})
;=> "{:a 1 :b #bytes \"dead\"}"

;; ordering: two byte arrays
;; [0x00 0x01] < [0x00 0x02]
;; [0x01] < [0x01 0x00]

;; determinism
(let [bs (byte-array [1 2 3])]
  (= (cedn/canonical-bytes {:prev bs})
     (cedn/canonical-bytes {:prev bs})))
;=> true
```

## Version

Publish as CEDN `1.2.0` (minor version bump — new feature, backwards
compatible). After publishing, stroopwafel will update its dep and remove
the `prepare-for-serialization` workaround.
