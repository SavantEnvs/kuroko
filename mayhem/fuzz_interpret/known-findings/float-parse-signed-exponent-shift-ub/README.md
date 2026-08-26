# UBSan: signed left-shift overflow in float-string parsing (src/obj_long.c:1432)

**Found via:** upstream's own `test/testParseFloat.krk` (line 5), replayed through the
`fuzz_interpret` harness under the project's `$SANITIZER_FLAGS` build (ASan+UBSan, halting).
Not a fuzzer-discovered novel input -- it was already present in upstream's own committed
test corpus, which is why it is filed here as a known-findings note instead of shipped in
`mayhem/fuzz_interpret/testsuite/`: a seed that crashes the harness on the very first run
also breaks Mayhem's initial `-runs=5` sanity probe, the same way a hanging seed does
(see docs/netnew-worker-prompt.md, "A HANGING SEED IN testsuite/ BREAKS EVERY RUN").

## Reproduce

```
$CC $SANITIZER_FLAGS -gdwarf-3 -fsanitize=fuzzer-no-link \
    -DKRK_NO_FILESYSTEM -DKRK_NO_SOURCE_IN_TRACEBACK -Isrc \
    "$STANDALONE_FUZZ_MAIN" mayhem/fuzz_interpret.c <sanitized libkuroko objects> \
    -lm -lpthread -ldl -o fuzz_interpret-standalone
./fuzz_interpret-standalone mayhem/fuzz_interpret/known-findings/float-parse-signed-exponent-shift-ub/repro.krk
```

Minimal input (one line, isolated by bisecting testParseFloat.krk):

```
print(float('-123431236.632163e-3'))
```

## Cause

`obj_long.c`'s decimal-string -> `double` conversion builds the IEEE-754 bit pattern by hand.
Near the end of that routine (obj_long.c:1425-1432):

```c
/* Apply sign */
if (negative) exp |= 2048;

/* Mash bits together to form double */
quot ^= 1ULL << 52;
quot |= exp << 52;                 // <-- obj_long.c:1432
```

`exp` is a signed integer type (`long long`/`int` per the surrounding arithmetic). For a
negative input, `exp |= 2048` sets bit 11, and the observed failing value is `exp == 3087`
(0b110000001111). `exp << 52` then places a set bit at position `52 + 11 = 63` -- the sign
bit of a 64-bit signed type -- which C considers undefined behavior (the shifted value
cannot be represented in the signed result type), even though on every real two's-complement
target the actual bit pattern produced is exactly the one intended (this is a standard
"build a double via integer bit-twiddling" idiom that silently relies on wraparound).
UBSan's `-fsanitize=shift` correctly flags the UB; the observed program behavior is not
affected by it under `-fsanitize-recover=undefined` (this is a `-fno-sanitize-recover=all`
build), but it is a HALT under our harness because the base image sets that flag globally
for every target, so this input aborts the process.

Only reached on a `float()` string parse whose decimal exponent lands in the subnormal or
saturated-exponent range for the constructed `double` (`negative` sign set + `exp` large
enough after the earlier saturation/subnormal clamping a few lines up) -- i.e. this specific
minimal repro needs BOTH a negative sign and an exponent value that clamps to the observed
`exp == 3087` after the `if (exp > 2046) ... else if (exp < 1 && exp >= -52) ...` branch
above it.

## Impact

Reliability/UB only (not a memory-safety bug): under our ASan+UBSan-halting build this
aborts the process (a libFuzzer-recorded UBSan finding) rather than corrupting memory; under
a build without `-fno-sanitize-recover=all` it silently "works" via signed-overflow
wraparound. Still worth fixing -- relying on signed left-shift into the sign bit is
technically UB and not guaranteed portable (e.g. could be miscompiled by a sufficiently
aggressive optimizer that assumes no UB).

## Suggested upstream fix

Do the bit-packing arithmetic in an unsigned type, e.g.:

```c
quot |= (uint64_t)exp << 52;
```

(`quot` is already `uint64_t`/`unsigned long long` per its use as the mantissa accumulator;
promoting `exp` to unsigned before the shift removes the UB with no behavior change on
two's-complement targets, which is every target this project ships for.)
