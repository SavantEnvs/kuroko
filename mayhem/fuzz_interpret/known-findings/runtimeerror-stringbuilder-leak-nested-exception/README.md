# ASan: StringBuilder leak when krk_runtimeError()'s own formatting raises a nested exception

**Found via:** fuzzing (fork-mode retest, `-fork=4 -ignore_crashes=1 -ignore_ooms=1
-ignore_timeouts=1 -timeout=15 -rss_limit_mb=2560 -max_total_time=150` over the seed corpus).
This is the dominant finding class in an early 150s local fork-mode run: 611 distinct
"leak-*" artifacts, ALL at the identical allocation site (`krk_pushStringBuilder` ->
`krk_reallocate`, called from `krk_runtimeError`), while coverage/features kept climbing
throughout the run (`cov` 4938->5355, `ft` 16116->19566 over 150s) -- i.e. the HEALTHY case
per docs/netnew-worker-prompt.md §6c ("coverage keeps climbing across the crashes"), not the
flat/rediscovering-one-PC case that would warrant disabling the target. One root cause,
triggered by a wide variety of mutated inputs (any program whose source contains an
invalid-UTF-8 byte sequence near a syntax error).

## Reproduce

Minimized by libFuzzer's own `-minimize_crash_input=1` down to a **single byte**:

```
$ od -An -tx1 repro.krk
 ae
```

(`0xAE` is a bare UTF-8 continuation byte -- not valid at the start of a character, and
not part of any valid multi-byte sequence starting at this offset.)

```
./fuzz_interpret-standalone mayhem/fuzz_interpret/known-findings/runtimeerror-stringbuilder-leak-nested-exception/repro.krk
```

reports:

```
Direct leak of 32 byte(s) in 1 object(s) allocated from:
    #... krk_reallocate            src/memory.c:178
    #... krk_pushStringBuilder     src/obj_str.c:1091
    #... krk_pushStringBuilderFormatV  src/obj_str.c:1136
    #... krk_runtimeError          src/exceptions.c:474
    ... (via checkString -> allocateString -> krk_copyString -> finishError -> krk_compile)
SUMMARY: AddressSanitizer: 32 byte(s) leaked in 1 allocation(s).
```

Not committed to `mayhem/fuzz_interpret/testsuite/` -- like a hang, a seed that crashes on
the very first run also kills Mayhem's initial `-runs=5` sanity probe deterministically on
every future run (docs/netnew-worker-prompt.md, "A HANGING SEED IN testsuite/ BREAKS EVERY
RUN").

## Cause

`src/exceptions.c`, `krk_runtimeError()`:

```c
KrkValue krk_runtimeError(KrkClass * type, const char * fmt, ...) {
	KrkValue msg = KWARGS_VAL(0);
	struct StringBuilder sb = {0};

	va_list args;
	va_start(args, fmt);

	if (!strcmp(fmt,"%V")) {
		msg = va_arg(args, KrkValue);
	} else if (!krk_pushStringBuilderFormatV(&sb, fmt, args)) {
		return NONE_VAL();        /* <-- sb.bytes leaked here */
	}
	...
```

`krk_pushStringBuilderFormatV()` (`src/obj_str.c`) bails out early -- "Bail on exception" --
whenever formatting one `%`-directive itself triggers a nested exception (e.g. a `%s`
argument that turns out to be invalid UTF-8, which is exactly what `checkString()` in
`src/object.c` raises via its own `krk_runtimeError(vm.exceptions->valueError, "Invalid
UTF-8 sequence in string.")` call). When that happens, `krk_pushStringBuilderFormatV()`
returns falsy, and `krk_runtimeError()`'s caller-side `else if (!...)` branch returns
`NONE_VAL()` immediately -- without calling `krk_discardStringBuilder(&sb)` (or
`krk_finishStringBuilder`) to release whatever bytes had already been appended to `sb` for
the message being formatted. `sb.bytes` (a `KRK_GROW_ARRAY`-managed heap buffer, separate
from the GC-tracked object heap) is orphaned.

For the 1-byte repro specifically: the scanner rejects the lone `0xAE` as an unexpected
token, the compiler's `finishError()` (`src/compiler.c:442`) tries to echo the offending
source line into the exception object via `krk_copyString(token->linePtr, i)`, that call's
UTF-8 validity check (`checkString()`, `src/object.c:117`) rejects the raw `0xAE` byte and
itself calls `krk_runtimeError(valueError, "Invalid UTF-8 sequence in string.")` -- a
**nested** call to `krk_runtimeError()` while the **outer** `krk_runtimeError()` (raising the
original `SyntaxError`) is still mid-format. The nested call sets
`KRK_THREAD_HAS_EXCEPTION`, the outer `krk_pushStringBuilderFormatV()` sees that flag and
bails, and the outer call's partially-built `StringBuilder` leaks.

Because the trigger only requires "a syntax/format error whose message construction embeds
attacker-controlled bytes that happen to be invalid UTF-8," it is reachable from many
different fuzzer inputs (hence 611 distinct artifacts for what is a single root cause) --
essentially any malformed-enough random byte string.

## Impact

Memory leak (not memory corruption): each trigger leaks a small (typically 32-64 byte)
heap buffer. Not exploitable, but real and upstream, and cheap for a long-running embedder
(e.g. a REPL or server process linking libkuroko) to accumulate under adversarial or just
noisy input over time.

## Suggested upstream fix

In `krk_runtimeError()` (`src/exceptions.c`), discard the builder on the early-return path:

```c
} else if (!krk_pushStringBuilderFormatV(&sb, fmt, args)) {
	krk_discardStringBuilder(&sb);
	return NONE_VAL();
}
```

(`krk_discardStringBuilder` is already defined in `src/obj_str.c` and used elsewhere for
exactly this purpose -- this call site is simply missing it.)
