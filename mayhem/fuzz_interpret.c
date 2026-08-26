/**
 * mayhem/fuzz_interpret.c — libFuzzer harness for the Kuroko bytecode VM.
 *
 * Feeds raw fuzzer bytes straight to krk_interpret(), the same entry point
 * src/kuroko.c's REPL/`-c`/file-exec paths all funnel through (see runString()
 * and the `runCmd` handling in main()). This exercises the full pipeline:
 * scanner -> compiler -> bytecode VM -> object system (str/list/dict/tuple/
 * set/bytes/long/generators/exceptions) -> GC.
 *
 * No file I/O: the library is built (see mayhem/build.sh) with
 * -DKRK_NO_FILESYSTEM -DKRK_NO_SOURCE_IN_TRACEBACK, which compiles out every
 * fopen()/stat()/dlopen() path in the VM (krk_runfile, module search-path
 * resolution, and the traceback source-line printer). `import` statements in
 * fuzzed source therefore always raise ImportError instead of touching disk —
 * verified by grep (fopen, dlopen, system) against every source file under
 * src/. We also
 * pass KRK_GLOBAL_NO_DEFAULT_MODULES to krk_initVM so no "kuroko"/"threading"
 * builtin module is registered (no host bindings beyond the bare language).
 *
 * No timer or watchdog: a guest infinite loop is a hang finding, bounded by
 * Mayhem's per-exec timeout (Mayhemfile `timeout:`) and libFuzzer's -timeout.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <kuroko/kuroko.h>
#include <kuroko/vm.h>

/* Guest programs may legitimately want a slightly deeper call stack than the
 * VM's compiled-in default (KRK_CALL_FRAMES_MAX), but we still want a hard
 * ceiling so a runaway recursive function fails fast as a stack-depth
 * exception rather than eating the whole per-input budget. */
#ifndef MAYHEM_MAX_RECURSION
#define MAYHEM_MAX_RECURSION 256
#endif
/* Keep individual runs fast; nothing about Kuroko's grammar needs a
 * multi-megabyte source file to explore new code paths. */
#ifndef MAYHEM_MAX_INPUT
#define MAYHEM_MAX_INPUT (64 * 1024)
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size == 0 || size > MAYHEM_MAX_INPUT) return 0;

	/* Kuroko source is a NUL-terminated C string (the scanner walks it with
	 * no explicit length), and a real Kuroko source file cannot itself
	 * contain a NUL byte (the scanner treats it as EOF) — so reject inputs
	 * with an embedded NUL rather than silently truncating what the fuzzer
	 * generated, which would waste it exploring a prefix repeatedly. */
	if (memchr(data, 0, size) != NULL) return 0;

	char *src = (char *)malloc(size + 1);
	if (!src) return 0;
	memcpy(src, data, size);
	src[size] = '\0';

	/* CLEAN_OUTPUT suppresses krk_dumpTraceback()'s stderr write on an
	 * uncaught guest exception (vm.c handleException()). Undefined-variable/
	 * bad-import/etc. exceptions are expected outcomes for arbitrary fuzzed
	 * source, not bugs, but Mayhem's triager pattern-matches the printed
	 * "Traceback (most recent call last):" text as a crash and files it as
	 * an "Uncaught Exception" defect. */
	krk_initVM(KRK_GLOBAL_NO_DEFAULT_MODULES | KRK_GLOBAL_CLEAN_OUTPUT);
	krk_setMaximumRecursionDepth(MAYHEM_MAX_RECURSION);
	krk_startModule("__main__");

	krk_interpret(src, "<mayhem>");

	krk_freeVM();
	free(src);
	return 0;
}
