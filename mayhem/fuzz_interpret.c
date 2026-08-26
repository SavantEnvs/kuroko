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
 * Watchdog: Kuroko has no language-level interrupt hook (unlike e.g. goja's
 * Runtime.Interrupt()) — a guest `while True: pass` or a pathological
 * recursive/allocating expression runs entirely as a native C loop inside
 * krk_interpret() with nothing to bound it but krk_setMaximumRecursionDepth()
 * (which only bounds call-stack depth, not e.g. a flat counting loop or a
 * huge string/list build-up). Per docs/netnew-worker-prompt.md §6b, DO NOT
 * use alarm()/SIGALRM: libFuzzer's own -timeout watchdog owns ITIMER_REAL,
 * and a harness alarm() silently swallows into libFuzzer's handler (or, if we
 * installed our own SIGALRM handler, permanently disables libFuzzer's own
 * timeout reporting). Use an INDEPENDENT POSIX per-process timer instead
 * (timer_create(CLOCK_MONOTONIC, ...) delivering SIGRTMIN+5), armed before
 * each krk_interpret() call and disarmed right after — exactly the pattern
 * that terminated the goja/ark equivalents in ~1.5s (exit 70) without
 * touching libFuzzer's own alarm.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <kuroko/kuroko.h>
#include <kuroko/vm.h>

/* Independent watchdog: a per-input hard budget, delivered via a realtime
 * signal libFuzzer does not use (it only arms ITIMER_REAL / SIGALRM). */
#ifndef MAYHEM_WATCHDOG_SIGNAL
#define MAYHEM_WATCHDOG_SIGNAL (SIGRTMIN + 5)
#endif
#ifndef MAYHEM_WATCHDOG_MS
#define MAYHEM_WATCHDOG_MS 1500L
#endif
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

static timer_t g_watchdog;
static int g_watchdog_ok = 0;

static void mayhem_watchdog_fire(int signo) {
	(void)signo;
	/* _exit(), not exit(): no atexit()/stdio flushing that could itself
	 * block or reenter a half-broken VM state. 70 == EX_SOFTWARE-ish,
	 * distinct from a plain crash so it is recognizable in triage. */
	_exit(70);
}

static void mayhem_watchdog_init(void) {
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = mayhem_watchdog_fire;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	if (sigaction(MAYHEM_WATCHDOG_SIGNAL, &sa, NULL) != 0) return;

	struct sigevent sev;
	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = MAYHEM_WATCHDOG_SIGNAL;
	sev.sigev_value.sival_ptr = &g_watchdog;
	if (timer_create(CLOCK_MONOTONIC, &sev, &g_watchdog) != 0) return;
	g_watchdog_ok = 1;
}

static void mayhem_watchdog_arm(long ms) {
	if (!g_watchdog_ok) return;
	struct itimerspec its;
	memset(&its, 0, sizeof(its));
	its.it_value.tv_sec = ms / 1000;
	its.it_value.tv_nsec = (ms % 1000) * 1000000L;
	timer_settime(g_watchdog, 0, &its, NULL);
}

static void mayhem_watchdog_disarm(void) {
	if (!g_watchdog_ok) return;
	struct itimerspec its;
	memset(&its, 0, sizeof(its));
	timer_settime(g_watchdog, 0, &its, NULL);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	(void)argc; (void)argv;
	mayhem_watchdog_init();
	return 0;
}

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

	mayhem_watchdog_arm(MAYHEM_WATCHDOG_MS);
	krk_interpret(src, "<mayhem>");
	mayhem_watchdog_disarm();

	krk_freeVM();
	free(src);
	return 0;
}
