#!/usr/bin/env bash
#
# mayhem/build.sh — build the Kuroko VM's fuzz harness + oracle test suite.
#
# Kuroko (kuroko-lang/kuroko) is a small (~1MB) C-implemented bytecode VM for
# a Python-flavored scripting language. Its own upstream language-detection
# stat is dominated by the bundled `.krk` stdlib byte count, but the fuzzable
# core -- scanner, compiler, VM, object system, GC -- is all C under src/*.c.
#
# Two independent builds, on purpose (the dual-build pattern from the porting
# skill: upstream writes its own objects to its own in-place paths, so a
# hand-compiled sanitized build into a separate dir coexists with no
# make clean/stash dance):
#   1) ORACLE  -- upstream's OWN recipe (`make` then `make test`, exactly what
#      .github/workflows/build.yml runs), normal flags, writes objects to
#      src/*.o / modules/*.so / ./kuroko IN PLACE. mayhem/test.sh only RUNS it.
#   2) FUZZ    -- the same src/*.c sources, recompiled with $SANITIZER_FLAGS +
#      $DEBUG_FLAGS + `-fsanitize=fuzzer-no-link`, hand-compiled straight with
#      clang (bypassing the Makefile) into mayhem-build/*.o so it never
#      touches the oracle's src/*.o above.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# Relax ONLY the pointer-overflow UBSan check (keep ASan + the rest of UBSan
# halting). krk_resetStack() -- called from krk_initVM() before the VM's
# value stack has ever been grown -- computes
# `krk_currentThread.stack + krk_currentThread.stackSize` while `stack` is
# still NULL and `stackSize` is 0 (the stack grows lazily on first push, see
# krk_growStack() in src/vm.c). That is the standard "NULL + 0" bump-pointer
# idiom, legal in C, but -fsanitize=pointer-overflow reports it as
# "applying zero offset to null pointer" -- and because SANITIZER_FLAGS sets
# -fno-sanitize-recover=all, that aborts EVERY run at krk_initVM() time,
# before a single byte of fuzzed input is interpreted (0 edges, looks like a
# dead/broken harness). Same class of false-positive as the gfatools/xdelta
# cases documented in docs/netnew-worker-prompt.md §6. Appended unconditionally
# (even to an explicitly-empty SANITIZER_FLAGS, where it is a no-op).
SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=pointer-overflow"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${CXX:=clang++}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${AR:=ar}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# ---------------------------------------------------------------------------
# 1) ORACLE build (clean, unsanitized, upstream's own flags). Produces:
#      ./kuroko              -- the CLI, dynamically linked (functional oracle)
#      modules/*.so          -- fileio/os/math/random/time/json/threading/... --
#                               needed because test/*.krk import them
#      libkuroko.a/.so       -- unused here, but a harmless side effect of `make all`
#    `make test` (run by mayhem/test.sh, NOT here) diffs ./kuroko's real stdout
#    against test/*.krk.expect for all of upstream's own test scripts -- an
#    honest behavioral oracle, not just an exit-code check.
# ---------------------------------------------------------------------------
# CFLAGS is a make command-line override here, which means the Makefile's own
# `CFLAGS += -Isrc` (and everything else it would normally append) can no
# longer take effect -- so this string must be a COMPLETE flag set, not a delta.
#
# Serial (no -j): upstream's own top-level `all` target has an under-specified
# dependency edge -- modules/codecs/sbencs.krk only order-depends on `kuroko`,
# not on `modules/fileio.so`, yet its generator script does `import fileio` --
# so a parallel build can run the generator before fileio.so exists, and
# krk-* tool links can similarly race libkuroko.a. Upstream's own CI
# (.github/workflows/build.yml) just runs plain `make`, i.e. serial; do the
# same rather than fight the race with -j"$MAYHEM_JOBS".
make CFLAGS="-Isrc -g -O2 -Wall -Wextra -pedantic -Wno-unused-parameter ${COVERAGE_FLAGS}" LDFLAGS="-L. ${COVERAGE_FLAGS}"
[ -x ./kuroko ] || { echo "build.sh: oracle build did not produce ./kuroko" >&2; exit 1; }
file ./kuroko | grep -q 'dynamically linked' || { echo "build.sh: ./kuroko is not dynamically linked (the sabotage/LD_PRELOAD check needs this)" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 2) FUZZ build: recompile the library sources (everything under src/*.c
#    except kuroko.c, which is the CLI's own main()) with the sanitizer +
#    debug flags, PLUS two defines that sandbox the interpreter against the
#    filesystem (full rationale in mayhem/fuzz_interpret.c's header comment):
#      -DKRK_NO_FILESYSTEM           compiles out krk_runfile() and the
#                                     module search-path/dlopen resolution in
#                                     krk_loadModule() (src/vm.c) -- so a
#                                     fuzzed `import` statement always raises
#                                     ImportError instead of touching disk.
#      -DKRK_NO_SOURCE_IN_TRACEBACK  compiles out the fopen() a traceback
#                                     would otherwise do to echo the source
#                                     line (src/exceptions.c).
#    `-fsanitize=fuzzer-no-link` is appended UNCONDITIONALLY -- including when
#    SANITIZER_FLAGS is the empty/no-sanitizer build -- so the LIBRARY carries
#    SanCov coverage instrumentation; without it Mayhem records 0 edges even
#    though the harness itself builds and runs fine locally.
# ---------------------------------------------------------------------------
FUZZ_BUILD_DIR="$SRC/mayhem-build"
mkdir -p "$FUZZ_BUILD_DIR"

FUZZ_DEFS="-DKRK_NO_FILESYSTEM -DKRK_NO_SOURCE_IN_TRACEBACK"
FUZZ_CFLAGS="-Isrc $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $FUZZ_DEFS -Wno-unused-parameter"

fuzz_objs=()
for f in src/*.c; do
  case "$f" in
    src/kuroko.c) continue ;;   # has its own main(); not part of the library
  esac
  o="$FUZZ_BUILD_DIR/$(basename "${f%.c}").o"
  # shellcheck disable=SC2086
  "$CC" $FUZZ_CFLAGS -c "$f" -o "$o"
  fuzz_objs+=("$o")
done
"$AR" rcs "$FUZZ_BUILD_DIR/libkuroko_fuzz.a" "${fuzz_objs[@]}"

# ---------------------------------------------------------------------------
# 3) Harness: one fuzzer binary (linked against $LIB_FUZZING_ENGINE) and one
#    standalone (non-fuzzer) reproducer (linked against $STANDALONE_FUZZ_MAIN,
#    LLVM's run-once driver) -- both C, so no C++-mangling split compile is
#    needed (that trick is only required for a C++ harness TU).
# ---------------------------------------------------------------------------
mkdir -p /mayhem

# shellcheck disable=SC2086
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $FUZZ_DEFS -Isrc \
  $LIB_FUZZING_ENGINE \
  mayhem/fuzz_interpret.c "$FUZZ_BUILD_DIR/libkuroko_fuzz.a" \
  -lm -lpthread -ldl \
  -o /mayhem/fuzz_interpret

# shellcheck disable=SC2086
"$CC" $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $FUZZ_DEFS -Isrc \
  "$STANDALONE_FUZZ_MAIN" \
  mayhem/fuzz_interpret.c "$FUZZ_BUILD_DIR/libkuroko_fuzz.a" \
  -lm -lpthread -ldl \
  -o /mayhem/fuzz_interpret-standalone

[ -x /mayhem/fuzz_interpret ] || { echo "build.sh: fuzz_interpret was not produced" >&2; exit 1; }
[ -x /mayhem/fuzz_interpret-standalone ] || { echo "build.sh: fuzz_interpret-standalone was not produced" >&2; exit 1; }

echo "build.sh: OK -- ./kuroko (oracle), /mayhem/fuzz_interpret (fuzz), /mayhem/fuzz_interpret-standalone (repro)"
