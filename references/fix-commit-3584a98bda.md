# Fix commit 3584a98bda

- **Commit:** `3584a98bda0f2c0d367255b046798b0d3a221a19`
- **Date:** 2026-10-18
- **Message:** `Avoid state corruption via bailout`
- **Fixes:** GHSA-w8hw-w9fx-j79w (CVE-2026-109618),
  GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
- **URL:** https://github.com/php/php-src/commit/3584a98bda0f2c0d367255b046798b0d3a221a19
- **Size:** 10,759 additions, 988 deletions (11,747 changed lines)

## Design notes

The change is deliberately broad because the root cause is a shared failure
pattern, not one parser bug:

- **Remove `longjmp()` for OOM.** OOM no longer bails out of the current
  context. A delayed, graceful soft OOM is stored in executor globals and
  triggered at the next VM safe point.
- **Hard memory limit.** If consumption crosses a second, higher threshold,
  PHP performs an immediate hard OOM with `_exit()`, so shutdown handlers do not
  run on invalid state.
- **Fallible allocations.** New `femalloc` / `fecalloc` / `ferealloc` /
  `safe_femalloc` APIs let callers return `NULL` instead of bailing out.
- **State reset before reuse.** Various globals that can be reached during
  request startup are reset, covering error, session, executor, object, and
  extension state.
- **Regression tests.** New `Zend/tests/oom_*.phpt` cases cover OOM during
  `SplFixedArray`, `array_fill`, `array_pad`, call frames, debug backtraces,
  exceptions, interrupts, JSON decoding, and hard-limit compilation failures.

The advisories state that the complete state reset—not only the OOM change—is
required; a partial backport that only changes `longjmp()` is not a complete
fix.

## Relevance to the checker

The 8.4.27 and 8.5.12 images used as candidates contain this commit. The
checker treats them as the first fixed releases, but a pass only covers the two
probes implemented here (mod_php OOM/session and mod_php fatal
backtrace/early-INI). It does not prove that every variant named in the
advisories is fixed.
