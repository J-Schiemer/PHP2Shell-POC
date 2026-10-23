# TODO — 8.5 fatal-backtrace path to true RCE

Status: research backlog
Current state: `8.5.11 + fatal_error_backtraces=1 + .htaccess warning` is a reliable
`VULNERABLE_CRASH`; `8.5.12` is `NO_CRASH`; neither stock image executes code.

Consolidated research log:
[`references/8.5-rce-research-log.md`](references/8.5-rce-research-log.md).

Phase 0 and Phase 1 are complete (2026-10-23): the stale array offset is stable,
the slot is **not** reclaimed before the consumer dtor, and an in-process fake
array proves the dtor can reach `zif_system`. That proof is instrumentation-only;
no remote reclaim primitive was found. See
[`references/8.5-rce-instrumentation.md`](references/8.5-rce-instrumentation.md).

This is deliberately separate from the validated 8.4 RCE chain and the default
8.5 crash oracle. Do not ship an 8.5 RCE stage until Phase 4 is repeatable.

## Ground truth

- 8.5.11’s fast shutdown path (`zend_execution_API.c`, around
  `zend_shutdown_executor_values`) skips the `last_fatal_error_backtrace`
  reset because it is inside `if (!fast_shutdown)`.
- 8.5.12 adds, after `zend_objects_store_free_object_storage()`:

  ```c
  /* may be used by zend_error_zstr_at before init_executor */
  ZVAL_UNDEF(&EG(last_fatal_error_backtrace));
  ```

  It clears the pointer without freeing it; the request heap is already gone.
- On 8.5.11, the next request’s `.htaccess` warning reaches
  `zend_error_zstr_at()` before `init_executor()`. That function starts with:

  ```c
  zval_ptr_dtor(&EG(last_fatal_error_backtrace));
  ZVAL_UNDEF(&EG(last_fatal_error_backtrace));
  ```

  and therefore calls `zend_array_destroy()` on the freed backtrace array.
- The crash is the array/frame dtor walking corrupted/freed memory, not yet a
  controlled call.
- Observed 8.5.11 offsets in this lab:

  | Symbol | Offset |
  |---|---|
  | `zval_ptr_dtor` | `0x7b47a0` |
  | `zif_system` | `0x5996e0` |

  These differ from 8.4.26 (`0x65eb60`, `0x465370`).
- The 8.4 A1/B1 stale-session leak does **not** reproduce unmodified on
  8.5.11, including with `fatal_error_backtraces=0`.
- The backtrace can contain object arguments (`zend.exception_ignore_args=0`).
  A test with `fatal.php?mode=object` shows `Object(P2SBacktraceProbe)` in the
  fatal log, but the consumer aborts before the object destructor runs.

## Phase 0 — Instrumentation and measurement

- [x] **T0.1** Add `docker/Dockerfile.85-debug` from
  `php:8.5.11-apache` with `gdb`, `gcc`, `make`, `autoconf`, and the PHP
  headers/`phpize` needed for a tiny inspection extension.
  **Result:** image also built for 8.5.12; actual build uses
  `research/build_85_debug.sh` (amd64 container + commit) because this Docker
  install has no buildx. `gdb` attaches only on native arm64; qemu-user returns
  `ENOSYS` for `PTRACE_ATTACH`.
- [x] **T0.2** Add a lab-only inspection extension (or gdb script) that logs,
  at producer RSHUTDOWN and at consumer `zend_error_zstr_at`:
  `EG(last_fatal_error_backtrace)` type/value, `Z_ARRVAL(...)`, refcount,
  chunk base, chunk offset, `arData`, `nNumUsed`, `pDestructor`, and the
  frame/args addresses.
  **Result:** `research/85probe/p2s85probe.c` (extension) plus
  `research/85probe/p2s85-preload.c` (LD_PRELOAD; interposes
  `zend_error_zstr_at`, `zval_ptr_dtor`, request startup/shutdown, and the
  56-byte allocator).
- [x] **T0.3** Run the producer (`/fatal.php?mode=user_error`) and consumer
  (`/consumer/index.php`) three times; normalize addresses by the 2 MB chunk
  base and confirm the stale array offset is stable.
  **Result:** top-level `+0x5a150`, frame `+0x5a118`, args `+0x5a188`, 3/3
  fresh workers, chunk `0x4008e00000` (8.5.11/QEMU). The health request must
  precede the producer, as in the checker, or the first offset can differ by
  one 56-byte slot.
- [x] **T0.4** Determine the exact allocation size/bin of the backtrace array and
  its frame/args arrays. Confirm the 8.5 `zend_array` layout used by
  `payload.build_ht()` (`pDestructor` at `0x30`, `arData` at `0x10`).
  **Result:** all three headers are 56-byte `_emalloc_56` blocks; layout
  confirmed. Top-level is packed (`flags=0x14`, `nTableSize=8`), frame is a
  static-key hash (`flags=0x10`, 4 elements).
- [x] **T0.5** Trace which allocation, if any, reclaims the freed array slot
  between producer shutdown and the consumer warning. Log ZendMM
  alloc/free and/or use a gdb watchpoint.
  **Result:** **none.** The header is byte-identical at producer RSHUTDOWN and
  at the consumer dtor (3/3). `P2S85_WATCH` shows no 56-byte alloc/free at the
  slot after producer shutdown. The crash is a double free of the stale
  array's nested frame/args/`arData`. The consumer warning runs **before**
  `php_request_startup()`; its own allocations happen after the dtor.
- [x] **T0.6** Document the findings in
  `references/8.5-rce-instrumentation.md`.
  **Result:** complete; evidence under `out/test85/phase0/`.

**Done when:** three runs give the same chunk-relative stale-array offset and we
know exactly what writes that slot before the consumer dtor.
**Status: met — nothing writes it; the same stale bytes are destroyed.**

## Phase 1 — Instrumented control proof

Goal: prove the consumer can call `zif_system` if the stale zval points at a
controlled fake array. This is a lab proof, not a remote exploit.

- [x] **T1.1** Build a fake 56-byte `zend_array` at a known address with the
  8.5 layout: `gc` rc=1/type=IS_ARRAY, `arData` → fake execute data, and
  `pDestructor = zif_system`.
  **Result:** `build_fake()` in `research/85probe/p2s85-preload.c`; static
  in-process buffer at `0x40028fb080`.
- [x] **T1.2** Reuse/adapt the B2 fake-array and fake-string layout from
  `payload.build_ht()` for an array placed at the stale slot address.
  **Result:** same offsets (`gc`, `arData 0x10`, `pDestructor 0x30`, fake
  execute data at `0x20`, fake zend_string at `0x80`).
- [x] **T1.3** In the inspection extension’s producer RSHUTDOWN, replace
  `EG(last_fatal_error_backtrace)` with the fake array (or write the fake
  bytes into the freed slot) and let the consumer warning dtor it.
  **Result:** done in the preload at the consumer dtor instead, because a
  producer-side write would be reset by `shutdown_memory_manager()`.
- [x] **T1.4** Verify `id > /out/rce85-instrumented-proof` is written by the
  consumer. If `zend_array_destroy()` tries to `efree()` the fake array, adjust
  GC/flags/`arData` to avoid the free.
  **Result:** 3/3 on 8.5.11; `uid=33(www-data) ...`; worker then aborts, as
  expected for a fake static array.
- [x] **T1.5** Run the same proof against 8.5.12; expect no proof and no crash.
  **Result:** 0/3 proof, consumer zval `UNDEF`, no crash, worker survives.
  Also 0/3 with `fatal_error_backtraces=0` on 8.5.11.

**Done when:** instrumented 8.5.11 executes the benign command and 8.5.12 does
not. **Status: met, with the caveat that this is an in-process proof.**

**Critical limit:** the consumer warning runs before `php_request_startup()`;
no attacker-controlled ZendMM allocation happens before the dtor, and the slot
is not reclaimed. The instrumented proof therefore does not establish a remote
primitive. Phase 3 must find a different early consumer (or producer-side
persistence) before Phase 4 can be attempted.

## Phase 2 — Remote heap leak on 8.5.11

Phase 0 finding to carry into T2.3/T2.4: the stale top-level array is in a 2 MB
chunk at `0x4008e00000` (QEMU), **not** the `0x4008000000` chunk used by the 8.4
`S` offset. The leak parser must identify that chunk and the 8.5 profile, not
reuse `S_OFFSET=0xF8398`. The 8.5 top-level slot is `chunk+0x5a150`.

- [ ] **T2.1** Recalibrate the 8.4 A1/B1 leak for 8.5.11 with
  `fatal_error_backtraces=0`; sweep `--big` (60–100), query length/name shape,
  `--fillers128`, `--burners`, and progress length. Keep an automated sweep
  under `research/85_leak_sweep.py`.
- [ ] **T2.2** If the session leak does not reproduce, try a session
  upload-progress leak or another `Set-Cookie` OOB read that returns >8 KB.
- [ ] **T2.3** Recover `libphp` and the main chunk with the 8.5 symbol offsets;
  validate page alignment and cluster counts.
- [ ] **T2.4** Add an 8.5-specific `Offsets`/layout profile if the 8.4 constants
  do not apply.

**Done when:** 8.5.11 leaks the main chunk and libphp 3/3; 8.5.12 leaks nothing.

## Phase 3 — Controlled reclaim without instrumentation

**Blocked premise (T0.5):** the mod_php `.htaccess` consumer emits its warning
before `php_request_startup()`, and the stale 56-byte header is **not**
reclaimed between producer shutdown and the dtor. There is no observed
attacker-controlled allocation before `zend_error_zstr_at()`. T3.1/T3.4 must
therefore start by finding a different early consumer, not by assuming the
existing one has a reclaim window.

**FPM pivot (2026-10-23):** measured in
[`references/8.5-fpm-instrumentation.md`](references/8.5-fpm-instrumentation.md).
FPM's `init_request_info()` applies `PHP_VALUE` and parses
`HTTP_AUTHORIZATION` **before** `php_request_startup()`, so the pre-startup
warning/crash reproduces 3/3 on 8.5.11 FPM (top-level `chunk+0x5c150`,
`zif_system` `0x400060e3a0`, `zval_ptr_dtor` `0x4000829460`). The extension
fake-array proof also reaches `zif_system` 3/3, and 8.5.12 is 0/3.

`HTTP_AUTHORIZATION` gives a binary-safe, attacker-controlled 56-byte
allocation (`auth_user`, `estrndup` of the decoded Basic payload) before the
dtor. However, it lands at `0x4006404000` while the stale slot is
`0x400645c150`: `shutdown_memory_manager()` rewinds the 56-byte free tail to the
start of the chunk, so the slot is ~90 pages away. With the auth payload in
`log` mode the consumer still crashes on the original array and writes no proof
(0/3); in `clear` mode the slot header is unchanged 3/3. A remote chain needs a
producer-side groom that moves the slot into the first 56-byte page, or a
repeatable pre-auth binary spray (auth is once per request).

**Groom result (2026-10-23):** a producer `HTTP_AUTHORIZATION` does move the
backtrace to the low page (`chunk+0x4150`), but it lands at slot 5/6 while the
consumer `auth_user` lands at slot 0 and `init_request_info()` only has a few
pre-auth 56-byte allocations. The five producer request-startup hash tables do
not exist before the consumer's `php_request_startup()`, so the slot gap is
structural. The FastCGI 65 KB per-value cap also prevents the large-auth UAF.
No remote 8.5 RCE was achieved; see the FPM doc.

- [ ] **T3.1** Using Phase 0’s offset, enumerate producer/intermediate
  allocations that can write a 56-byte fake array at the stale address.
  **T0.5 result:** none in the current path; retarget this task.
- [ ] **T3.2** Try the object-argument path with a shallow stack:
  `fatal.php?mode=object`, `zend.exception_ignore_args=0`, varied object
  size/class. Check whether `__destruct` runs in the consumer (proof file).
- [ ] **T3.3** Try a three-stage groom: producer fatal → intermediate request
  that reclaims the array/object slot → consumer warning. Account for the fact
  that a normal intermediate request calls `init_executor()` and clears the
  global; use a request that fails before that point or an early consumer.
- [ ] **T3.4** Try an early consumer with attacker-controlled allocations:
  FPM `PHP_VALUE` / `PHP_ADMIN_VALUE`, session upload progress, or an
  application-level `auto_prepend_file` warning. Record the request ordering.
- [ ] **T3.5** Iterate with a harmless marker first (`pDestructor` points to a
  marker function or `zif_system("id>/out/...")`) until the consumer reaches
  the controlled code.

**Done when:** a consumer request executes controlled code without an
instrumentation extension.

## Phase 4 — Full 8.5 RCE chain

- [ ] **T4.1** Combine leak + reclaim + fake array/object →
  `zif_system("id>/out/rce85-proof")`.
- [ ] **T4.2** Run 5/5 on 8.5.11 and 0/5 on 8.5.12, with target health checks.
- [ ] **T4.3** Record attempts, time, required config
  (`fatal_error_backtraces=1`, `exception_ignore_args=0`, mod_php, single
  worker), and failure modes.
- [ ] **T4.4** Add paired-control semantics: pre-fix control must succeed or the
  candidate result is `INCONCLUSIVE`.
- [ ] **T4.5** Update `references/lab-verification.md` and the README with the
  new evidence and limitations.

**Done when:** the 8.5 path is a repeatable, no-instrumentation RCE proof in the
lab and the fixed image is clean.

## Phase 5 — Checker integration (optional)

- [ ] **T5.1** Add an opt-in command/probe, e.g.
  `php2shell-check verify85-rce` or
  `php2shell-check probe --probe backtrace-rce`. Do not replace the crash
  oracle as the default.
- [ ] **T5.2** Keep `backtrace` (crash/UAF) as the stable 8.5 regression; label
  the RCE stage as target-specific.
- [ ] **T5.3** Add unit/integration tests: fake-array builder, leak parser,
  8.5.12 negative, and a no-instrumentation assertion.
- [ ] **T5.4** Run the full `selftest` and confirm the 8.4 RCE chain is
  unaffected.
- [ ] **T5.5** Document that an 8.5 RCE pass depends on the exact image,
  allocator layout, and early consumer; it is not a generic remote check.

## Guardrails

- Localhost Docker only; pinned image digests; benign `id` proof; no reverse
  shell or persistence.
- Keep `docker/php-lab.ini` unchanged for the validated 8.4 chain. Use
  `docker/php-85.ini` / the 8.5 temp ini for
  `fatal_error_backtraces` and `exception_ignore_args`.
- After every change, run:

  ```bash
  uv run python -m unittest discover -s tests -v
  uv run php2shell-check selftest
  ```

- Keep the existing 8.5 crash oracle until Phase 4 passes 5/5.

## Open decisions

1. Is an **instrumented proof** enough, or is a no-instrumentation remote chain
   required?
   **Evidence (Phase 0/1):** the instrumented proof works 3/3, but the slot is
   not reclaimed and the consumer warning pre-dates request startup. The
   no-instrumentation chain is not currently supported by this consumer.
2. mod_php first, or pivot to FPM where the early consumer may be easier to
   control?
   **Evidence:** mod_php's `.htaccess` diagnostic is strictly pre-startup. FPM
   applies `PHP_VALUE`/`PHP_ADMIN_VALUE` in `init_request_info()` before
   `php_request_startup()` and also parses `HTTP_AUTHORIZATION` there. It gives
   a real binary-controlled pre-startup 56-byte allocation, but not at the
   stale slot (see the FPM pivot note above). FPM is the better research
   platform; the reclaim still needs grooming.
3. Should the final checker include an 8.5 RCE stage at all, or keep the crash
   oracle as the stable regression?
   **Recommendation:** keep the crash oracle as the default. Do not ship an 8.5
   RCE stage based on an in-process redirect.
