# Public PoC provenance

- **Repository:** https://github.com/9bie/php2shell-bypass-aslr-exp
- **Pinned commit:** `17e98ee81025cccfd94b4f9c9a17bf269c65ff75`
  (`exploit: pin one child under the official prefork workers`, 2026-10-22)
- **Observed stars at retrieval:** ~1,021
- **License:** none found in the repository (no `LICENSE` file). It is therefore
  referenced for research and **not vendored** into this project.

## What the upstream PoC demonstrates

The upstream README claims the following, with evidence logs in
`pure/evidence/`:

- Stock `php:8.4.26-apache`, stock `php.ini-production` (`display_errors=Off`,
  `memory_limit=128M`, `post_max_size=8M`), official prefork
  (`MaxRequestWorkers=150`): **10/10** successful RCE.
- Single-worker baseline: **20/20**.
- Roughly 3–4 seconds per run on native x86_64.
- No PHP/Apache build, no target-side files, no `session_start()`, no gdb in the
  delivery path.

The chain is:

1. Hold `MaxRequestWorkers - 1` partial POSTs so the four chain requests land on
   one prefork child.
2. Bypass `post_max_size` with `Transfer-Encoding: chunked`; without a
   `Content-Length`, the `rfc1867_post_handler` entry check is skipped.
3. **A1** OOM during upload-progress cleanup leaves dangling `PS(id)` /
   `PS(mod_data)`.
4. **B1** reaches the stale `PS(id)` and URL-encodes ~800 KB of worker memory
   into a `Set-Cookie`. The window contains the id chunk, the main ZendMM chunk,
   and `zval_ptr_dtor` pointers.
5. **A2** cheap-OOM leaves the session verifier dangling.
6. **B2** places a fake reference and a fake `zend_array` whose `pDestructor` is
   `zif_system`; shutdown calls `system()`.

The upstream offsets for the official image are:

| Symbol / location | Offset |
|---|---|
| `zval_ptr_dtor` | `libphp + 0x65EB60` |
| `zif_system` | `libphp + 0x465370` |
| fake array `S` | `main + 0xF8398` |
| A2 `hsv` | `main + 0x7D720` |

## How this project differs

- The request builders were reimplemented in
  `src/php2shell_check/payload.py`. They are byte-identical to the upstream
  builders for A1, B1, A2, the fake `zend_array`, and the fake-reference spray
  (verified by SHA-256).
- The engine does not use the upstream `--workers 150` pinning; the lab runs a
  single prefork worker with `KeepAlive Off`, which removes the multi-worker
  race and makes producer/consumer ordering deterministic.
- The leak parser is address-layout agnostic. Under QEMU user-mode emulation the
  guest heap pointers are in the `0x4000...` range, not the native `0x7f...`
  range. The parser derives `libphp` by checking `q - dtor_offset` for page
  alignment and then clusters the remaining pointers by 2 MB.
- The checker adds a negative control (`fatal_error_backtraces=0`) for the 8.5
  probe and an explicit `INCONCLUSIVE` result when the control fails.
- No upstream code or data is vendored; the upstream repository has no license.

## Safety and scope

The upstream tool is a full exploit. This repository uses the same primitives
only against loopback Docker containers, with a benign `id` proof, fixed image
digests, memory/CPU limits, and no persistence. Do not reuse it against systems
you do not own.
