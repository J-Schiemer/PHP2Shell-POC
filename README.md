# PHP2Shell fix checker

> **Lab use only.** This project runs a deliberately vulnerable PHP/Apache
> container, sends memory-corruption traffic to it, and executes a harmless
> proof command (`id`) as the web worker. Run it only against containers you
> own. The CLI binds every lab port to `127.0.0.1`; do not point it at a remote
> host.

Differential test harness for the PHP2Shell fixes:

| CVE | Advisory | Confirmed path used here |
|---|---|---|
| CVE-2026-109618 | [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) | OOM during mod_php multipart startup leaves request state invalid |
| CVE-2026-109619 | [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp) | The next request on the same worker consumes stale session / executor globals |

Fixed releases: **8.2.35, 8.3.36, 8.4.27, 8.5.12**.

The harness always compares a **known-vulnerable control** with a **candidate**.
If the control cannot be exploited, the candidate result is `INCONCLUSIVE`,
never `PATCHED`. This prevents a broken offset or a changed heap layout from
being mistaken for a working fix.

## Quick start

Requirements: Docker with `linux/amd64` support (Docker Desktop on Apple
Silicon works through emulation), and [uv](https://docs.astral.sh/uv/).

```bash
uv sync

# Full self-test: 8.4.26 -> 8.4.27 (RCE) and 8.5.11 -> 8.5.12 (backtrace)
uv run php2shell-check selftest
```

Verify a candidate image:

```bash
uv run php2shell-check verify \
  --control php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a \
  --candidate php:8.4.27-apache@sha256:a0b75cee7023ba2c127138dcad2ecc6ec7e09435534645e70450f29f24ea2a5a
```

Exit codes:

| Code | Verdict |
|---|---|
| `0` | `FIX VERIFIED` — control vulnerable, candidate not vulnerable and healthy |
| `1` | `CANDIDATE VULNERABLE` — RCE or stale-session leak reproduced |
| `2` | `INCONCLUSIVE` — control failed, timeout, wrong SAPI, or unhealthy target |

Each run writes evidence to `out/runs/<timestamp>-.../`:

```text
control/
  a1.resp  b1.resp  a2.resp  b2.resp
  proof.txt
  out/
candidate/
  a1.resp  b1.resp
report.json
```

## Probes

### `verify` — 8.4 mod_php OOM + stale session

The engine reimplements the public PHP2Shell request shapes:

1. **A1** sends a chunked multipart body that exhausts the 128 MB request
   memory limit during upload-progress cleanup.
2. **B1** sends a second request that reaches the dangling `PS(id)` before
   normal session initialization and returns an oversized `Set-Cookie` — an
   out-of-bounds read of worker memory.
3. The leak is parsed for `zval_ptr_dtor` (1,095 occurrences in the reference
   layout) and the main ZendMM chunk (87 occurrences).
4. **A2** leaves the session verifier dangling.
5. **B2** places a fake `zend_array` whose `pDestructor` is `zif_system`, then
   the shutdown path runs `id > /out/<nonce>`.

`a1.resp`/`b1.resp` are saved; `proof.txt` is the command output.

### `backtrace` — 8.5 fatal backtrace + early INI diagnostic

This is the confirmed CVE-2026-109619 mod_php path:

1. `fatal_error_backtraces=1` is set administratively.
2. `/fatal.php` raises an uncaught exception; PHP stores the fatal backtrace in
   request memory.
3. `/consumer/index.php` has a `.htaccess` with an invalid `memory_limit`.
   mod_php applies that diagnostic before request initialization, which reaches
   the stale backtrace.
4. The probe reports a crash if the prefork worker is replaced or Apache logs a
   child exit / heap corruption.

The control is also run with `fatal_error_backtraces=0`; if the crash still
happens, it is not attributable to the backtrace and the result is
`INCONCLUSIVE`.

### `probe`

```bash
uv run php2shell-check probe --image <image> --probe leak
uv run php2shell-check probe --image <image> --probe rce
uv run php2shell-check probe --image <image> --probe backtrace
```

## Configuration

The lab uses a **single prefork worker** and `KeepAlive Off` so producer and
consumer requests always reach the same process without worker pinning. The
stock `php.ini-production` is copied into the image at start; the lab overrides
only:

```ini
session.save_path = "/tmp"
session.use_strict_mode = 0
session.use_cookies = 1
session.upload_progress.enabled = On
session.upload_progress.cleanup = On
max_input_vars = 100000
max_multipart_body_parts = -1
```

`memory_limit=128M`, `post_max_size=8M`, and `display_errors=Off` remain the
stock values the chain was calibrated against.

### Offsets

`zif_system` and `zval_ptr_dtor` are read from the target's
`libphp.so` at runtime (ELF symbol table). The two heap constants
(`S = main + 0xF8398`, main-cluster count `87`) are calibrated for the official
`php:8.4.26-apache` build. A candidate with a different allocator layout can
therefore fail the RCE stage; the leak oracle is independent of the symbol
offsets and remains the portable check.

### Image pinning

The defaults pin the exact multi-arch manifest digests that were validated.
Re-tagging or rebuilding the same PHP tag can move heap offsets; pin your own
digests when you extend the matrix.

### Use a paired control for custom builds

For a custom fix, pass the **unfixed build from the same source and config** as
`--control` and the fixed build as `--candidate`:

```bash
uv run php2shell-check verify \
  --control my-php:pre-fix \
  --candidate my-php:fixed
```

Comparing only against the stock 8.4.26 image is weaker: a candidate that
changes the allocator layout can fail the leak oracle for layout reasons rather
than because the fix works. A `PATCHED` verdict is only as strong as the control
and the matching configuration.

## "Both paths" and scope

- **8.4 path**: full chain, including a benign command execution proof.
- **8.5 path**: fatal-backtrace producer + early-INI consumer, crash/UAF oracle.
- **Not covered**: FPM, FrankenPHP, LSAPI, OPcache type confusion, and the
  application-specific producers described in the advisories. A pass on this
  harness is evidence about these two paths, not a proof that every variant of
  both CVEs is fixed.

## Roadmap

The 8.5 fatal-backtrace path currently ships as a crash/UAF oracle. Phase 0/1
established a stable mod_php offset, showed that the consumer does **not**
reclaim the slot before the dtor, and produced an in-process fake-array proof
that reaches `zif_system`. The FPM pivot confirmed the pre-startup
`PHP_VALUE`/`Authorization` window and found a binary-controlled 56-byte
allocation. A producer-side auth groom moves the backtrace to the low 56-byte
page, but the consumer allocation still lands at slot 0 while the producer
array is at slot 6/7; the FastCGI 65 KB param cap blocks the large-payload
alternative. The remote chain is therefore blocked, not merely uncalibrated.

Full details:

- [`references/8.5-rce-research-log.md`](references/8.5-rce-research-log.md) —
  consolidated log, grooming attempts, and the structural blocker
- [`references/8.5-rce-instrumentation.md`](references/8.5-rce-instrumentation.md) —
  mod_php Phase 0/1
- [`references/8.5-fpm-instrumentation.md`](references/8.5-fpm-instrumentation.md) —
  FPM pivot
- [`writeup/index.html`](writeup/index.html) — self-contained, nine-page
  interactive field guide with a continuous allegory and step simulations

The validated 8.4 RCE chain and the 8.5 crash oracle remain the supported
checks. The research backlog is tracked in
[`TODO-8.5-RCE.md`](TODO-8.5-RCE.md).

### Publishing the writeup

`writeup/index.html` is a self-contained static page with hash routing; it does
not need a build step. The repository includes [`wrangler.jsonc`](wrangler.jsonc),
which serves `writeup/` as Workers static assets. In a Workers Builds project,
set the build command to `exit 0` and the deploy command to
`npx wrangler deploy`. For Cloudflare Pages instead, use `writeup` as the build
output directory with no build command. [`writeup/_headers`](writeup/_headers)
adds baseline security headers in both setups.

## Manual lab

```bash
docker compose -f docker/compose.yaml --profile vuln84 up -d
docker compose -f docker/compose.yaml --profile fixed84 up -d
```

Ports: `18080` vuln 8.4, `18081` fixed 8.4, `18082` vuln 8.5, `18083` fixed
8.5. Tear down with:

```bash
docker compose -f docker/compose.yaml \
  --profile vuln84 --profile fixed84 --profile vuln85 --profile fixed85 down
```

## Attribution

The wire-level request shapes and heap calibration are based on the public
research PoC [`9bie/php2shell-bypass-aslr-exp`](https://github.com/9bie/php2shell-bypass-aslr-exp)
at commit `17e98ee81025cccfd94b4f9c9a17bf269c65ff75`. This repository
reimplements the builders in Python and adds the differential checker; the
upstream project has no license file, so it is referenced rather than vendored.
See `references/` for the advisories, fix commit, and provenance notes.

## Safety

- Containers are local-only, memory-limited, and run with
  `no-new-privileges`.
- The proof command is `id`; there is no reverse shell or persistence.
- The exploit traffic intentionally crashes or corrupts the worker. Do not run
  it against shared or production services.

## License

Released under the [MIT License](LICENSE). See [`NOTICE`](NOTICE) for upstream
attribution and the responsible-use notice.

## Imprint

<https://totallylegit.zip/dev/null/imprint>
