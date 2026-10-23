# Lab verification record

Validated on 2026-10-23 on Docker Desktop (aarch64 host) using
`--platform linux/amd64` (QEMU user-mode emulation).

## Images

| Role | Image | Digest |
|---|---|---|
| 8.4 vulnerable | `php:8.4.26-apache` | `sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a` |
| 8.4 fixed | `php:8.4.27-apache` | `sha256:a0b75cee7023ba2c127138dcad2ecc6ec7e09435534645e70450f29f24ea2a5a` |
| 8.5 vulnerable | `php:8.5.11-apache` | `sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b` |
| 8.5 fixed | `php:8.5.12-apache` | `sha256:e25ab14ef2cfec3bab9dd66c6cf871691146f428fbd72241b1a2c38fcacf92f5` |

All four are Debian 13 (trixie), Apache 2.4.69 prefork, mod_php, NTS.

## 8.4 path — OOM + stale session

Command:

```bash
uv run php2shell-check verify \
  --control php:8.4.26-apache \
  --candidate php:8.4.27-apache --attempts 3
```

Result:

```text
[control] php:8.4.26-apache
[control] VULNERABLE_RCE proof=uid=33(www-data) gid=33(www-data) groups=33(www-data)
[candidate] php:8.4.27-apache
[candidate] no leak: no stale-session leak after 3 attempts: A1 returned HTTP 200
[candidate] PATCHED
verdict: FIX VERIFIED
```

Representative leak on 8.4.26 under QEMU:

```text
decoded_len: 819208
zval_ptr_dtor: 0x40060f7b60  (1095 occurrences)
libphp:        0x4005a99000
main_chunk:    0x4008000000  (87 occurrences)
zif_system:    0x4005efe370
fake_array:    0x40080f8398
clusters:      0x4019200000:7495, 0x4008000000:87, 0x4019800000:79
```

The same run on native x86_64 would use `0x7f...` pointers; the parser does not
assume either range.

## 8.5 path — fatal backtrace + early INI diagnostic

Command:

```bash
uv run php2shell-check backtrace \
  --control php:8.5.11-apache \
  --candidate php:8.5.12-apache
```

Result:

```text
[control] php:8.5.11-apache with fatal_error_backtraces=1
[control] VULNERABLE_CRASH
[control] php:8.5.11-apache with fatal_error_backtraces=0
[control] NO_CRASH
[candidate] php:8.5.12-apache with fatal_error_backtraces=1
[candidate] NO_CRASH
verdict: FIX VERIFIED
```

Producer: `GET /fatal.php?mode=user_error` (`E_USER_ERROR`).
Consumer: `GET /consumer/index.php` with `.htaccess` containing
`php_value memory_limit 999999999999999999999`.

Control log on 8.5.11:

```text
PHP Fatal error:  p2s-backtrace-producer in /var/www/html/fatal.php on line 5
Stack trace:
#0 /var/www/html/fatal.php(5): trigger_error()
#1 {main}
zend_mm_heap corrupted
[core:notice] [pid 1] AH00052: child pid 47 exit signal Abort (6)
```

Negative controls:

- Same image, same producer, `fatal_error_backtraces=0`: only the
  `Invalid "memory_limit"` startup warning; worker stays alive.
- 8.5.12 with `fatal_error_backtraces=1`: only the startup warning; worker
  stays alive.

Other producer modes tested on 8.5.11:

| Producer | Result |
|---|---|
| `E_USER_ERROR` | crash (used) |
| OOM (`str_repeat` 200 MB) | crash, but not backtrace-specific |
| `require` missing file | no crash |
| uncaught `RuntimeException` | no crash |
| parse error file | no crash |

The `E_USER_ERROR` producer is the one used by the checker because it is
specific: the `fatal_error_backtraces=0` control proves the crash depends on the
stale backtrace state.

## Final self-test evidence

```text
out/runs/20261023-123611-verify-5f5477/report.json       -> FIX VERIFIED (0)
out/runs/20261023-123615-backtrace-8f0fcb/report.json    -> FIX VERIFIED (0)
```

The 8.4 control proof file contains:

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

