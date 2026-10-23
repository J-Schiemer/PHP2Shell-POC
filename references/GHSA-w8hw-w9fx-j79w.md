# GHSA-w8hw-w9fx-j79w — RCE via OOM corruption

- **CVE:** CVE-2026-109618
- **Severity:** Critical, CVSS v4.0 9.2
- **Published:** 2026-10-21
- **Package:** php-src (PHP)
- **Affected:** `< 8.2.35`, `< 8.3.36`, `< 8.4.27`, `< 8.5.12`
- **Patched:** 8.2.35, 8.3.36, 8.4.27, 8.5.12
- **Weaknesses:** CWE-416, CWE-755, CWE-824, CWE-1325, CWE-1419
- **Source:** https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- **Related:** https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

## Summary

PHP uses `longjmp()` for out-of-memory (OOM) errors to exit the current context
and abort handling of the request. In some contexts, request memory is
temporarily reachable before it is fully initialized. If any allocation fails at
that point, PHP does not properly account for the early exit and leaves the
request memory in an invalid state. The failed allocation does not need to be
related to the invalid memory. The request shutdown procedure may then read or
branch on it. Multiple OOM strategies can consistently trigger this condition
and lead to remote code execution.

## OOM strategies

Several multipart parsing problems can let a request reach OOM while remaining
within its apparent PHP limits:

- A multipart request without a usable declared content length may pass the
  initial `post_max_size` check and continue supplying decoded body data.
- A multipart part can contain an unrestricted number of headers. Representing
  these headers inside PHP can use substantially more memory than their wire
  representation, allowing a request within `post_max_size` to exhaust the
  normal `memory_limit`.
- Empty file controls do not count towards `max_file_uploads` but still create
  the normal file metadata arrays. Nested field names multiply the generated
  array work.

OOM can also be reached in application-specific ways when attacker-controlled
input causes a sufficiently large allocation or repeated memory use.

## Susceptibility

Apache mod_php unconditionally invokes the request shutdown procedure, even when
request startup has failed. During request startup, automatic body parsing can
exhaust the configured memory limit and exit the request in a context where
state is temporarily invalid. Shutdown then processes this invalid state. This
happens entirely before any application-specific code begins execution.

FPM exits the child when request startup fails. This prevents consumption of the
invalid state and removes the child from the pool. After normal startup, OOM may
still be reached in a context failing to account for an early exit, with the
invalid state being processed during request shutdown. Source analysis
therefore supports FPM as susceptible, though no complete FPM exploit was
demonstrated for this SAPI.

FrankenPHP is analogous to Apache mod_php and calls request shutdown
unconditionally, making it likely susceptible to application-independent
attacks. LSAPI models FPM, with application-specific exploits being likely but
unvalidated.

## Mitigation

Updating to a PHP release containing the patch is the **only complete
mitigation**. The patch removes `longjmp()` for OOM, replacing it with a delayed,
graceful soft OOM triggered at the next VM safe point, and an immediate hard OOM
using `_exit()` if memory consumption reaches a second, higher threshold. The
shutdown procedure no longer sees invalid state.

For installations that cannot update:

- Set and enforce `memory_limit=-1` administratively. This is not complete: if
  `mmap()` or another underlying allocation fails, PHP can still use
  `longjmp()`.
- Keep `post_max_size` conservative and independently enforce the decoded
  request size at the frontend.
- Reduce `max_input_nesting_level`, and bound the number of input variables,
  multipart parts, headers per part, and uploads.
- If the application does not use multipart form data, block such requests at
  the frontend.
- A container/cgroup memory limit may help but is not guaranteed to prevent
  allocation failure.
- Do **not** use `RLIMIT_AS` or `RLIMIT_DATA`; they cause `mmap()` to fail and
  trigger the vulnerable `longjmp()` path.

## Impact

The confirmed impact is unauthenticated remote code execution as the web worker
account. Complete RCE was validated over HTTP against mod_php with default PHP
input and memory limits and normal prefork configurations with multiple workers.
Additional workers and unrelated traffic can increase the required number of
attempts but do not remove the condition.

Exploit portability and reliability depend on the PHP build, extensions,
frontend behavior, and allocator layout.
