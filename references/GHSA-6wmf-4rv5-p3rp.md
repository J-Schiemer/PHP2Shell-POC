# GHSA-6wmf-4rv5-p3rp — RCE via stale global state

- **CVE:** CVE-2026-109619
- **Severity:** Critical, CVSS v4.0 9.2
- **Published:** 2026-10-21
- **Package:** php-src (PHP)
- **Affected:** `< 8.2.35`, `< 8.3.36`, `< 8.4.27`, `< 8.5.12`
- **Patched:** 8.2.35, 8.3.36, 8.4.27, 8.5.12
- **Weaknesses:** CWE-416, CWE-755, CWE-824, CWE-1325, CWE-1419
- **Source:** https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
- **Related:** https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w

## Summary

PHP contains various global state, such as error, session, object and extension
state that is retained by a worker but points to memory owned by one request.
That state must be reset before the request memory is released. Some input,
configuration, session and error handling operations run before normal
initialization of the next request. They inadvertently access stale state not
reset by the previous request before initialization has a chance to replace it,
causing a use-after-free. A strategically crafted heap layout can produce full
remote code execution.

State can survive for more than one reason. A fatal error, including one caused
by memory exhaustion, can abandon an operation before it performs its matching
reset. A warning or other nonfatal diagnostic can also repopulate error state
after that state was already cleared during shutdown. The request heap is then
freed while the worker global field still refers to it. A later operation that
runs before normal request initialization can consume the stale value.

## Producer / consumer model

Successful exploitation requires both a producer and a consumer:

1. A reachable PHP operation stores request-owned state in a globally accessible
   location (producer).
2. The state is not reset, or another operation repopulates it after its normal
   reset.
3. PHP releases the request memory while the persistent worker retains the
   referring global state.
4. The same worker handles another request.
5. A PHP operation reads, frees, branches, or otherwise acts on the stale state
   before normal request initialization resets it (consumer).

The demonstrated producing and consuming operations occur in different HTTP
requests handled by the same worker.

## Producers

A producing operation becomes dangerous when its request-owned state remains
published after the request heap is freed. A fatal error can cause this by
abandoning the operation before it resets the state. Fatal interruptions include
parse and compile failures, uncaught errors, failure of `require`, and
`Maximum execution time exceeded`.

OOM can provide the same interruption when an affected error, exception, object,
or extension state was already published.

Even a nonfatal diagnostic from extension or server cleanup during a later
shutdown stage can repopulate new request-owned error information to the global
state.

## Consumers before normal initialization

### INI diagnostics

A warning, notice, or deprecation during initialization can consume stale error
state. It does not need to be fatal, displayed, or logged. Such a warning may be
raised when applying invalid or deprecated INI settings before ordinary
executor initialization. Examples include:

- Deterministic deprecations such as `auto_detect_line_endings=1`, a
  `filter.default` value other than the default, PHP 8.3+ legacy `assert.*`
  settings, PHP 8.4+ legacy session settings, and PHP 8.5 `report_memleaks=0` or
  nonzero `intl.error_level`.
- Explicitly configured `mbstring.http_input`, `mbstring.http_output`,
  `mbstring.internal_encoding`, `iconv.input_encoding`,
  `iconv.output_encoding`, or `iconv.internal_encoding`.
- Invalid or conflicting `zend.assertions`, `memory_limit`, `date.timezone`,
  DBA, EXIF, mail, OpenSSL, zlib, and loaded extension values.
- Malformed or overflowing quantities, including invalid `memory_limit`, body
  size, input, timeout, stack, and extension values on PHP 8.2+.
- Configured log, mail, session, or SOAP cache paths rejected under
  `open_basedir`.

Global state is accessed before PHP decides whether to report, display, or log
the warning. Changing `error_reporting`, using `@`, or disabling
`display_errors` or `log_errors` does not protect against this vulnerability.

Reachability:

- **Apache mod_php:** `.htaccess` and Apache `php_value` / `php_flag` /
  `php_admin_*` directory configuration is applied before
  `php_request_startup()`. Normal `php.ini` is startup configuration and is not
  reapplied as a consumer across requests.
- **FPM:** conditionally exposed when the frontend sends `PHP_VALUE` /
  `PHP_ADMIN_VALUE` parameters that produce a diagnostic before request
  initialization. Pool values and `.user.ini` do not provide the same early
  consumer. FPM also exits a child after `php_request_startup()` fails.
- **LSAPI:** can apply special environment INI values early and is a
  conditional candidate.
- **FrankenPHP:** an equivalent early configuration consumer was not
  established in the default configuration.

### Session upload progress

Session upload progress can reach session handling before ordinary session
initialization. It can therefore consume session or decoder state left by an
interrupted request before normal initialization resets it. This consumer is
independent of the INI diagnostic path.

## Confirmed cases

### PHP 8.5 fatal-error backtrace — confirmed

With `fatal_error_backtraces` enabled, fatal error reporting stores backtrace
state owned by the request. Resetting of this global state is always missed
during shutdown. A diagnostic on a subsequent request reaches the stale value
before normal request initialization resets it. This is the strongest
demonstrated case and the basis of the confirmed mod_php exploitation.

This repository's 8.5 probe uses this exact shape: an `E_USER_ERROR` producer,
then a `.htaccess` `php_value memory_limit <overflow>` diagnostic as the
consumer. On 8.5.11 the worker aborts with `zend_mm_heap corrupted` and
`AH00052: child pid ... exit signal Abort (6)`; with
`fatal_error_backtraces=0`, or on 8.5.12, it does not.

### Session upload progress lifecycle — confirmed

An upload can initialize request-owned session and decoding state before normal
module initialization. OOM or another fatal error after that state has been
published can prevent its matching reset. PHP then frees the request heap while
persistent session or decoder globals still refer to it. A later upload progress
operation reaches those globals before ordinary initialization and treats them
as valid state.

The demonstrated application-independent trigger is OOM during input processing.
With mod_php, both the producing operation and fatal error can occur during
multipart startup. FPM terminates a child when this startup fails, so that exact
sequence does not survive. The validated FPM path publishes state during
application execution after successful startup, reaches a fatal error, and then
uses session upload progress as the early consumer.

## Mitigation

Updating to a release containing the complete state reset patch is the **only
reliable mitigation**. There is no complete generic configuration mitigation.

For PHP 8.5 installations that cannot update:

- Set `fatal_error_backtraces=0` administratively and restart every worker.
  This removes the producer used by the confirmed RCE case.
- Set `session.upload_progress.enabled=0` administratively for the session
  lifecycle case.
- Reduce the remaining risk by breaking as many links as possible:
  eliminate attacker-reachable fatal errors; eliminate diagnostics during
  extension post-deactivation and server cleanup; eliminate diagnostics from
  per-request INI configuration; consider `pm.max_requests=1`.
- Treat a PHP execution timeout as another fatal error.
- Enable `log_errors=On`, a functional `error_log`, and
  `error_reporting=E_ALL` during an isolated audit, and review logs for
  warnings, deprecations, fatal/parse/uncaught errors, and
  `Maximum execution time exceeded`.

Absence of an error in logs is not proof of safety. Fixing observed errors
reduces exposure but does not replace updating.

## Impact

Confirmed impact is unauthenticated heap use-after-free, memory disclosure, and
remote code execution with the web worker's privileges. The fatal backtrace path
has confirmed RCE against mod_php. Session lifecycle RCE was validated against
mod_php and FPM.
