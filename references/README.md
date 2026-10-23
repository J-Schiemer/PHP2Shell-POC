# References

Curated source material for this lab. The upstream advisory pages are the
authoritative source; the notes below preserve the details used to build and
validate the harness.

| Document | What it covers |
|---|---|
| [GHSA-w8hw-w9fx-j79w](GHSA-w8hw-w9fx-j79w.md) | CVE-2026-109618 — OOM corruption / `longjmp()` |
| [GHSA-6wmf-4rv5-p3rp](GHSA-6wmf-4rv5-p3rp.md) | CVE-2026-109619 — stale global state across requests |
| [fix-commit-3584a98bda](fix-commit-3584a98bda.md) | Upstream fix commit metadata and design |
| [public-poc-9bie](public-poc-9bie.md) | Pinned public PoC, calibration, licensing |
| [lab-verification](lab-verification.md) | What this repository reproduced on which image |

Advisory URLs:

- https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

Fixed releases: 8.2.35, 8.3.36, 8.4.27, 8.5.12. Affected: earlier releases on
each branch, with source backports for older EOL branches.
