# Syntecxhub_Security_Scanner

[![CI](https://github.com/DevRisny/Syntecxhub_Security_Scanner/actions/workflows/ci.yml/badge.svg)](https://github.com/DevRisny/Syntecxhub_Security_Scanner/actions)
![Python](https://img.shields.io/badge/python-3.9%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green) ![Scan](https://img.shields.io/badge/scanning-passive%20only-success)

Week 2, Task 3 of the **Syntecxhub Cyber Security Internship**: a **web vulnerability scanner** that crawls a site and reports real, common weaknesses — missing security headers, insecure cookies, information disclosure, weak TLS — **without sending any attack payload**. No SQL injection string and no injected script is ever sent; every check only reads the response that would already be sent to any ordinary visitor. See [SECURITY.md](SECURITY.md) for the full design reasoning and threat model.

## Task checklist (adapted)
| Brief asked for | What this project does |
|---|---|
| Crawl given pages | Same-origin crawler, concurrent, rate-limited, `robots.txt`-aware |
| Inject payloads, analyze responses | **Not done on purpose** — see [SECURITY.md](SECURITY.md) for why; instead analyzes the natural response for real vulnerability indicators |
| Save vulnerable endpoints + report | JSON / CSV / self-contained HTML report, severity-ranked |
| Only test permitted targets | Hard safety gate: refuses any non-local target unless explicitly confirmed |
| Basic concurrency and rate-limiting | `ThreadPoolExecutor` + a shared token-interval rate limiter |

## Quick start
```bash
pip install .                 # installs the `secscan` command
secscan http://localhost:8080 --html report.html --json report.json
```
Try it against the included intentionally-misconfigured demo site:
```bash
pip install ".[demo]"
python examples/demo_site.py &          # starts on 127.0.0.1:8090
secscan http://127.0.0.1:8090 -y --html report.html
```

### Example (real output, against the demo site)
```
$ secscan http://127.0.0.1:8090 -y
Target: http://127.0.0.1:8090  (3 page(s) scanned)
  INFO:3  LOW:9  MEDIUM:7  HIGH:1
  [HIGH] Verbose error output / information disclosure (Python traceback)  -  http://127.0.0.1:8090/error
  [MEDIUM] Cookie 'session' missing HttpOnly, SameSite flag(s)  -  http://127.0.0.1:8090/
  [MEDIUM] Missing Content-Security-Policy header  -  http://127.0.0.1:8090/
  ...

$ secscan https://example.com -y
Refused: 'example.com' looks like a public host. Only scan systems you own or are
explicitly authorized to test... Re-run with --allow-public if you have written permission.
```

## Options
```
secscan <url> [--max-pages N] [--workers N] [--rate N] [--timeout N]
              [--ignore-robots] [--allow-public] [-y]
              [--json FILE] [--csv FILE] [--html FILE] [-v]
```
Exit code is `1` if any HIGH/CRITICAL finding was reported (useful in CI), else `0`.

## How it works
```
 target URL ──► permission gate ──► crawler (same-origin, robots.txt, rate-limited)
                                        │
                                each fetched page
                                        ▼
                headers ──► check_security_headers / check_cookies
                body    ──► check_information_disclosure / check_mixed_content
                host    ──► check_tls (once, certificate + protocol)
                                        │
                                        ▼
                              ScanResult ──► JSON / CSV / HTML report
```
1. **Permission gate.** `localhost`/private addresses are allowed by default; any other host needs `--allow-public` plus a typed `yes` (or `-y` once you've confirmed).
2. **Crawl.** Breadth-first, same origin only, `robots.txt` honored, a shared rate limiter caps requests/second across worker threads.
3. **Checks.** Pure functions that take the response already received and return `Finding` objects — nothing is sent to the server beyond the original GET.
4. **Report.** Findings are ranked by severity and exported.

## Project layout
```
src/syntecxhub_scanner/
  permission.py   safety gate (local vs. public target)
  findings.py     Finding / Severity / ScanResult
  checks.py       the passive checks
  crawler.py      same-origin crawler, robots.txt, rate limiter
  scanner.py      orchestrates permission + crawl + checks
  report.py       JSON / CSV / HTML output
  cli.py          `secscan` command
examples/demo_site.py   a tiny, deliberately misconfigured Flask app to scan
tests/                  38 tests
```

## Tests
```bash
pip install -e . ruff
python -m unittest discover -s tests -v
ruff check . && ruff format --check .
```
Includes a real end-to-end test: a local HTTP server plays a page with a leaked stack trace, an insecure cookie, missing headers and a `robots.txt`-disallowed path, and the real scanner is pointed at it over `127.0.0.1` — plus a test that greps the crawler module to confirm no SQL/script payload string ever appears in the code.

## Limits (honest notes)
See [SECURITY.md](SECURITY.md) — in short: this finds **misconfiguration and disclosure** issues, not active injection vulnerabilities that only appear when a form is submitted. For that, an authorized tester uses an established tool (OWASP ZAP, Burp Suite) against a target they're permitted to attack.

## What I learned
OWASP Secure Headers, cookie security flags, information disclosure (stack traces, DB error strings, server banners), TLS/certificate validation, polite crawling (`robots.txt`, rate limiting, concurrency), and why a responsible scanner design matters as much as its feature set.
