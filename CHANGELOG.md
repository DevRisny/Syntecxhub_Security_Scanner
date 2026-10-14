# Changelog

## 1.0.0
- Same-origin crawler: robots.txt respected, rate-limited, concurrent, same-origin only
- Passive checks: missing security headers, insecure cookie flags, information disclosure
  (stack traces, SQL/PHP/.NET/Java error messages, directory listing, version banners),
  mixed content, TLS protocol/certificate expiry
- Safety gate: refuses public targets unless explicitly confirmed (`--allow-public`)
- JSON, CSV and self-contained HTML reports; severity-based exit code for CI use
- `secscan` console command
- Example intentionally-misconfigured Flask demo site to try it against
- 38 unit and integration tests, including a real local-server end-to-end scan
- ruff lint and format checks, GitHub Actions CI on Python 3.9 to 3.13
