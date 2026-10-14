# Security notes

## Why this tool sends no attack payloads
A classic "vulnerability scanner" injects SQL/script payloads into a live target to see what
breaks. That is powerful, but it is also an attack tool: the same code that finds a bug on a
target you are authorized to test can be pointed at a target you are not. This project takes a
different, safer design: it only ever sends **plain GET requests** and studies the response
that *would already be sent to any visitor* — headers, cookies, error pages, TLS configuration.
Every one of the checks below is something a browser or a passive observer could see without
ever sending a crafted input.

## What is checked
| Check | What it looks for | Why it matters |
|---|---|---|
| `CSP-001` / `CSP-002` | Missing or weak Content-Security-Policy | CSP is the main browser-side defence against injected scripts |
| `HDR-001..005` | Missing X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, HSTS | Standard OWASP Secure Headers baseline |
| `COOKIE-001` | Cookies missing Secure / HttpOnly / SameSite | Session theft via XSS or network sniffing |
| `INFO-001` | Server/X-Powered-By reveals a software version | Lets an attacker target known CVEs for that exact version |
| `INFO-002` | Stack traces / DB error strings / directory listing in the response body | Information disclosure: reveals file paths, DB engine, queries |
| `MIXED-001` | HTTPS page loading an HTTP resource | Mixed content can be tampered with on the network |
| `TLS-001..003` | Outdated TLS version, expired or soon-to-expire certificate | Weak transport security |

## Safety gate
`secscan` refuses to scan a host that doesn't look like `localhost`/a private address unless
you pass `--allow-public` **and** type `yes` at a confirmation prompt (or pass `-y` once you've
already confirmed you're authorized). This mirrors the internship brief's rule: "only test on
allowed targets". Always get written permission before scanning anything you do not own.

## What is NOT covered (honest limits)
- **No active testing.** This will not find a SQL injection or stored XSS that only shows up
  when a form is actually submitted. For that, authorized testers use established tools (OWASP
  ZAP, Burp Suite, sqlmap) against a target they are permitted to attack — deliberately outside
  the scope of this project.
- **No authentication.** It crawls only pages reachable without logging in.
- **robots.txt is honored**, so disallowed paths are never requested (use `--ignore-robots`
  only on a target you control, if you need full coverage).
- Rate limiting and a request cap protect the target from being hammered, but a very large site
  will only be partially covered within `--max-pages`.
- Not a replacement for a professional penetration test.

## Reporting
Open a GitHub issue (no secrets in it) or contact the author through the GitHub profile.
