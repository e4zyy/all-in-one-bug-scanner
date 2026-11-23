# All In One Bug Scanner

**All In One Bug Scanner** is a Python-based assistive scanner for authorized vulnerability disclosure programs (VDPs) and bug-bounty testing. It maps findings to an OWASP-style focus list, performs baseline-aware checks, generates payload variants, and produces timestamped TXT and JSON reports.

> **Use only on systems you are explicitly authorized to test.** Automated scanning can generate substantial traffic and may violate a program’s rules. Always review the target’s scope, rate limits, and testing policy before running it.

## Features

- Crawls same-host URLs and discovers HTML forms and input parameters.
- Tests query, form, and JSON parameters.
- Uses response baselines and delta scoring to reduce false positives.
- Generates mutated payloads for SQL injection and reflected XSS testing.
- Checks common security misconfigurations, exposed files, secrets, access-control surfaces, authentication endpoints, CSRF indicators, and open redirects.
- Performs passive subdomain-takeover checks using certificate-transparency data from `crt.sh`.
- Saves findings to a timestamped `.txt` report and a structured `.json` report.
- Separates confirmed-looking findings from an audit queue for manual review.

## Requirements

- Python 3.8+
- `requests`

Install dependencies:

```bash
pip install requests
```

## Installation

```bash
git clone [https://github.com/e4zyy/all-in-one-bug-scanner.git](https://github.com/e4zyy/all-in-one-bug-scanner.git)
cd all-in-one-bug-scanner

python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install requests
```

Place `all_in_one_bug_scanner.py` in the repository root.

## Quick start

```bash
python3 all_in_one_bug_scanner.py -u [https://example.com](https://example.com)
```

For a safer first scan, limit concurrency and crawling:

```bash
python3 all_in_one_bug_scanner.py -u [https://example.com](https://example.com) \
  --threads 2 \
  --delay 0.5 \
  --max-urls 30
```

## Usage

```bash
python3 all_in_one_bug_scanner.py -u [https://target.tld](https://target.tld)
python3 all_in_one_bug_scanner.py -u [https://target.tld](https://target.tld) --cookie "session=abc" --threads 12
python3 all_in_one_bug_scanner.py -u target.tld --subdomains --proxy http://127.0.0.1:8080
python3 all_in_one_bug_scanner.py --list-modules
```

## Command-line options

| Option | Description | Default |
|---|---|---|
| `-u`, `--url` | Target URL or hostname | Required |
| `--cookie` | Cookie string for authenticated testing | Empty |
| `-H`, `--header` | Add a custom header, for example `-H "Authorization: Bearer TOKEN"` | None |
| `--proxy` | HTTP/HTTPS proxy, for example `http://127.0.0.1:8080` | None |
| `-t`, `--threads` | Number of concurrent workers | `8` |
| `--delay` | Delay between requests, in seconds | `0.0` |
| `--timeout` | Per-request timeout, in seconds | `12.0` |
| `--depth` | Crawl depth | `2` |
| `--max-urls` | Maximum URLs to crawl | `220` |
| `--variants` | Maximum mutated payloads per probe | `12` |
| `--sleep` | Delay used by time-based SQL injection checks, in seconds | `5` |
| `--subdomains` | Run passive subdomain-takeover checks | Disabled |
| `--only` | Run only selected modules, comma-separated | All modules |
| `--skip` | Skip selected modules, comma-separated | None |
| `-o`, `--outdir` | Report output directory | `reports` |
| `--insecure` | Disable TLS certificate verification | Enabled |
| `--quiet` | Reduce console output | Disabled |
| `--list-modules` | List available modules | — |

## Modules

Run this command to display the module list:

```bash
python3 all_in_one_bug_scanner.py --list-modules
```

| Module | Checks |
|---|---|
| `sqli` | Error-based, boolean differential, and time-based SQL injection heuristics |
| `xss` | Reflected XSS probes and basic DOM sink indicators |
| `injection` | SSTI, command injection, LDAP injection, CRLF injection, XXE, open redirects, and host-header reflection |
| `misconfig` | Security headers, CORS, cookie flags, verbose errors, HTTP methods, and host-header behavior |
| `access` | Forced-browsing paths, exposed admin/debug surfaces, and numeric IDOR candidates |
| `sensitive` | Exposed `.git`, `.env`, backups, source maps, and potential secrets in JavaScript bundles |
| `auth` | Authentication endpoints, default-credential checks, and JWT inspection |
| `csrf` | POST forms without common anti-CSRF token names |
| `takeover` | Passive subdomain-takeover candidate checks |

Example: run only lower-impact configuration and access-control checks:

```bash
python3 all_in_one_bug_scanner.py -u [https://example.com](https://example.com) --only misconfig,access
```

Example: skip injection testing:

```bash
python3 all_in_one_bug_scanner.py -u [https://example.com](https://example.com) --skip sqli,xss,injection
```

## Authenticated testing

Copy the session cookie from your browser developer tools, then pass it to the scanner:

```bash
python3 all_in_one_bug_scanner.py -u [https://example.com](https://example.com) \
  --cookie "session=YOUR_SESSION_VALUE" \
  --threads 2 \
  --delay 0.5
```

Add authorization headers when needed:

```bash
python3 all_in_one_bug_scanner.py -u [https://example.com](https://example.com) \
  --cookie "session=YOUR_SESSION_VALUE" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  --threads 2
```

## Proxy support

Route traffic through Burp Suite or another local proxy:

```bash
python3 all_in_one_bug_scanner.py -u [https://example.com](https://example.com) \
  --proxy http://127.0.0.1:8080 \
  --threads 1 \
  --delay 1
```

## Reports

Reports are written to the output directory, by default `reports/`:

```text
reports/example.com_YYYYMMDD-HHMMSS.txt
reports/example.com_YYYYMMDD-HHMMSS.json
```

Each report includes:

- Target, start time, duration, and finding count.
- Severity counts and an overall verdict.
- WAF and environment notes.
- An audit queue for items requiring manual review.
- Finding details: module, confidence, URL, method, parameter, payload, evidence, request/response excerpts, remediation, and audit notes.

## Interpreting results

Treat every scanner result as a **lead**, not a confirmed vulnerability.

- Reproduce high- and critical-severity findings manually.
- Verify the security impact, not merely the presence of a payload or error message.
- Check whether input is encoded, sanitized, blocked by a CSP, or only reflected in a non-executable context.
- Validate exposed secrets before reporting them; do not submit unverified key material.
- Confirm access-control issues from an unauthenticated or low-privilege session.
- Include clear reproduction steps, impact, evidence, and remediation guidance in your bug-bounty report.

## Responsible-use guidance

- Test only in-scope assets.
- Respect program rules on automated scanning, rate limits, and prohibited techniques.
- Start with low concurrency and a request delay.
- Avoid time-based payloads on production systems unless the program explicitly permits them.
- Do not access, download, or expose data beyond what is necessary to demonstrate a vulnerability.
- Stop testing and report immediately if you encounter sensitive customer data, production credentials, or an unintended outage.

## Disclaimer

This tool is intended for authorized security testing, education, and defensive research. The author is not responsible for misuse or for any damage caused by running this tool against systems without permission.
