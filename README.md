# scan_web — Crawl & XSS/SQLi reconnaissance tool

A small, opinionated Python tool for quickly crawling a target site (same-host), discovering input parameters, and running ordered per-parameter checks: XSS payload testing (reflected) followed by SQLi indicator testing. It validates CVE and CWE tokens it finds by querying the NVD and MITRE indexes (optional).

WARNING: This tool sends HTTP requests to target hosts. Only run it against systems you own or where you have explicit authorization to test.

## Requirements

- Python 3.8+ (3.11 used in development)
- requests

Install dependencies:

```powershell
python -m pip install --user requests
```

## Files

- `scan_web.py` — main scanner script (crawl -> XSS -> SQLi). Outputs results to `./result/<host>.txt`.
- `README.md` — this document.

## Quick usage

Run a normal crawl-and-scan (crawler enabled by default):

```powershell
python3 scan_web.py -u http://example.com
```

Scan a URL without crawling (only test parameters present in the provided URL):

```powershell
python3 scan_web.py -u "http://example.com/page.php?id=1" --no-crawl
```

Limit pages to crawl and reduce request timeout (helpful to avoid long stalls):

```powershell
python3 scan_web.py -u http://example.com --crawl-pages 6 --timeout 6
```

Speed up scans by limiting payload counts for reconnaissance:

```powershell
python3 scan_web.py -u http://example.com --max-xss 12 --max-sqli 30
```

If you prefer to avoid external CVE/CWE lookups (NVD/MITRE), disable enrichment:

```powershell
python3 scan_web.py -u http://example.com --no-enrich
```

## CLI flags (summary)

- `-u`, `--url` : Target URL to scan (query string not required; crawler will discover inputs when enabled)
- `-y`, `--yes` : Skip authorization prompt (non-interactive)
- `--no-enrich` : Disable NVD/MITRE enrichment (enabled by default)
- `--no-crawl` : Disable crawling; only test parameters present in the provided URL
- `--crawl-pages N` : Maximum pages to crawl (default: 8)
- `--timeout N` : Request timeout in seconds (default: 12)
- `--max-sqli N` : Limit number of SQLi payloads to use (0 = no limit)
- `--max-xss N` : Limit number of XSS payloads to use (0 = no limit)

Note: There are also internal throttling/threading controls (THREADS, REQUEST_DELAY) in the script. If you want, I can expose `--threads` and `--delay` flags to the CLI.

## Output

- Results are appended to `./result/<host>.txt` (a human-friendly text report). The script also prints findings to stdout in real time.
- Each finding includes:
  - parameter name
  - payload/vector tested
  - evidence snippet
  - validated CVE/CWE entries (if found and enrichment is enabled)
  - CVSS / heuristic severity when available

## Safety & performance tips

- Start with small values for `--crawl-pages`, `--max-xss`, and `--max-sqli` to get a quick overview. Increase them later for deeper testing.
- Use `--timeout` to avoid long TLS/read stalls on slow hosts.
- Respect `robots.txt` — the scanner checks and will skip XSS if crawling is disallowed for the path.
- Consider adding a short delay between requests (`REQUEST_DELAY`) if scanning a sensitive production host.

## Next improvements you can enable

- Expose `--threads` and `--delay` flags to the CLI for concurrency and polite throttling.
- Add a `--fast-scan` preset that uses a smaller payload set and fewer pages for quick reconnaissance.
- Add unit tests for CVE/CW E extraction and severity inference (mock NVD responses).

## Example quick command

```powershell
python3 scan_web.py -u http://unesco.com --crawl-pages 4 --max-xss 12 --max-sqli 30 --timeout 6
```

