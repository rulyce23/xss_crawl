scan_web.py — CVE & Severity heuristics

What I changed

- Added functions to extract CVE identifiers from responses/evidence (regex matching CVE-YYYY-NNNN).
- Added functions to extract CVSS numeric scores when present and heuristics to infer severity from scores or keyword hints.
- Integrated detection into XSS and SQLi findings: results now include 'cves', 'cvss', and 'severity' fields where detected.
- Final summary aggregates discovered CVEs and prints a heuristic severity breakdown.

Notes & caveats

- This tool performs only local/offline heuristics. It does NOT query the NVD, cve.org, or any external CVE database to validate or enrich findings.
- CVE matching uses a simple regex; false positives are possible in arbitrary text.
- CVSS extraction relies on common textual patterns; it will only find scores embedded in responses or evidence text (e.g., copied advisory snippets).
- Severity is derived from CVSS numeric thresholds (>=9 Critical, >=7 High, >=4 Medium, >0 Low) or plain keyword matches ("critical", "high", etc.) if a numeric score is absent.

How to run

1. Install Python 3 and the 'requests' library if missing:

   python -m pip install requests

2. Run the scanner (be authorized to test target):

   python "scan_web (1).py" -u "https://example.com/page.php?id=1&cat=2"

The script will prompt for confirmation before proceeding and will write results to ./result/<host>.txt

Next steps (optional)

- Integrate with an online CVE/OSV lookup to validate and enrich discovered CVEs.
- Add unit tests for the new extraction helpers.
- Improve robustness for importing as a module (avoid prompting for input on import).