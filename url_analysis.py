from __future__ import annotations

import ipaddress
import re
from typing import List
from urllib.parse import urlparse, parse_qs

from .scoring import Finding, Report, build_report

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "qrco.de", "l.ead.me", "s.id", "v.gd",
}
SUSPICIOUS_TLDS = {
    "zip", "mov", "top", "xyz", "click", "link", "gq", "tk", "ml", "cf", "ga", "icu",
    "cyou", "monster", "rest", "country", "buzz", "sbs", "cfd",
}
SECOND_LEVEL = {"co.in", "co.uk", "com.au", "com.br", "org.in", "net.in", "gov.in", "ac.in", "co.jp", "co.za"}
KEYWORDS = re.compile(r"(login|signin|verify|secure|account|update|wallet|claim|reward|bonus|kyc|suspend|unlock)", re.I)

# brand token -> legitimate registered domains
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amazon.jobs", "amazonaws.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "google": {"google.com", "google.co.in", "gstatic.com", "googleusercontent.com", "withgoogle.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "indeed": {"indeed.com", "indeed.co.in"},
    "naukri": {"naukri.com"},
    "paytm": {"paytm.com", "paytm.in"},
    "phonepe": {"phonepe.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "onlinesbi": {"onlinesbi.sbi", "onlinesbi.com", "sbi.co.in"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "fb.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t"})


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def registered_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _brand_findings(host: str) -> List[Finding]:
    out: List[Finding] = []
    reg = registered_domain(host)
    label = reg.split(".")[0]
    parts = re.split(r"[.\-_]", host)
    for token, legit in BRANDS.items():
        if reg in legit:
            continue
        if token in parts or (len(token) >= 6 and label.startswith(token) and len(label) > len(token)):
            out.append(Finding(0.5, f"Uses the brand name '{token}' but isn't an official {token} domain"))
        elif len(token) >= 5 and levenshtein(label.translate(_LEET), token) <= 1 and label != token:
            out.append(Finding(0.55, f"Look-alike spelling of '{token}' (possible typosquatting)"))
    return out


def analyze_url(url: str) -> List[Finding]:
    raw = url.strip()
    explicit = bool(re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I))
    if not explicit:
        raw = "https://" + raw
    try:
        p = urlparse(raw)
        host = (p.hostname or "").lower().rstrip(".")
    except ValueError:
        return [Finding(0.4, "Malformed URL")]
    if not host:
        return [Finding(0.3, "URL has no valid hostname")]

    f: List[Finding] = []
    if explicit and p.scheme.lower() == "http":
        f.append(Finding(0.15, "Unencrypted HTTP link"))
    if "@" in p.netloc:
        f.append(Finding(0.45, "Contains 'user@' trick that disguises the real destination"))
    if _is_ip(host):
        f.append(Finding(0.45, "Uses a raw IP address instead of a domain name"))
    if "xn--" in host:
        f.append(Finding(0.4, "Punycode domain (can imitate other characters)"))
    if any(ord(c) > 127 for c in host):
        f.append(Finding(0.35, "Domain contains non-ASCII look-alike characters"))
    if registered_domain(host) in SHORTENERS or host in SHORTENERS:
        f.append(Finding(0.3, "URL shortener hides the real destination"))
    tld = host.rsplit(".", 1)[-1]
    if tld in SUSPICIOUS_TLDS:
        f.append(Finding(0.2, f"Suspicious top-level domain '.{tld}'"))
    if not _is_ip(host) and len(host.split(".")) > 4:
        f.append(Finding(0.2, "Unusually deep subdomain chain"))
    if host.count("-") >= 3:
        f.append(Finding(0.15, "Many hyphens in domain name"))
    if KEYWORDS.search(host + p.path):
        f.append(Finding(0.15, "Urgent/credential keywords in the link (login, verify, claim...)"))
    if len(raw) > 150:
        f.append(Finding(0.1, "Very long URL"))
    for values in parse_qs(p.query).values():
        if any(re.match(r"https?://", v, re.I) for v in values):
            f.append(Finding(0.2, "Link redirects to another URL (possible open redirect)"))
            break
    if not _is_ip(host):
        f += _brand_findings(host)
    return f


def analyze_url_report(url: str) -> Report:
    return build_report("url", url, analyze_url(url))
