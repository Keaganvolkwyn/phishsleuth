import re
from urllib.parse import urlparse

_URL_RE = re.compile(r'(https?://[^\s<>"\)\]]+)', re.I)

def extract_urls(text: str):
    if not text:
        return []
    return _URL_RE.findall(text)

def parse_domain(url: str):
    try:
        p = urlparse(url)
        host = p.hostname or ""
        return host.lower()
    except Exception:
        return ""

def looks_like_ip(host: str) -> bool:
    return bool(re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', host))

def has_many_subdomains(host: str) -> bool:
    return host.count('.') >= 3

def is_punycode(host: str) -> bool:
    return 'xn--' in host

def has_mixed_chars(host: str) -> bool:
    # letters+digits mix in same label is a simple heuristic
    return any(any(c.isalpha() for c in part) and any(c.isdigit() for c in part) for part in host.split('.'))
