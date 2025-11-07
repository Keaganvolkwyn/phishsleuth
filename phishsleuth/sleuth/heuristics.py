from .url_tools import extract_urls, parse_domain, looks_like_ip, has_many_subdomains, is_punycode, has_mixed_chars
from .email_tools import extract_email_like_fields, count_urgency_words, count_credential_requests, has_attachment_language
from .ai_reason import ai_available, ai_judge

# --- URL scoring --------------------------------------------------------------

def score_and_flags_for_url(url: str):
    findings = []
    host = parse_domain(url)

    if not host:
        findings.append({"label": "Malformed URL", "detail": "Could not parse the domain.", "severity": "high", "weight": 25})
        return 25, findings

    if url.lower().startswith("http://"):
        findings.append({"label": "No HTTPS", "detail": "Link uses http instead of https.", "severity": "medium", "weight": 10})

    if looks_like_ip(host):
        findings.append({"label": "Raw IP address", "detail": f"Host is an IP ({host}), often used to hide identity.", "severity": "high", "weight": 20})

    if has_many_subdomains(host):
        findings.append({"label": "Many subdomains", "detail": f"Host has many dots ({host}).", "severity": "medium", "weight": 10})

    if is_punycode(host):
        findings.append({"label": "Punycode domain", "detail": f"Internationalized domain may be a look-alike ({host}).", "severity": "medium", "weight": 10})

    if has_mixed_chars(host):
        findings.append({"label": "Look-alike pattern", "detail": f"Mixed letters/digits in domain could mimic brands ({host}).", "severity": "low", "weight": 5})

    if "@" in url:
        findings.append({"label": "@ in URL", "detail": "Everything before @ is ignored by browsers—often used to hide real host.", "severity": "high", "weight": 20})

    if "-" in host and any(part in host for part in ["secure", "login", "update", "verify"]):
        findings.append({"label": "Brand+keyword mashup", "detail": "Suspicious mix of login/security words in host.", "severity": "medium", "weight": 10})

    base_score = sum(f["weight"] for f in findings)
    return min(base_score, 90), findings

# --- Text scoring -------------------------------------------------------------

_BRAND_DOMAINS = {
    "dhl": ["dhl.com", "dhl.de", "dhl.co.uk", "dhl.co.za", "dhlparcel.nl", "dhlparcel.be"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "paypal": ["paypal.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.za"],
}
_BRAND_WORDS = set(_BRAND_DOMAINS.keys())

_EXTRA_URGENCY = [
    "package waiting", "package is waiting", "parcel waiting", "delivery pending",
    "schedule delivery", "tracking code", "track your parcel", "failed delivery",
    "awaiting confirmation", "confirm delivery", "shipping notice",
]

def _contains_any(text: str, words) -> int:
    t = (text or "").lower()
    return sum(1 for w in words if w in t)

def score_and_flags_for_text(text: str):
    findings = []
    urls = extract_urls(text)
    meta = extract_email_like_fields(text)

    # Content cues
    u = count_urgency_words(text) + _contains_any(text, _EXTRA_URGENCY)
    if u:
        findings.append({"label": "Urgency language", "detail": f"Detected {u} urgency/delivery cues.", "severity": "medium", "weight": min(22, 5*u)})

    c = count_credential_requests(text)
    if c:
        findings.append({"label": "Sensitive info request", "detail": "Asks for passwords/OTP/card details—classic phishing.", "severity": "high", "weight": min(25, 8*c)})

    if has_attachment_language(text):
        findings.append({"label": "Attachment lure", "detail": "Mentions attachments/invoices—common malware delivery.", "severity": "medium", "weight": 10})

    # Header cues (very naive)
    if meta.get("from") and any(k in meta["from"].lower() for k in ["noreply", "support", "security", "offers"]):
        findings.append({"label": "Generic sender", "detail": f"From: {meta['from']}", "severity": "low", "weight": 5})

    # URL cues inside text
    seen_hosts = set()
    for uurl in urls[:3]:
        s, fl = score_and_flags_for_url(uurl)
        host = parse_domain(uurl)
        if host:
            seen_hosts.add(host)
        if s > 0:
            findings.append({"label": "Suspicious link", "detail": f"{uurl}", "severity": "medium", "weight": min(20, s//2)})
            findings.extend(fl)

    # Brand mismatch
    mentioned = [b for b in _BRAND_WORDS if b in (text or "").lower()]
    if mentioned:
        domains = set(seen_hosts)
        frm = (meta.get("from") or "").lower()
        import re
        m = re.search(r'@([A-Za-z0-9\.\-\_]+)', frm)
        if m:
            domains.add(m.group(1))
        for brand in mentioned:
            allowed = _BRAND_DOMAINS.get(brand, [])
            if domains and not any(any(d.endswith(allow) for allow in allowed) for d in domains):
                findings.append({
                    "label": "Brand/domain mismatch",
                    "detail": f"Mentions '{brand.upper()}', but domains seen {sorted(domains) or ['(none)']} are not typical {brand.upper()} domains.",
                    "severity": "high",
                    "weight": 18,
                })

    base = sum(f["weight"] for f in findings)
    score = min(base, 95)
    return score, findings

# --- Blended analysis (rules + optional AI) ----------------------------------

def blended_analysis(inp: str, mode: str = "text", use_ai: bool = True, model: str = "gpt-4o", blend: float = 0.5):
    """Default: 50% rules + 50% AI. Robust against AI structure issues."""
    if mode == "url":
        rule_score, findings = score_and_flags_for_url(inp.strip())
    else:
        rule_score, findings = score_and_flags_for_text(inp)

    ai_info = {"score": 0, "rationale": "AI disabled."}
    if use_ai and ai_available():
        ai_info = ai_judge(inp, model=model) or {}

    # Defensive parsing
    ai_score_raw = ai_info.get("score", 0) if isinstance(ai_info, dict) else 0
    try:
        ai_score = int(float(ai_score_raw))
    except Exception:
        ai_score = 0
    ai_score = max(0, min(100, ai_score))

    final = round((1.0 - blend) * rule_score + blend * ai_score)
    band = "Low" if final < 30 else "Medium" if final < 60 else "High"

    meta = [
        {"label": "Risk band", "detail": f"{band} risk (blended).", "severity": "info", "weight": 0},
        {"label": "Rule score", "detail": f"{rule_score}/100 (heuristics).", "severity": "info", "weight": 0},
        {"label": "AI score", "detail": f"{ai_score}/100 — {ai_info.get('rationale','') if isinstance(ai_info, dict) else ''}", "severity": "info", "weight": 0},
    ]
    return {"score": final, "findings": meta + findings}


def format_findings(findings):
    lines = []
    for f in findings:
        sev = f.get("severity", "info")
        emoji = {"high":"🔴","medium":"🟠","low":"🟡","info":"🟦"}.get(sev, "🟦")
        lines.append(f"{emoji} **{f.get('label','Flag')}** — {f.get('detail','')}")
    return "\n".join(lines)
