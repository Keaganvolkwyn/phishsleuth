# sleuth/heuristics.py
"""
Pure rules-based phishing detector for PhishSleuth.

Covers common phishing patterns in emails/SMS:
- Urgency & threats
- Requests for credentials / OTP / payments
- Suspicious links & domains
- Brand impersonation
- Attachments & file lures
- Generic greetings
"""

from __future__ import annotations
import re
from typing import Tuple, List, Dict, Any
from urllib.parse import urlparse

HEUR_VERSION = "rules-v1"

# --- Keyword sets -----------------------------------------------------------

URGENT_TERMS = [
    "urgent", "immediately", "asap", "straight away",
    "within 24 hours", "today", "now", "right away",
]

THREAT_TERMS = [
    "account will be closed", "suspended", "locked",
    "last warning", "final notice", "legal action",
    "fine", "penalty", "lose access", "limited access",
]

CREDENTIAL_TERMS = [
    "login", "log in", "sign in", "verify your account",
    "confirm your account", "update your account",
    "password", "passcode", "one time password", "otp",
    "security code", "verification code",
]

PAYMENT_TERMS = [
    "invoice", "payment", "pay now", "overdue",
    "bank details", "credit card", "debit card",
    "wire transfer", "bitcoin", "crypto",
]

ATTACHMENT_TERMS = [
    "attachment", "attached", "see attached", "open the attached",
    ".zip", ".exe", ".html", ".htm", ".pdf",
]

GENERIC_GREETINGS = [
    "dear customer", "dear client", "dear user",
    "dear valued customer", "dear valued client",
]

# Common brands attackers like to impersonate
BRAND_KEYWORDS = [
    "dhl", "fedex", "ups", "amazon", "paypal",
    "apple", "microsoft", "standard bank", "fnb",
    "absa", "capitec", "netflix", "facebook", "instagram",
]

SUSPICIOUS_TLDS = [
    ".top", ".xyz", ".club", ".click", ".info", ".shop",
    ".work", ".loan", ".win", ".men", ".kim",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
]


# --- Helpers ----------------------------------------------------------------

def _add(findings: List[Dict[str, Any]], label: str, detail: str,
         severity: str, weight: int) -> int:
    findings.append({
        "label": label,
        "detail": detail,
        "severity": severity,
        "weight": weight,
    })
    return weight


def _score_for_urgency(text_lower: str, findings: List[Dict[str, Any]]) -> int:
    hits = sum(1 for w in URGENT_TERMS if w in text_lower)
    if not hits:
        return 0
    severity = "medium" if hits <= 2 else "high"
    weight = min(25, hits * 6)
    return _add(findings, "Urgency language",
                f"Detected {hits} urgency phrases.", severity, weight)


def _score_for_threats(text_lower: str, findings: List[Dict[str, Any]]) -> int:
    hits = sum(1 for w in THREAT_TERMS if w in text_lower)
    if not hits:
        return 0
    severity = "medium" if hits == 1 else "high"
    weight = min(25, 8 * hits)
    return _add(findings, "Threat/penalty language",
                f"Detected {hits} threat/penalty phrases.", severity, weight)


def _score_for_credentials(text_lower: str, findings: List[Dict[str, Any]]) -> int:
    hits = sum(1 for w in CREDENTIAL_TERMS if w in text_lower)
    if not hits:
        return 0
    severity = "high"
    weight = min(30, 10 * hits)
    return _add(findings, "Credentials / OTP request",
                "Message refers to login, passwords or codes.", severity, weight)


def _score_for_payments(text_lower: str, findings: List[Dict[str, Any]]) -> int:
    hits = sum(1 for w in PAYMENT_TERMS if w in text_lower)
    if not hits:
        return 0
    severity = "medium" if hits == 1 else "high"
    weight = min(25, 7 * hits)
    return _add(findings, "Payment / money request",
                "Message pushes a payment, invoice or financial transfer.",
                severity, weight)


def _score_for_attachments(text_lower: str, findings: List[Dict[str, Any]]) -> int:
    hits = sum(1 for w in ATTACHMENT_TERMS if w in text_lower)
    if not hits:
        return 0
    severity = "medium"
    weight = min(20, 5 * hits)
    return _add(findings, "Attachment lure",
                "Message mentions attachments or risky file types.",
                severity, weight)


def _score_for_greeting(text_lower: str, findings: List[Dict[str, Any]]) -> int:
    hits = [g for g in GENERIC_GREETINGS if g in text_lower]
    if not hits:
        return 0
    return _add(findings, "Generic greeting",
                f"Uses non-personal greeting: {', '.join(hits)}.",
                "low", 8)


def _extract_urls(text: str) -> List[str]:
    return re.findall(r"https?://[^\s]+", text)


def _score_single_url(url: str, text_lower: str) -> Tuple[int, str, str, str]:
    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()
    except Exception:
        return 0, "", "", ""

    # IP address in URL
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host.split(":")[0]):
        return 25, "IP address URL", "Link uses raw IP address.", "high"

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return 18, "Unusual domain", f"Domain ends with {tld}.", "medium"

    # Many digits or dashes
    if sum(c.isdigit() for c in host) >= 5 or host.count("-") >= 3:
        return 15, "Noisy domain", "Domain has many digits or dashes.", "medium"

    # URL shortener
    if any(short in host for short in URL_SHORTENERS):
        return 20, "URL shortener", "Link uses a generic URL shortener.", "medium"

    # Brand impersonation: brand in text, but NOT in domain
    for brand in BRAND_KEYWORDS:
        if brand in text_lower and brand not in host:
            return (
                22,
                "Possible brand impersonation",
                f"Mentions {brand.title()} but domain does not match brand.",
                "high",
            )

    return 0, "", "", ""


def _score_for_urls(urls: List[str], text_lower: str,
                    findings: List[Dict[str, Any]]) -> int:
    score = 0
    for url in urls:
        weight, label, detail, severity = _score_single_url(url, text_lower)
        if weight > 0:
            findings.append({
                "label": label,
                "detail": f"{detail} ({url})",
                "severity": severity,
                "weight": weight,
            })
            score += weight
    return min(score, 40)


def score_and_flags_for_text(text: str) -> Tuple[int, List[Dict[str, Any]]]:
    """Heuristic scan for phishing indicators in email/SMS text."""
    text_lower = text.lower()
    findings: List[Dict[str, Any]] = []
    score = 0

    score += _score_for_urgency(text_lower, findings)
    score += _score_for_threats(text_lower, findings)
    score += _score_for_credentials(text_lower, findings)
    score += _score_for_payments(text_lower, findings)
    score += _score_for_attachments(text_lower, findings)
    score += _score_for_greeting(text_lower, findings)

    urls = _extract_urls(text)
    if urls:
        score += _score_for_urls(urls, text_lower, findings)

    # Clamp overall score
    score = max(0, min(100, score))
    return score, findings


def score_and_flags_for_url(url: str) -> Tuple[int, List[Dict[str, Any]]]:
    """Direct URL scoring."""
    findings: List[Dict[str, Any]] = []
    w, label, detail, severity = _score_single_url(url.strip(), url.lower())
    if w > 0:
        findings.append({
            "label": label,
            "detail": detail,
            "severity": severity,
            "weight": w,
        })
    return max(0, min(100, w)), findings


def analyze_text_or_url(inp: str, mode: str = "text") -> Dict[str, Any]:
    """Main entry point used by the Streamlit app."""
    if mode == "url":
        rule_score, findings = score_and_flags_for_url(inp.strip())
    else:
        rule_score, findings = score_and_flags_for_text(inp)

    # Risk band purely from rules
    if rule_score < 25:
        band = "Low"
    elif rule_score < 60:
        band = "Medium"
    else:
        band = "High"

    meta = [
        {
            "label": "Risk band",
            "detail": f"{band} risk (rules-based).",
            "severity": "info",
            "weight": 0,
        },
        {
            "label": "Rule score",
            "detail": f"{rule_score}/100 (heuristics).",
            "severity": "info",
            "weight": 0,
        },
    ]

    return {"score": rule_score, "findings": meta + findings}


def format_findings(findings: List[Dict[str, Any]]) -> str:
    """Turn findings list into markdown-friendly text."""
    parts = []
    for f in findings:
        parts.append(f"{f.get('label', 'Flag')} — {f.get('detail', '')}")
    return " ".join(parts)
