# sleuth/heuristics.py
import re
from typing import Tuple, List, Dict, Any
from sleuth.ai_reason import ai_available, ai_judge

HEUR_VERSION = "h2"

# --- Simple keyword heuristics ---
DELIVERY_TERMS = ["package", "delivery", "parcel", "shipment", "tracking", "courier"]
URGENT_TERMS = ["urgent", "immediately", "asap", "now", "today", "confirm", "verify", "account", "password"]

def score_and_flags_for_text(text: str) -> Tuple[int, List[Dict[str, Any]]]:
    """Quick heuristic scan for phishing indicators in plain text."""
    text_lower = text.lower()
    findings = []

    urgency_hits = sum(word in text_lower for word in URGENT_TERMS)
    delivery_hits = sum(word in text_lower for word in DELIVERY_TERMS)
    score = min(100, urgency_hits * 5 + delivery_hits * 5)

    if urgency_hits > 0:
        findings.append({
            "label": "Urgency language",
            "detail": f"Detected {urgency_hits} urgency/delivery cues.",
            "severity": "medium",
            "weight": urgency_hits,
        })
    if delivery_hits > 0:
        findings.append({
            "label": "Delivery language",
            "detail": f"Detected {delivery_hits} delivery-related terms.",
            "severity": "low",
            "weight": delivery_hits,
        })

    return score, findings


def score_and_flags_for_url(url: str) -> Tuple[int, List[Dict[str, Any]]]:
    """Basic heuristic scoring for suspicious URLs."""
    findings = []
    score = 0

    if re.search(r"[\d\-]{3,}", url):
        score += 10
        findings.append({
            "label": "Numeric domain",
            "detail": "Contains multiple numbers or dashes.",
            "severity": "medium",
            "weight": 10,
        })

    if not any(tld in url for tld in [".com", ".org", ".net", ".gov", ".edu"]):
        score += 10
        findings.append({
            "label": "Odd TLD",
            "detail": "URL lacks common top-level domain.",
            "severity": "medium",
            "weight": 10,
        })

    if re.search(r"(login|verify|account|update|bank)", url, re.I):
        score += 20
        findings.append({
            "label": "Sensitive path",
            "detail": "Suspicious path or query keywords.",
            "severity": "high",
            "weight": 20,
        })

    return min(score, 100), findings


def blended_analysis(inp: str, mode: str = "text", use_ai: bool = True,
                     model: str = "gpt-4o", blend: float = 0.5):
    """Combine rule-based and AI-based phishing analysis."""
    if mode == "url":
        rule_score, findings = score_and_flags_for_url(inp.strip())
    else:
        rule_score, findings = score_and_flags_for_text(inp)

    ai_info = {"score": 0, "rationale": "AI disabled."}
    if use_ai and ai_available():
        try:
            ai_info = ai_judge(inp, model=model) or {}
        except Exception:
            ai_info = {"score": 0, "rationale": "AI error (exception in ai_judge)."}

    raw = ai_info.get("score", 0) if isinstance(ai_info, dict) else 0
    try:
        ai_score = int(float(raw))
    except Exception:
        ai_score = 0
    ai_score = max(0, min(100, ai_score))

    final = round((1.0 - blend) * rule_score + blend * ai_score)
    band = "Low" if final < 30 else "Medium" if final < 60 else "High"

    meta = [
        {"label": "Risk band", "detail": f"{band} risk (blended).", "severity": "info", "weight": 0},
        {"label": "Rule score", "detail": f"{rule_score}/100 (heuristics).", "severity": "info", "weight": 0},
        {"label": "AI score", "detail": f"{ai_score}/100 — {ai_info.get('rationale','') if isinstance(ai_info, dict) else ''}",
         "severity": "info", "weight": 0},
    ]

    return {"score": final, "findings": meta + findings}


def format_findings(findings: List[Dict[str, Any]]) -> str:
    """Compact string summary for display."""
    return " ".join([f"{f['label']} — {f['detail']}" for f in findings])
