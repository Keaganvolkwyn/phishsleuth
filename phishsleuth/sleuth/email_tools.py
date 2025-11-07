import re

_URGENCY = [
    "urgent", "immediately", "now", "last chance", "final notice", "suspend",
    "close your account", "verify", "confirm", "within 24 hours", "action required",
    "warning", "failed delivery", "awaiting confirmation", "schedule delivery",
    "tracking code", "parcel waiting", "package waiting"
]

_CREDENTIAL = [
    "password", "passcode", "otp", "one-time code", "card number", "cvv",
    "security code", "login", "sign in", "account details", "bank details"
]

_ATTACHMENT = [
    "see attached", "attachment", "invoice attached", "document attached",
    "open the attachment", "pdf attached"
]

def extract_email_like_fields(text: str):
    """Very naive parse of From:/Subject: lines if present."""
    out = {}
    for line in (text or "").splitlines():
        if line.lower().startswith("from:"):
            out["from"] = line.split(":", 1)[1].strip()
        if line.lower().startswith("subject:"):
            out["subject"] = line.split(":", 1)[1].strip()
    return out

def count_urgency_words(text: str) -> int:
    t = (text or "").lower()
    return sum(1 for w in _URGENCY if w in t)

def count_credential_requests(text: str) -> int:
    t = (text or "").lower()
    return sum(1 for w in _CREDENTIAL if w in t)

def has_attachment_language(text: str) -> bool:
    t = (text or "").lower()
    return any(w in t for w in _ATTACHMENT)
