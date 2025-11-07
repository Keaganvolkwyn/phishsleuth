# sleuth/ai_reason.py
from typing import Dict, Any, Optional
import os

def _get_api_key() -> Optional[str]:
    """
    Robustly fetch the API key.
    - Prefer env var (Streamlit Cloud injects secrets into env)
    - Fall back to st.secrets.get if available
    Never raises KeyError.
    """
    key = os.getenv("OPENAI_API_KEY")
    if key:
        return key
    try:
        import streamlit as st
        # .get() avoids KeyError on some Streamlit builds
        return st.secrets.get("OPENAI_API_KEY", None)
    except Exception:
        return None

def ai_available() -> bool:
    return bool(_get_api_key())

def _client():
    # Support optional project/base_url (enterprise/project-scoped keys)
    from openai import OpenAI
    kwargs = {"api_key": _get_api_key()}
    project = os.getenv("OPENAI_PROJECT") or os.getenv("OPENAI_PROJECT_ID")
    if project:
        kwargs["project"] = project
    base_url = os.getenv("OPENAI_BASE_URL")
    if base_url:
        kwargs["base_url"] = base_url
    return OpenAI(**kwargs)

_PROMPT = """You are a cybersecurity analyst. Classify phishing risk (0=benign, 100=highly suspicious).
Use strict criteria: brand impersonation, urgency, odd/mismatched domains, credential/payment requests, attachment lures.
Return compact JSON ONLY like:
{"score": <int 0-100>, "rationale": "<short paragraph with 2-4 reasons>"}

CONTENT START
{content}
CONTENT END
"""

def ai_judge(content: str, model: str = "gpt-4o") -> Dict[str, Any]:
    """
    Call LLM; return score/rationale.
    Never raise; on any failure, return {"score": 0, "rationale": "..."} with error class/message.
    """
    if not ai_available():
        return {"score": 0, "rationale": "AI disabled (no API key set or not visible)."}

    try:
        client = _client()
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a concise, cautious security analyst."},
                {"role": "user", "content": _PROMPT.format(content=content[:8000])},
            ],
            temperature=0.2,
        )
        txt = (resp.choices[0].message.content or "").strip()
        import json, re
        m = re.search(r"\{.*\}", txt, re.S)
        if not m:
            return {"score": 0, "rationale": "AI returned no JSON."}
        data = json.loads(m.group(0))
        score = int(max(0, min(100, int(data.get("score", 0)))))
        rationale = str(data.get("rationale", "")).strip() or "No rationale."
        return {"score": score, "rationale": rationale}
    except Exception as e:
        msg = getattr(e, "message", str(e))
        if not isinstance(msg, str):
            msg = str(msg)
        return {"score": 0, "rationale": f"AI error; running rules-only. ({e.__class__.__name__}: {msg[:200]})"}
