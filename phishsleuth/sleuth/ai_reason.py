from typing import Dict, Any, Optional

def _get_api_key() -> Optional[str]:
    """Prefer Streamlit secrets on Cloud, env var locally."""
    key = None
    try:
        import streamlit as st  # safe if not present
        key = st.secrets.get("OPENAI_API_KEY", None)
    except Exception:
        key = None
    if not key:
        import os
        key = os.getenv("OPENAI_API_KEY")
    return key

def ai_available() -> bool:
    return bool(_get_api_key())

def _client():
    from openai import OpenAI
    return OpenAI(api_key=_get_api_key())

_PROMPT = """You are a cybersecurity analyst. Classify phishing risk (0=benign, 100=highly suspicious).
Use strict criteria: brand impersonation, urgency, odd/mismatched domains, credential/payment requests, attachment lures.
Return compact JSON:
{"score": <int 0-100>, "rationale": "<one short paragraph citing 2-4 reasons>"}

CONTENT START
{content}
CONTENT END
"""

def ai_judge(content: str, model: str = "gpt-4o-mini") -> Dict[str, Any]:
    """Call LLM; return score/rationale. Never raise; always safe-fallback."""
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
        text = (resp.choices[0].message.content or "").strip()
        import json, re
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            return {"score": 0, "rationale": "AI returned no JSON."}
        data = json.loads(m.group(0))
        score = int(max(0, min(100, int(data.get("score", 0)))))
        rationale = str(data.get("rationale", "")).strip() or "No rationale."
        return {"score": score, "rationale": rationale}
    except Exception as e:
        return {"score": 0, "rationale": f"AI error; running rules-only. ({e.__class__.__name__})"}
