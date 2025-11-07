import streamlit as st
from pathlib import Path

# MUST be the first Streamlit command:
st.set_page_config(page_title="PhishSleuth", page_icon="🕵️‍♂️", layout="centered")

# Imports that do NOT call st.* at import time
from sleuth.ai_reason import ai_available
from sleuth.url_tools import extract_urls
from sleuth.heuristics import blended_analysis, format_findings

BASE_DIR = Path(__file__).parent

# Sidebar status (debug)
st.sidebar.markdown("### AI status")
st.sidebar.write("Key detected:", bool(ai_available()))

st.title("🕵️‍♂️ PhishSleuth — AI-style Phishing Analyzer (demo)")
st.markdown("**Demo by Keagan Volkwyn — (ISC)² Conference**")
st.caption("Paste an email, message, or URL. Get a risk score and the reasons why it may be phishing.")

with st.expander("What is phishing? (quick primer)", expanded=False):
    st.markdown("""
**Phishing** is a social-engineering attack that tricks you into doing something risky
(clicking a malicious link, downloading malware, or giving away credentials/OTP). It often uses:
- Urgency or threats (“Your account will be closed”)
- Impersonation (spoofed brands, look-alike domains)
- Suspicious links/attachments
- Requests for sensitive info

This tool uses transparent rules, optionally blended with AI, to produce a **risk score (0–100)**.
    """)

# Samples
sample_choice = st.selectbox(
    "Need a sample?",
    ["(none)", "Suspicious bank notice (text)", "Delivery notice (URL)", "Legit newsletter (text)"]
)
st.session_state.setdefault("input_text", "")

if sample_choice != "(none)":
    try:
        sample_text = (BASE_DIR / "assets" / "example_inputs.txt").read_text(encoding="utf-8")
        blocks = sample_text.split("---\n")
        presets = {
            b.splitlines()[0].strip(): "\n".join(b.splitlines()[1:]).strip()
            for b in blocks if b.strip()
        }
        st.session_state["input_text"] = presets.get(sample_choice, "")
    except FileNotFoundError:
        st.warning("⚠️ Sample file not found at phishsleuth/assets/example_inputs.txt")
        st.session_state["input_text"] = ""

txt = st.text_area(
    "Paste email text or a URL:",
    value=st.session_state["input_text"],
    height=240,
    help="You can paste a full email, SMS, or a single URL."
)

# AI toggle
use_ai_default = ai_available()
use_ai = st.toggle("Enable AI reasoning (uses API key if set)", value=use_ai_default)
analyze = st.button("Analyze")

def build_report(result, original_text):
    lines = [
        "PhishSleuth report",
        "Demo by Keagan Volkwyn",
        "",
        "Original input:",
        original_text,
        "",
        f"Risk score: {result['score']} / 100",
        "Findings:"
    ]
    for f in result["findings"]:
        sev = f.get("severity", "info")
        lines.append(f"- {f.get('label', 'Flag')} ({sev}): {f.get('detail', '')}")
    return "\n".join(lines)

if analyze and txt.strip():
    urls = extract_urls(txt)
    mode = "url" if len(urls) == 1 and urls[0].strip() == txt.strip() else "text"

    # You can change the model here if your project lacks access to gpt-4o-mini
    result = blended_analysis(txt, mode=mode, use_ai=use_ai, model="gpt-4o-mini", blend=0.3)

    st.subheader("Risk score (blended)")
    st.progress(min(result["score"] / 100, 1.0))
    st.markdown(f"### {result['score']} / 100")

    badges = []
    for f in result["findings"]:
        severity = f.get("severity", "info")
        label = f.get("label", "Flag")
        color = {"high": "🔴", "medium": "🟠", "low": "🟡", "info": "🟦"}.get(severity, "🟦")
        badges.append(f"{color} **{label}**")
    if badges:
        st.markdown("**Top signals:** " + " • ".join(badges))

    st.subheader("Why this score?")
    st.markdown(format_findings(result["findings"]))

    st.subheader("Safer next steps")
    st.markdown("""
- Verify the sender via a known, official channel (do **not** use the links or numbers in the message).
- Hover or long-press links to preview the real destination.
- Never enter passwords, 2FA codes, or card details from unsolicited requests.
- If it claims to be your bank, **log in from the official website/app you already trust**.
    """)

    report_text = build_report(result, txt)
    st.download_button("Download report (.txt)", report_text, file_name="phishsleuth_report.txt", mime="text/plain")
    st.code(report_text, language="text")

elif analyze:
    st.warning("Please paste some text or a URL to analyze.")

st.markdown("---\nMade with ❤️ by Keagan Volkwyn | (ISC)² Conference Demo 2025")
