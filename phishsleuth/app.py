from pathlib import Path

import streamlit as st

from sleuth.heuristics import analyze_text_or_url, format_findings
from sleuth.url_tools import extract_urls

BASE_DIR = Path(__file__).parent

st.set_page_config(page_title="PhishSleuth", page_icon="🕵️‍♂️", layout="centered")

st.title("🕵️‍♂️ PhishSleuth — Rules-based Phishing Analyzer (demo)")
st.markdown("**Demo by Keagan Volkwyn — (ISC)² Conference**")
st.caption("Paste an email, SMS, or URL. Get a risk score and the specific red flags detected.")

with st.expander("What is phishing? (quick primer)", expanded=False):
    st.markdown("""
**Phishing** is a social-engineering attack where an attacker tricks you into doing something risky
(clicking a malicious link, downloading malware, or giving away credentials/OTP). It often uses:
- Urgency or threats (“Your account will be closed”)
- Impersonation (spoofed brands, look-alike domains)
- Suspicious links/attachments
- Requests for passwords, codes, or payments

This demo uses transparent **rules** – no AI – to flag common red flags and produce a **risk score (0–100)**.
    """)

# --- Sample selector --------------------------------------------------------

sample_choice = st.selectbox(
    "Need a sample?",
    ["(none)", "Suspicious bank notice (text)", "Delivery notice (URL)", "Legit newsletter (text)"],
)

st.session_state.setdefault("input_text", "")

if sample_choice != "(none)":
    try:
        sample_path = BASE_DIR / "assets" / "example_inputs.txt"
        raw = sample_path.read_text(encoding="utf-8")
        blocks = raw.split("---\n")
        presets = {}
        for b in blocks:
            b = b.strip()
            if not b:
                continue
            lines = b.splitlines()
            presets[lines[0].strip()] = "\n".join(lines[1:]).strip()
        st.session_state["input_text"] = presets.get(sample_choice, "")
    except FileNotFoundError:
        st.warning("Sample file not found at assets/example_inputs.txt")
        st.session_state["input_text"] = ""

# --- Main input -------------------------------------------------------------

txt = st.text_area(
    "Paste email text or a URL:",
    value=st.session_state["input_text"],
    height=260,
    help="You can paste a full email, SMS, or a single URL.",
)

analyze = st.button("Analyze")

# --- Run analysis -----------------------------------------------------------

def build_report(result, original_text: str) -> str:
    lines = []
    lines.append("PhishSleuth report (rules-only)")
    lines.append("Demo by Keagan Volkwyn")
    lines.append("")
    lines.append("Original input:")
    lines.append(original_text)
    lines.append("")
    lines.append(f"Risk score: {result['score']} / 100")
    lines.append("Findings:")
    for f in result["findings"]:
        sev = f.get("severity", "info")
        lines.append(f"- {f.get('label','Flag')} ({sev}): {f.get('detail','')}")
    return "\n".join(lines)


if analyze and txt.strip():
    urls = extract_urls(txt)
    mode = "url" if len(urls) == 1 and urls[0].strip() == txt.strip() else "text"

    result = analyze_text_or_url(txt, mode=mode)

    st.subheader("Risk score (rules-based)")
    st.progress(min(result["score"] / 100, 1.0))
    st.markdown(f"### {result['score']} / 100")

    # Build badges from findings
    badges = []
    for f in result["findings"]:
        severity = f.get("severity", "info")
        label = f.get("label", "Flag")
        if severity == "high":
            color = "🔴"
        elif severity == "medium":
            color = "🟠"
        elif severity == "low":
            color = "🟡"
        else:
            color = "🟦"
        if label not in ("Risk band", "Rule score"):
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
- If it claims to be your bank or delivery company, **log in from the official website/app you already trust**.
    """)

    report_text = build_report(result, txt)
    st.download_button(
        "Download report (.txt)",
        report_text,
        file_name="phishsleuth_report.txt",
        mime="text/plain",
    )
    st.code(report_text, language="text")

elif analyze:
    st.warning("Please paste some text or a URL to analyze.")

st.markdown("---\nMade BY Keagan Volkwyn 2025")
