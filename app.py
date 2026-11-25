
import streamlit as st
import re
import pandas as pd
import ipaddress
from urllib.parse import urlparse
from difflib import SequenceMatcher

# ==========================================
# PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ PhishGuard")
st.subheader("Phishing Email Detection & Awareness System")

st.write(
    "Analyze email messages, identify suspicious senders, "
    "fake domains, malicious links and email authentication indicators."
)

st.divider()


# ==========================================
# KNOWN BRAND DOMAINS
# ==========================================

BRANDS = {
    "paypal": "paypal.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com"
}

PUBLIC_PROVIDERS = {
    "gmail.com", "yahoo.com", "outlook.com",
    "hotmail.com", "proton.me"
}


# ==========================================
# EMAIL VALIDATION
# ==========================================

def validate_email(email):
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return bool(re.fullmatch(pattern, email.strip()))


# ==========================================
# DOMAIN ANALYSIS
# ==========================================

def analyze_domain(domain):

    score = 0
    findings = []

    domain = domain.lower().strip()

    try:
        ipaddress.ip_address(domain)
        score += 30
        findings.append("IP address used as sender domain.")
        return score, findings

    except ValueError:
        pass

    if domain.startswith("xn--") or ".xn--" in domain:
        score += 20
        findings.append("Internationalized domain detected.")

    if domain.count("-") >= 2:
        score += 10
        findings.append("Domain contains multiple hyphens.")

    for brand, official_domain in BRANDS.items():

        similarity = SequenceMatcher(
            None, brand, domain.split(".")[0]
        ).ratio()

        if similarity >= 0.75 and domain != official_domain:
            score += 25
            findings.append(
                f"Possible {brand} lookalike domain. "
                f"Compare with {official_domain}."
            )

    if not findings:
        findings.append("No basic domain warning detected.")

    return score, findings


# ==========================================
# SENDER ANALYSIS
# ==========================================

def analyze_sender(sender):

    domain = sender.split("@")[-1].lower()

    score, findings = analyze_domain(domain)

    if domain in PUBLIC_PROVIDERS:
        findings.append(
            "Public email provider detected. "
            "This does not prove the sender is legitimate."
        )

    return score, domain, findings


# ==========================================
# KEYWORD ANALYSIS
# ==========================================

def analyze_keywords(subject, content):

    text = (subject + " " + content).lower()

    suspicious_words = [
        "urgent",
        "verify your account",
        "click here",
        "password",
        "bank account",
        "suspended",
        "free gift",
        "limited time",
        "confirm your identity",
        "account blocked",
        "update payment",
        "reset your password",
        "immediate action",
        "unusual activity",
        "claim your reward"
    ]

    score = 0
    findings = []

    for word in suspicious_words:
        if word in text:
            score += 10
            findings.append(
                f"Suspicious phrase detected: {word}"
            )

    return score, findings


# ==========================================
# URL ANALYSIS
# ==========================================

def analyze_urls(content):

    urls = re.findall(
        r"https?://[^\s<>\"']+",
        content,
        re.IGNORECASE
    )

    score = 0
    results = []
    findings = []

    shorteners = {
        "bit.ly", "tinyurl.com", "t.co",
        "is.gd", "cutt.ly"
    }

    for url in urls:

        clean_url = url.rstrip(".,;!?)")
        parsed = urlparse(clean_url)

        domain = parsed.hostname or ""

        if not domain:
            continue

        warnings = []

        try:
            ipaddress.ip_address(domain)
            score += 30
            warnings.append("IP-based URL")

        except ValueError:
            pass

        if domain.lower() in shorteners:
            score += 20
            warnings.append("Shortened URL")

        if "@" in clean_url:
            score += 20
            warnings.append("URL contains @ symbol")

        if parsed.scheme.lower() != "https":
            warnings.append("URL does not use HTTPS")

        if domain.lower() in BRANDS.values():
            warnings.append("Known brand domain detected; verify the exact URL.")

        for brand, official_domain in BRANDS.items():

            similarity = SequenceMatcher(
                None, brand, domain.split(".")[0]
            ).ratio()

            if similarity >= 0.75 and domain.lower() != official_domain:
                score += 25
                warnings.append(
                    f"Possible {brand} lookalike domain"
                )

        if warnings:
            findings.extend(warnings)

        results.append({
            "URL": clean_url,
            "Domain": domain,
            "Warnings": (
                ", ".join(warnings)
                if warnings else "No basic warning detected"
            )
        })

    return score, results, findings


# ==========================================
# EMAIL HEADER ANALYSIS
# ==========================================

def analyze_headers(header_text):

    findings = []
    score = 0

    if not header_text.strip():
        return score, ["No email headers provided."]

    headers = {}

    for line in header_text.splitlines():

        if ":" in line and not line.startswith((" ", "\t")):

            key, value = line.split(":", 1)

            headers[key.strip().lower()] = value.strip()

    from_header = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    return_path = headers.get("return-path", "")
    authentication = headers.get(
        "authentication-results", ""
    ).lower()

    if from_header:
        findings.append("From header found.")
    else:
        findings.append("From header missing.")
        score += 10

    if reply_to:
        findings.append(f"Reply-To address: {reply_to}")

        if from_header and reply_to.lower() not in from_header.lower():
            findings.append(
                "Reply-To differs from From. Investigate this mismatch."
            )
            score += 15

    if return_path:
        findings.append(f"Return-Path found: {return_path}")
    else:
        findings.append("Return-Path not provided.")

    if authentication:

        for mechanism in ["spf", "dkim", "dmarc"]:

            match = re.search(
                rf"\b{mechanism}=(pass|fail|softfail|neutral|none|temperror|permerror)\b",
                authentication
            )

            if match:

                result = match.group(1)

                findings.append(
                    f"{mechanism.upper()} result: {result}"
                )

                if result in ["fail", "softfail", "permerror"]:
                    score += 20

            else:

                findings.append(
                    f"{mechanism.upper()} result not found."
                )

    else:

        findings.append(
            "Authentication-Results header missing. "
            "SPF, DKIM and DMARC cannot be verified from this input."
        )

    return score, findings


# ==========================================
# COMPLETE EMAIL ANALYSIS
# ==========================================

def analyze_email(sender, subject, content, header_text):

    total_score = 0
    all_findings = []

    sender_score, domain, sender_findings = analyze_sender(sender)

    keyword_score, keyword_findings = analyze_keywords(
        subject, content
    )

    url_score, url_results, url_findings = analyze_urls(
        content
    )

    header_score, header_findings = analyze_headers(
        header_text
    )

    total_score = min(
        sender_score + keyword_score + url_score + header_score,
        100
    )

    all_findings.extend(keyword_findings)
    all_findings.extend(url_findings)

    if total_score >= 50:
        classification = "Phishing"

    elif total_score >= 20:
        classification = "Suspicious"

    else:
        classification = "Safe"

    return (
        total_score,
        classification,
        domain,
        sender_findings,
        all_findings,
        url_results,
        header_findings
    )


# ==========================================
# USER INPUT
# ==========================================

st.header("📩 Email Analyzer")

sender = st.text_input(
    "Sender Email Address *",
    placeholder="example@domain.com"
)

subject = st.text_input(
    "Email Subject *",
    placeholder="Enter email subject"
)

content = st.text_area(
    "Email Content *",
    height=180,
    placeholder="Paste complete email content here..."
)

header_text = st.text_area(
    "Email Headers (Optional)",
    height=150,
    placeholder="Paste original email headers here..."
)

st.caption("* Sender, subject and email content are mandatory.")


# ==========================================
# ANALYZE BUTTON
# ==========================================

if st.button("🔍 Analyze Email", use_container_width=True):

    if not sender.strip() or not subject.strip() or not content.strip():

        st.error("All three mandatory fields must be completed.")

    elif not validate_email(sender):

        st.error("Please enter a valid sender email address.")

    else:

        (
            score,
            classification,
            domain,
            sender_findings,
            all_findings,
            url_results,
            header_findings
        ) = analyze_email(
            sender.strip(),
            subject.strip(),
            content.strip(),
            header_text
        )

        st.divider()

        st.header("📊 Analysis Results")

        col1, col2 = st.columns(2)

        with col1:
            st.metric("Risk Score", f"{score}/100")

        with col2:
            st.metric("Classification", classification)

        st.progress(score / 100)

        if classification == "Phishing":
            st.error("🚨 Potential phishing email detected!")

        elif classification == "Suspicious":
            st.warning("⚠️ Suspicious email indicators detected.")

        else:
            st.success(
                "No major indicators detected by current rules."
            )

        st.subheader("📧 Sender Domain Analysis")

        st.write(f"**Detected domain:** {domain}")

        for item in sender_findings:
            st.write("•", item)

        st.subheader("🚩 Suspicious Indicators")

        if all_findings:
            for item in all_findings:
                st.warning(item)
        else:
            st.success("No basic suspicious indicators detected.")

        st.subheader("🔗 URL Analysis")

        if url_results:
            st.dataframe(
                pd.DataFrame(url_results),
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No URLs detected.")

        st.subheader("📨 Email Header Analysis")

        for item in header_findings:
            st.write("•", item)

        st.divider()

        st.header("🛡️ Security Recommendations")

        if classification == "Phishing":

            st.error("""
            - Do not click suspicious links.
            - Do not share passwords or OTPs.
            - Avoid downloading unexpected attachments.
            - Report the email to the security team.
            """)

        elif classification == "Suspicious":

            st.warning("""
            - Verify the sender independently.
            - Check suspicious domains.
            - Avoid sharing confidential information.
            - Contact the organization through official channels.
            """)

        else:

            st.info("""
            - Continue following email security practices.
            - Verify unexpected requests.
            - Never share passwords or OTPs.
            """)

        st.caption(
            "The risk score is a rule-based heuristic, not a probability. "
            "Header checks use supplied text and do not independently "
            "authenticate the sender. A Safe result is not a guarantee."
        )


# ==========================================
# PHISHING AWARENESS
# ==========================================

st.divider()

st.header("📚 Phishing Awareness Center")

with st.expander("What is phishing?"):

    st.write(
        "Phishing is a cyberattack in which attackers use "
        "deceptive messages to steal sensitive information."
    )

with st.expander("Common phishing techniques"):

    st.write("""
    1. Email spoofing.
    2. Fake or lookalike domains.
    3. Malicious links.
    4. Urgent account verification requests.
    5. Credential theft.
    """)

with st.expander("Prevention guidelines"):

    st.write("""
    1. Check the sender's address.
    2. Inspect links before opening them.
    3. Never share passwords or OTPs.
    4. Enable multi-factor authentication.
    5. Report suspicious emails.
    6. Verify unexpected requests independently.
    """)

st.divider()

st.caption(
    "PhishGuard | Future Interns Cyber Security Internship | Task 02"
)
