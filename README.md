# FUTURE_CS_02
# 🛡️ PhishGuard
### Phishing Email Detection & Awareness System

**Future Interns | Cyber Security Internship | Task 02**

## Project Overview

PhishGuard is a Python-based web application developed using Streamlit to demonstrate basic phishing email detection and security awareness.

It analyzes email information and identifies selected suspicious indicators to help users understand potential email threats.

## Features

- Sender email and domain analysis.
- Suspicious phrase detection.
- URL extraction and analysis.
- Optional email header analysis.
- Risk scoring from 0 to 100.
- Safe, Suspicious and Phishing classifications.
- Security recommendations and phishing awareness guidance.

## Technologies Used

- Python
- Streamlit
- Pandas
- Regular Expressions

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/FUTURE_CS_02.git
```

Move into the project directory:

```bash
cd FUTURE_CS_02
```

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

Run the application:

```bash
python -m streamlit run app.py
```

The application will open in your browser at `http://localhost:8501`.

## Testing Results

| Test | Risk Score | Classification |
|---|---:|---|
| Legitimate email | 0/100 | Safe |
| Account-update email | 10/100 | Safe |
| Bank-account suspension email | 90/100 | Phishing |
| Sample email headers | 55/100 | Phishing |

**Testing observation:** The account-update sample was classified as Safe despite being intended as a suspicious sample. This identifies an area for improvement in the current detection rules.

## Limitations

- Uses rule-based detection rather than a trained machine-learning model.
- Risk scores are heuristic values, not probabilities.
- Email headers are analyzed from user-supplied text and are not independently authenticated.
- False positives and false negatives are possible.

## Project Documentation

Refer to the `reports` folder for the project report and the `screenshots` folder for testing evidence.

## Disclaimer

PhishGuard is an educational cybersecurity project. Its results should not be treated as a guarantee that an email is safe or malicious.
