# CS 166 Final Project — Phishing & Scam Email Detection

> **Course:** CS 166 – Information Security  
> **GitHub:** https://github.com/Lushangtu123/CS-166-Final-Project

A full-stack phishing and scam-email detection system built on a Random Forest classifier trained on the UCI Phishing Websites Dataset. The project includes a reproducible ML pipeline and an interactive web application with three analysis modes: **email address risk analysis**, **email content scanning**, and **email authenticity verification**.

---

## Table of Contents

- [Project Structure](#project-structure)
- [Features](#features)
- [Detection Modules](#detection-modules)
  - [Email Address Analysis](#1-email-address-analysis)
  - [Email Content Analysis](#2-email-content-analysis)
  - [Email Authenticity Verification](#3-email-authenticity-verification)
- [Model Performance](#model-performance)
- [Quick Start — Web App](#quick-start--web-app)
- [Quick Start — ML Notebook](#quick-start--ml-notebook)
- [Tech Stack](#tech-stack)
- [Feature Engineering](#feature-engineering)
- [Dataset](#dataset)

---

## Project Structure

```
CS-166-Final-Project/
├── phishing-detection/          # ML pipeline (Jupyter Notebook)
│   ├── data/
│   │   └── phishing_dataset.csv          # auto-downloaded on first run
│   ├── notebooks/
│   │   └── phishing_detection.ipynb      # main notebook
│   ├── src/
│   │   ├── preprocess.py                 # loading, cleaning, scaling, splitting
│   │   ├── train.py                      # model definitions & training loop
│   │   └── evaluate.py                   # metrics + publication-quality plots
│   ├── requirements.txt
│   └── README.md
│
├── website/                     # Interactive web application
│   ├── app.py                            # FastAPI backend (all API endpoints)
│   ├── requirements.txt
│   ├── data/                             # dataset (shared with ML pipeline)
│   └── static/
│       ├── index.html                    # single-page frontend
│       ├── app.js                        # client-side logic & rendering
│       └── style.css                     # dark-theme UI
│
└── progress_report.md           # Mid-project progress report
```

---

## Features

### Web Application

| Feature | Description |
|---------|-------------|
| **Email Address Analysis** | ML + heuristic analysis of any email address for phishing risk |
| **Suspected Phishing Override** | Shows amber "Suspected Phishing" verdict when heuristics detect high-risk patterns even if ML says legitimate |
| **Semantic Domain Analysis** | Detects fake business domains (e.g. `[abbr]+[financial term]+[business suffix]`), brand impersonation, government keyword abuse |
| **Disposable Email Detection** | 500+ known providers + pattern matching + 6-factor heuristic for auto-generated usernames |
| **Email Content Analysis** | Rule-based keyword scan across 10 phishing categories + 11 structural checks |
| **Email Authenticity Verification** | 7-stage live verification: format → DNS/MX → SMTP probe → PTR → SPF → DMARC → domain age |
| **Model Metrics Dashboard** | Live display of all four classifiers' accuracy, F1, and ROC AUC |

---

## Detection Modules

### 1. Email Address Analysis

The core analysis pipeline combines a **Random Forest ML model** with an extended **heuristic layer**.

**ML Prediction**

- 30 features extracted from the email address and domain
- `RandomForestClassifier` trained on 11,055 UCI phishing website samples
- Returns phishing probability (%) and a `Legitimate / Suspected Phishing / Likely Phishing` verdict

**Verdict Logic**

| Condition | Verdict | Banner Color |
|-----------|---------|--------------|
| ML = phishing | Likely Phishing | 🔴 Red |
| ML = legitimate + ≥1 high-risk heuristic indicator | Suspected Phishing | 🟡 Amber |
| ML = legitimate + no high-risk indicators | Legitimate Email | 🟢 Green |

**Semantic Domain Analysis (heuristic layer)**

Runs on any domain not in the known-legitimate provider list and flags:

| Pattern | Risk Level |
|---------|-----------|
| `[short abbreviation] + [financial keyword] + [business suffix]` (e.g. `bpinsgroup`) | High |
| Domain combines financial keywords + business suffixes | High |
| Known brand name embedded as substring (typosquatting) | High |
| Government/regulatory keyword on non-.gov domain | High |
| Financial-sector keyword on unverified domain | Medium |
| Business suffix on unrecognized domain | Low |
| Long concatenated word-chain domain (>15 chars) | Medium |

**Disposable Email Detection — Three States**

| State | Color | Trigger |
|-------|-------|---------|
| 🟣 **Confirmed Disposable** | Purple | Domain in 500+ provider database or pattern keyword match |
| 🟠 **Suspected Disposable** | Amber | Auto-generated username heuristic (6-factor score ≥ 2) |
| 🟢 **Not Disposable** | Green | Neither check triggered |

Auto-generated username heuristic factors:

| Factor | Description |
|--------|-------------|
| F1 Shannon Entropy > 3.0 | High entropy = uniform character spread = random |
| F2 Vowel ratio ≤ 30% | Real words have more vowels than random strings |
| F3 Digits scattered inside | Auto-generators embed digits throughout, not just at end |
| F4 Unique-char ratio ≥ 75% | Random strings rarely repeat characters |
| F5 No embedded English word | Legitimate usernames contain readable names or words |
| F6 Non-name word.word combo | `word.word` separators not matching `first.last` patterns |

Legitimate `firstname.lastname` patterns (e.g. `alice.smith`) are exempted via a curated database of ~120 first names and ~100 last names.

---

### 2. Email Content Analysis

A **rule-based heuristic scanner** for email subject and body text. No ML model — pure keyword matching and structural analysis.

**Keyword Categories (10 categories)**

| Category | Examples |
|----------|---------|
| Urgency & Pressure | "act now", "immediate action", "expires today" |
| Threats & Fear | "account suspended", "legal action", "unauthorized access" |
| Financial Lure | "you have won", "transfer funds", "unclaimed prize" |
| Credential Harvesting | "verify your password", "login to confirm", "update your details" |
| Brand Impersonation | "paypal", "apple id", "microsoft account", "amazon" |
| Deceptive Tactics | "this is not spam", "click the link below", "limited time" |
| Suspicious Attachments | "open the attached file", "download the invoice", ".exe", ".zip" |
| Tech Support / Malware | "your computer is infected", "call our toll-free", "remote access" |
| Job / Money Mule | "work from home", "wire transfer", "uncashed cheque" |
| Social Engineering | "i need your help", "please keep this confidential", "strictly private" |

**Structural / Linguistic Checks (11 checks)**

| Check | Signal |
|-------|--------|
| IP-based URLs | Links using raw IP addresses instead of domain names |
| URL shorteners | Bit.ly, tinyurl, etc. masking the real destination |
| Excessive `!` / `?` | More than 3 exclamation or question marks |
| Excessive capitalization | > 30% uppercase words |
| High URL count | More than 5 links in the message body |
| Mismatched link text | Visible text says one domain but href points to another |
| Generic salutation | "Dear Customer", "Dear User", "Dear Account Holder" |
| Non-native English phrasing | "kindly do the needful", "revert back to us", "regularize" |
| Large currency amounts | $10,000+ amounts mentioned in body text |
| Excessive generic CTAs | More than 3 "Click here" / "Visit now" type buttons |
| Character obfuscation | Leetspeak substitutions: `0` for `o`, `@` for `a`, `3` for `e` |

**Safety Signals (reduce risk score)**

Unsubscribe links, privacy policy mentions, physical address, sender verification phrases.

**Risk Score → Overall Verdict**

| Score | Verdict |
|-------|---------|
| ≥ 60 | 🔴 Critical Risk |
| 40–59 | 🔴 High Risk |
| 20–39 | 🟡 Medium Risk |
| 5–19 | 🟡 Low Risk |
| < 5 | 🟢 Likely Safe |

---

### 3. Email Authenticity Verification

A **7-stage live verification** pipeline that checks whether an email address physically exists and whether its domain follows email security best practices. Stages 3–7 run **in parallel** to minimize latency.

| Stage | Check | Method |
|-------|-------|--------|
| 1 | **Format Validation** | RFC 5321 regex — catches malformed addresses |
| 2 | **DNS / MX Records** | `dns.resolver` MX lookup; falls back to A record |
| 3 | **SMTP Mailbox Probe** | Connects to MX server port 25, sends `RCPT TO` |
| 4 | **MX Reverse DNS (PTR)** | Checks if MX server IP has a PTR record |
| 5 | **SPF Record** | Queries TXT record for `v=spf1`; parses `-all / ~all / ?all / +all` |
| 6 | **DMARC Policy** | Queries `_dmarc.<domain>` TXT; parses `p=reject/quarantine/none` |
| 7 | **Domain Age (WHOIS)** | Retrieves registration date; flags domains < 30 days old |

**Overall Verdict**

| Verdict | Condition |
|---------|-----------|
| ✅ Verified | SMTP accepted the address (code 250) |
| ❌ Likely Invalid | SMTP rejected (5xx) or no DNS records |
| ⚠️ Unverifiable | MX found but port 25 blocked (common on residential/cloud IPs) |
| 🚨 Suspicious | Domain registered < 30 days ago |
| ❌ Invalid Format | RFC 5321 violation |

**SPF policy interpretation**

| Policy | Meaning | Risk |
|--------|---------|------|
| `-all` (strict) | Unauthorized senders are rejected | Low |
| `~all` (softfail) | Unauthorized senders are flagged | Medium |
| `?all` (neutral) | No enforcement | High |
| `+all` (open) | Any server may send | Critical |
| *(absent)* | No SPF — domain freely spoofable | High |

**DMARC policy interpretation**

| Policy | Enforcement |
|--------|------------|
| `p=reject` | Unauthorized emails are rejected outright |
| `p=quarantine` | Unauthorized emails go to spam |
| `p=none` | Monitoring only — no active protection |
| *(absent)* | No DMARC — no anti-spoofing policy |

> **Note:** Large providers (Gmail, Outlook, Yahoo) block inbound port 25 probes, so SMTP results will show "Unverifiable" — this is expected. MX records and security policy checks still provide meaningful signals.

---

## Model Performance

All four classifiers evaluated on the held-out test set (20% of 11,055 samples):

| Classifier | Accuracy | Precision | Recall | F1-Score | ROC AUC |
|------------|----------|-----------|--------|----------|---------|
| **Random Forest** | **97.47%** | **97.48%** | **97.47%** | **97.46%** | **0.9977** |
| SVM (RBF) | 95.16% | 95.20% | 95.16% | 95.15% | 0.9893 |
| Decision Tree | 94.80% | 94.81% | 94.80% | 94.80% | 0.9865 |
| Logistic Regression | 92.85% | 92.87% | 92.85% | 92.84% | 0.9808 |

The Random Forest model is used for real-time inference in the web application.

**Top 3 most important features (Random Forest Gini importance):**

1. `sslfinal_state` (32.0%) — mapped to *Known Legit Provider*
2. `url_of_anchor` (25.0%) — mapped to *Username Length*
3. `web_traffic` (7.1%) — mapped to *High-Traffic Mail Platform*

---

## Quick Start — Web App

```bash
# 1. Navigate to the website directory
cd website

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start the server (with auto-reload for development)
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Then open **http://localhost:8000** in your browser.

> The model trains automatically on first launch using the UCI dataset
> (or a synthetic fallback if the dataset file is absent).

---

## Quick Start — ML Notebook

```bash
# 1. Navigate to the ML pipeline directory
cd phishing-detection

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Launch Jupyter
jupyter notebook notebooks/phishing_detection.ipynb
```

The notebook automatically downloads and caches the UCI dataset on first run.
A synthetic dataset is generated if no internet connection is available.

---

## Tech Stack

### Backend
- **Python 3.x**
- **FastAPI** — REST API and static file serving
- **scikit-learn** — Random Forest, StandardScaler
- **pandas / NumPy** — data loading and feature extraction
- **uvicorn** — ASGI server
- **dnspython** — DNS MX, TXT (SPF/DMARC), A, PTR record lookups
- **python-whois** — domain registration date retrieval
- **smtplib / socket** — SMTP mailbox probe

### Frontend
- **HTML5 / CSS3 / Vanilla JavaScript**
- **Chart.js** — model performance charts
- Dark-theme responsive UI with animated probability bars and orbital hero visual

### ML Pipeline
- **scikit-learn** — Logistic Regression, Random Forest, SVM (RBF), Decision Tree
- **matplotlib / seaborn** — confusion matrices, ROC curves, feature importance charts
- **Jupyter Notebook** — reproducible end-to-end pipeline
- **ucimlrepo** — automatic dataset download

---

## Feature Engineering

The web application maps the original 30 UCI phishing-website features onto email address characteristics:

| Feature Group | Email Characteristic |
|---------------|---------------------|
| **URL-based** | IP address domain, address length, multiple `@` symbols, URL shortener domain, double-slash in domain, hyphen in domain, subdomain depth, `http` token in address |
| **Domain-based** | Known legitimate provider, common TLD, domain label length, digits in domain, high-traffic mail platform, phishing keywords in domain/username, suspicious TLD |
| **HTML/Content-based** | High digit ratio in username, username randomness (Shannon entropy), special characters, username length, brand spoofing, noreply address, repeated characters, digit-letter mix, auto-generated pattern, composite risk score, email format validity |

Each feature is scored as:
- `+1` — Legitimate signal (shown in green)
- `0` — Neutral / inconclusive
- `-1` — Phishing signal (shown in red)

---

## Dataset

- **Source:** [UCI ML Repository – Phishing Websites (ID 327)](https://archive.ics.uci.edu/ml/datasets/phishing+websites)
- **Size:** 11,055 rows × 30 features + 1 target
- **Label encoding:** `-1` = phishing → remapped to `0`; `1` = legitimate
- **Feature types:** Ternary integers `{-1, 0, 1}` encoding URL, domain, and HTML signals
- **Collection date:** 2012 (features reflect phishing techniques of that era)

---

*CS 166 – Information Security | Final Project*
