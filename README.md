# CS 166 Final Project — Phishing & Scam Email Detection

> **Course:** CS 166 – Information Security  
> **GitHub:** https://github.com/Lushangtu123/CS-166-Final-Project

A full-stack phishing and scam-email detection system built on a Random Forest classifier trained on the UCI Phishing Websites Dataset. The project includes a reproducible ML pipeline and an interactive web application with three analysis modes: **email address risk analysis**, **email content scanning**, and **email authenticity verification**.

> 📋 **Change history:** see [`CHANGELOG.md`](./CHANGELOG.md) for a dated log
> of every model upgrade, dataset addition, and bug fix.

> **Public deployment safety:** outbound email-authenticity verification is disabled by default. The complete SMTP/DNS/WHOIS version must be deployed explicitly on your own computer and must not be exposed as an anonymous public endpoint.

---

## Table of Contents

- [Project Structure](#project-structure)
- [Features](#features)
- [Detection Modules](#detection-modules)
  - [Email Address Analysis](#1-email-address-analysis)
  - [Email Content Analysis](#2-email-content-analysis)
  - [Email Authenticity Verification](#3-email-authenticity-verification)
- [Model Performance](#model-performance)
- [Deployment Modes](#deployment-modes)
- [Quick Start — Web App](#quick-start--web-app)
- [Quick Start — ML Notebook](#quick-start--ml-notebook)
- [Testing](#testing)
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
| **Email Content Analysis** | Hybrid **ML + heuristic** classifier — TF-IDF (word + char n-gram) → CV-selected calibrated model (LogReg / LinearSVC / ComplementNB) trained on ~82 400 emails incl. 2026 LLM-grounded benchmarks (PhishNChips v5.2, PhishFuzzer), blended 55 / 45 with the 10-category keyword scan + 11 structural checks |
| **Email Authenticity Verification** | Local-only, opt-in 7-stage verification: format → DNS/MX → SMTP probe → PTR → SPF → DMARC → domain age |
| **Model Metrics Dashboard** | Live display of all classifiers' accuracy, F1, and ROC AUC (UCI URL-feature models + content classifier) |

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

A **hybrid ML + heuristic** scanner for email subject and body text. Combines:

1. **TF-IDF + auto-selected classifier** — trained on **~61 000 real emails**
   merged from three public corpora plus ~3 600 modern-style template samples.
   At startup the pipeline performs **3-fold CV model selection** across:
   - `LogisticRegression` (liblinear, balanced)
   - `CalibratedClassifierCV(LinearSVC)` — Platt-scaled SVM for trustworthy
     probabilities
   - `ComplementNB`
   
   The best model by CV ROC AUC is fit on the full training set. Feature space
   is a `FeatureUnion` of:
   - word 1–2 grams (semantic phrases)
   - `char_wb` 3–5 grams (catches obfuscation like `P@yP@l`, `Amaz0n`)

2. **Rule-based heuristic layer** — explainable keyword categories + structural
   checks (below)
3. **Score blending** — the final risk verdict combines the ML probability
   (55 %) and the heuristic score (45 %) into a `combined_phishing_score`

**Content Classifier — Test-set Metrics (n ≈ 16 500, 20 % hold-out)**

| Accuracy | Precision | Recall | F1-Score | ROC AUC | Training corpus |
|----------|-----------|--------|----------|---------|-----------------|
| **99.05 %** | **99.0 %** | **99.2 %** | **99.08 %** | **0.9996** | **~82 400 emails** (incl. 2026 LLM-grounded data) |

The training set now blends classic public corpora (Phishing_Email.csv,
CEAS_08, Nazario, ~59 k) with two **2026 LLM-grounded benchmarks**:
**PhishNChips v5.2** (2 387 emails grounded in live PhishTank /
OpenPhish / GitHub-Pages / Tranco URLs + modern workplace legit) and
**PhishFuzzer** (19 800 LLM variants over 3 300 real seeds; Spam class
dropped, Phishing/Valid kept for binary). See the *Datasets* section
below for full provenance.

The trained pipeline is pickled to `phishing-detection/data/content_model_cache.pkl`
(~3.6 MB) so subsequent server starts load in **< 50 ms** instead of the ~2-minute
initial training time.

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

This high-risk outbound feature is disabled on public deployments. To use it, deploy the project on your own computer with the explicit local settings shown below. Do not expose the enabled endpoint anonymously to the internet.

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

## Deployment Modes

Runtime behavior is controlled with environment variables. Safe defaults are listed in [`.env.example`](./.env.example).

| Variable | Default | Purpose |
|----------|---------|---------|
| `APP_ENV` | `production` | Selects production-safe or local development behavior |
| `ENABLE_EMAIL_VERIFICATION` | `false` | Enables outbound SMTP, DNS, PTR, SPF, DMARC, and WHOIS checks |
| `ALLOW_SYNTHETIC_DATA` | `false` | Allows a synthetic model dataset for local experimentation only |

Production mode rejects both high-risk verification and synthetic-data opt-in. A public deployment also requires the real dataset at `phishing-detection/data/phishing_dataset.csv`; startup fails with an actionable message when it is missing.

`APP_ENV=demo` is reserved for the included zero-cost Render demo. It permits a
clearly reported lightweight synthetic model, but it still rejects all live
SMTP, DNS, PTR, SPF, DMARC, and WHOIS verification requests.

For the complete local-only version:

```bash
cd website
APP_ENV=development \
ENABLE_EMAIL_VERIFICATION=true \
ALLOW_SYNTHETIC_DATA=true \
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Binding to `127.0.0.1` keeps the enabled verifier on your own computer. Use real data when evaluating model quality; synthetic data is only a development fallback.

### Zero-cost Render demo

The root-level [`render.yaml`](./render.yaml) deploys the safe public subset on
a free Render web service and gives it an HTTPS `*.onrender.com` address. In
Render, create a **Blueprint**, connect this repository, and approve the
detected `free` service.

The Blueprint prebuilds a single-worker synthetic content model sized for the
512 MB free instance. The public service keeps email-authenticity verification
disabled, enforces a 64 KB request limit and 20 POST requests per minute per IP,
checks allowed hostnames, and adds browser security headers. The free profile
is suitable for a class-project demo, not production or model-quality claims.

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

# 4. Ensure the real dataset exists for production mode
#    phishing-detection/data/phishing_dataset.csv
#    Run the ML notebook once to download/cache it, or provide a validated copy.

# 5. Start with safe public-service defaults
uvicorn app:app --host 0.0.0.0 --port 8000 --env-file ../.env.example
```

Then open **http://localhost:8000** in your browser.

> Production startup requires the real UCI dataset. Synthetic fallback is available only when explicitly enabled in local development mode.

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

## Testing

Backend tests use the Python standard library test runner; frontend tests use Node's built-in test runner:

```bash
# From the repository root, with website dependencies installed
python -m unittest discover -s website/tests -v
python -m compileall -q website phishing-detection/src
node --test website/static/app.test.mjs
node --check website/static/app.js
```

The same checks run automatically in GitHub Actions on pushes and pull requests. Live SMTP/WHOIS probes and full external model training are intentionally excluded from CI.

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

## Datasets

### 1. URL-feature dataset (email-address classifier + notebook)

- **Source:** [UCI ML Repository – Phishing Websites (ID 327)](https://archive.ics.uci.edu/ml/datasets/phishing+websites)
- **Size:** 11,055 rows × 30 features + 1 target
- **Label encoding:** `-1` = phishing → remapped to `0`; `1` = legitimate
- **Feature types:** Ternary integers `{-1, 0, 1}` encoding URL, domain, and HTML signals
- **Collection date:** 2012 (features reflect phishing techniques of that era)

### 2. Email-text datasets (content classifier)

The corpus blends **classic 2002-2008 public data** with **two 2026
LLM-grounded benchmarks**, all auto-downloaded by
`content_model.ensure_real_dataset()` on first server start:

| Corpus | Era | Rows | Phishing / Legit | Source | License |
|--------|-----|-----:|------------------|--------|---------|
| `Phishing_Email.csv` | 2002-2007 | 18 631 | 7 309 / 11 322 | [HF mirror of Kaggle *Phishing Email Detection*](https://huggingface.co/datasets/zefang-liu/phishing-email-dataset) (Cyber Cop) | LGPL-3.0 |
| `CEAS_08.csv` | 2008 | 39 127 | 21 841 / 17 286 | [Champa et al. 2024 — Zenodo 8339691](https://zenodo.org/records/8339691) (CEAS 2008 challenge) | CC-BY-4.0 |
| `Nazario.csv` | 2005-2008 | 1 562 | 1 562 / 0 | [Champa et al. 2024 — Zenodo 8339691](https://zenodo.org/records/8339691) (Nazario phishing corpus) | CC-BY-4.0 |
| `phishnchips_*.csv` (core + cross-domain + infra) | **Apr 2026** | 2 387 | 1 054 / 1 333 | [AreLit/PhishNChips v5.2](https://huggingface.co/datasets/AreLit/PhishNChips) — emails grounded in live PhishTank / OpenPhish / GitHub-Pages / Tranco URLs + modern workplace legit | MIT |
| `phishfuzzer_{train,val,test}.csv` | **Nov 2026** | 13 356 (Spam dropped) | 6 756 / 6 600 | [hai123xz/PhishFuzzer-split](https://huggingface.co/datasets/hai123xz/PhishFuzzer-split) — LLM (Gemini-2.5-Flash) variants over 3 300 real seeds; 3-class → binary | CC-BY-4.0 |
| **Real total** | mixed | **75 063** | **38 522 / 36 541** | | |
| Synthetic templates | 2024-2026 | ~5 600 | ~2 800 / ~2 800 | Generated in `content_model.py` (`n_variants=160` × ~35 templates) | — |
| **Grand total** | | **~80 700** | balanced | | |

**Why blend the two 2026 LLM-grounded corpora in:**
- **PhishNChips v5.2** anchors the model to *real* 2026 phishing
  infrastructure (PhishTank-grounded URLs, GitHub Pages phishing,
  IPFS-hosted lures, URL shorteners, infrastructure phishing) and to
  *modern legitimate workplace* patterns (Google Workspace, M365,
  e-signature, finance tools, HR / IT portals).
- **PhishFuzzer** brings ~13 k LLM-generated variants of contemporary
  brand-impersonation lures (Dropbox, Xerox, ICAO, DocuSign, etc.) plus
  matched legit examples — invaluable for teaching the model to
  distinguish brand-issued transactional email from brand-impersonating
  phishing.
- Synthetic templates (now 35+ legit categories, 160 variants each) are
  still needed for *brand-issued transactional* emails (Amazon shipping,
  Stripe payout, DocuSign envelope from the brand itself, mortgage
  statements, 2FA backup-code emails) — those are not strongly
  represented in any single public corpus. Without them the
  PhishFuzzer brand-impersonation signal would dominate and produce
  legit false positives on the real things.

**Model selection:** at training time `build_content_pipeline` runs
3-fold ROC-AUC cross-validation across `LogisticRegression`,
`CalibratedClassifierCV(LinearSVC)`, and `ComplementNB`. A tie-break
prefers LogReg whenever the AUC gap is < 0.001, because its sigmoid
output is naturally well-calibrated at the decision boundary (Platt
calibration on LinearSVC was producing brittle 50–60 % probabilities
for boundary samples like legitimate Amazon-shipping emails).

---

*CS 166 – Information Security | Final Project*
