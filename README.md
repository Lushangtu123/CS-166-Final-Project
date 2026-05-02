# CS 166 Final Project — Phishing & Scam Email Detection

> **Course:** CS 166 – Information Security  
> **GitHub:** https://github.com/Lushangtu123/CS-166-Final-Project

A full-stack phishing / scam-email detection system built on a Random Forest classifier trained on the UCI Phishing Websites Dataset. The project includes a reproducible ML pipeline and an interactive web application where users can analyze any email address for phishing risk, disposable-address usage, and auto-generated username patterns.

---

## Table of Contents

- [Demo Screenshot](#demo-screenshot)
- [Project Structure](#project-structure)
- [Features](#features)
- [Model Performance](#model-performance)
- [Quick Start — Web App](#quick-start--web-app)
- [Quick Start — ML Notebook](#quick-start--ml-notebook)
- [Tech Stack](#tech-stack)
- [Feature Engineering](#feature-engineering)
- [Disposable Email Detection](#disposable-email-detection)
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
│   ├── app.py                            # FastAPI backend
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
| **Email Analysis** | Enter any email address and get a full phishing risk breakdown |
| **ML Prediction** | Random Forest classifier returns phishing probability (%) |
| **Risk Indicators** | Detailed list of specific warning signs found in the address |
| **Top Feature Breakdown** | Top 10 features driving the prediction, with importance bars |
| **Confirmed Disposable** | 500+ known disposable/temporary email domains detected exactly |
| **Suspected Disposable** | Multi-factor heuristic detects auto-generated addresses on unknown domains |
| **Model Metrics** | Live display of all four classifiers' accuracy, F1, ROC AUC |

### Disposable Email Detection — Three States

| State | Color | Trigger |
|-------|-------|---------|
| 🟣 **Confirmed Disposable** | Purple | Domain found in 500+ provider database or pattern match |
| 🟠 **Suspected Disposable** | Amber | Auto-generated username heuristic (6-factor score ≥ 2) |
| 🟢 **Not Disposable** | Green | Neither check triggered |

**Auto-generated username heuristic factors:**

| Factor | Description |
|--------|-------------|
| F1 Shannon Entropy > 3.0 | High entropy = uniform character spread = random |
| F2 Vowel ratio ≤ 30% | Real words have more vowels than random strings |
| F3 Digits scattered inside | Auto-generators embed digits throughout (not just at the end) |
| F4 Unique-char ratio ≥ 75% | Random strings rarely repeat characters |
| F5 No embedded English word | Legitimate usernames contain readable names or words |
| F6 Non-name word.word combo | `word.word` separators not matching first.last name patterns |

Legitimate `firstname.lastname` patterns (`alice.smith`, `john.doe`) are exempted via a curated name database of ~120 first names and ~100 last names.

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

1. `sslfinal_state` (32.0%) — mapped to *Known Legit Provider* for email
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

# 4. Start the server
uvicorn app:app --host 0.0.0.0 --port 8000
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

### Frontend
- **HTML5 / CSS3 / Vanilla JavaScript**
- **Chart.js** — model performance charts
- Dark-theme responsive UI with animated probability bars

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

## Disposable Email Detection

### Known Provider Database (500+ domains)

Includes all major disposable email families:

- **Mailinator** family (mailinator.com, mailinator.net, …)
- **Guerrilla Mail** (guerrillamail.com/.net/.org/.de, sharklasers.com, grr.la, …)
- **10 Minute Mail** (10minutemail.com, 20minutemail.com, 60minutemail.com, …)
- **YOPmail** (yopmail.com/.fr, jetable.fr.nf, …)
- **Temp-Mail** (tempmail.com/.net/.org, temp-mail.org/.io, …)
- **Trash Mail** (trashmail.com/.me/.net/.at, discardmail.com, …)
- **Maildrop / Mailnull** (maildrop.cc, mailnull.com, mailnesia.com, …)
- **Burner / Wegwerf** (burnermail.io, wegwerfadresse.de, …)
- **Spam services** (spambox.us, spamgourmet.com, spamfree24.org, …)
- **And 400+ more** including international, pattern-matched, and user-reported domains

### Pattern-Based Detection

Domain labels are also scanned for keywords like `tempmail`, `throwaway`, `trashmail`, `disposable`, `guerrilla`, `mailinator`, `wegwerf`, `burnermail`, and 50+ more.

---

## Dataset

- **Source:** [UCI ML Repository – Phishing Websites (ID 327)](https://archive.ics.uci.edu/ml/datasets/phishing+websites)
- **Size:** 11,055 rows × 30 features + 1 target
- **Label encoding:** `-1` = phishing → remapped to `0`; `1` = legitimate
- **Feature types:** Ternary integers `{-1, 0, 1}` encoding URL, domain, and HTML signals
- **Collection date:** 2012 (features reflect phishing techniques of that era)

---

*CS 166 – Information Security | Final Project*
