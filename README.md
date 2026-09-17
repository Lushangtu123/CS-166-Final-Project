# CS 166 Final Project — Phishing & Scam Email Detection

> **Course:** CS 166 – Information Security  
> **GitHub:** https://github.com/Lushangtu123/CS-166-Final-Project

PhishGuard is a FastAPI web application for explainable phishing-email
screening. It supports three distinct workflows:

- sender/domain risk analysis from an email address;
- message analysis from subject/body text or a complete RFC 5322 `.eml` file;
- optional, local-only DNS/SMTP/WHOIS authenticity checks.

The UCI Phishing Websites model in this repository is retained as a separate
course benchmark. Its URL/HTML weights are **not** used as an email-sender
classifier, because those features do not represent the same input domain.

See [`CHANGELOG.md`](./CHANGELOG.md) for the dated change history.

## Detection design

### Sender/domain mode

`POST /api/analyze-email` returns an explainable `risk_score`, not a trained
probability. Signals include:

- look-alike brand names and phishing keywords in untrusted domains;
- risky TLDs, IP-literal domains, excessive subdomains, and unusual syntax;
- confirmed disposable-provider domains, separated from privacy relays;
- anchored disposable-domain patterns and multi-factor auto-generated mailbox
  patterns, reported as suspicion rather than proof;
- plus-address aliases and Gmail dot normalization without added risk.

Disposable-email results include `disposable_status`,
`disposable_confidence`, `matched_provider_domain`, and
`address_alias_type`. A domain-list match confirms only the provider category;
it does not establish how long an individual mailbox exists or that its sender
is malicious.

The response declares `analysis_method: sender-domain-heuristics` so callers do
not confuse the score with model confidence. A low sender score does not prove a
message is safe; compromised legitimate accounts require full-message analysis.

### Full-message mode

`POST /api/analyze-content` accepts `subject` and `body`, or `raw_email` for a
complete message. Raw input enables additional checks:

- SPF, DKIM, and DMARC results from explicitly trusted authentication servers;
- protected-brand display-name and Unicode/IDN domain impersonation;
- From / Reply-To / Return-Path domain mismatches;
- the same sender/domain heuristics used by the sender-only workflow;
- executable, macro-enabled, disk-image, and archive attachment extensions or
  MIME types;
- every HTML, Markdown, and plain-text link destination, including displayed-host
  mismatch, Unicode/IDN and ASCII digit-substitution lookalikes, URL userinfo,
  deceptive brand subdomains, and credential-themed domains;
- IP-based and shortened URLs, urgency, credential requests, threats, and
  character obfuscation.

Safety-footer phrases such as “unsubscribe” and “privacy policy” are reported
as context but never subtract risk: an attacker can copy them. Regional English
phrasing is not scored as malicious.

### Optional text classifier

The web service defaults to rules-only analysis. When `CONTENT_MODEL_ENABLED=true`,
the content endpoint loads a SHA-256-verified offline artifact containing the
word and character n-gram TF-IDF classifier. Web startup never downloads data or
trains a model. Its offline evaluation pipeline is designed around missed-phishing
risk:

1. Messages are normalized across all sources before splitting; duplicate
   families are removed and label-conflicting families are excluded.
2. Source-record/template IDs and PhishNChips campaign URLs receive group IDs;
   corpora without usable metadata use source-independent normalized hashes.
3. The held-out split and model-selection folds use `StratifiedGroupKFold`.
4. Models are selected by cross-validated PR AUC, which is more informative for
   imbalanced phishing detection than ROC AUC alone.
5. TF-IDF is fitted inside each cross-validation pipeline, preventing vocabulary
   leakage.
6. The phishing decision threshold is selected from training-fold out-of-fold
   predictions by maximizing F2, which weights recall more heavily.
7. Reports include phishing recall, false-negative rate, PR AUC, ROC AUC, Brier
   score, threshold, split strategy, and train/test group overlap.

Structural/rule evidence and ML evidence are fused conservatively: weak model
evidence cannot average away a strong authentication or message-structure
signal.

## Project structure

```text
CS-166-Final-Project/
├── phishing-detection/          # UCI phishing-website notebook benchmark
│   ├── data/                    # optional local email corpora and caches
│   ├── notebooks/
│   └── src/
├── website/
│   ├── app.py                   # API and explainable content rules
│   ├── content_model.py         # group-isolated optional text model
│   ├── email_structure.py       # RFC 5322/MIME/header analysis
│   ├── config.py
│   ├── prebuild_demo_model.py   # explicit offline artifact builder
│   ├── static/
│   └── tests/
├── render.yaml                  # safe rules/structure-only public demo
└── CHANGELOG.md
```

## API overview

| Endpoint | Purpose |
|---|---|
| `POST /api/analyze-email` | Explainable sender/domain risk |
| `POST /api/analyze-content` | Subject/body or raw-message analysis |
| `POST /api/verify-email` | Local-only network authenticity checks |
| `GET /api/metrics` | Archived UCI website benchmark and optional live text-model metrics |
| `GET /api/config` | Public feature flags |
| `GET /health` | Detector availability and deployment profile |

Example raw-message request:

```json
{
  "raw_email": "From: Example <notice@example.com>\nReply-To: help@lookalike.example\nSubject: Action required\n\nReview your account."
}
```

Keep `TRUSTED_AUTHSERV_IDS` empty unless you know which receiving mail system
created the uploaded message's authentication results. The upstream receiver
must remove attacker-supplied copies of its own authentication-service ID before
adding its result. Untrusted header claims are returned for inspection but
cannot increase or suppress risk.

## Runtime configuration

| Variable | Default | Purpose |
|---|---:|---|
| `APP_ENV` | `production` | `development`, `demo`, `production`, or `test` |
| `ENABLE_EMAIL_VERIFICATION` | `false` | Enables outbound DNS/SMTP/WHOIS checks; rejected in public modes |
| `CONTENT_MODEL_ENABLED` | `false` | Loads a verified offline email-text artifact |
| `CONTENT_MODEL_ARTIFACT` | empty | Path to the trusted artifact created by `prebuild_demo_model.py` |
| `CONTENT_MODEL_ARTIFACT_SHA256` | empty | Required SHA-256 digest for the configured artifact |
| `TRUSTED_AUTHSERV_IDS` | empty | Comma-separated authentication service IDs allowed to affect raw-message risk |
| `RATE_LIMIT_BUCKET_CAPACITY` | `4096` | Hard bound for in-process rate-limit keys |
| `CONTENT_MODEL_USE_REAL` | profile-dependent | Offline training: load local public corpora |
| `CONTENT_MODEL_AUTO_DOWNLOAD` | profile-dependent | Offline training: download configured public corpora when missing |
| `CONTENT_MODEL_USE_CACHE` | `false` | Offline training: explicitly trust/load the local pickle cache |
| `CONTENT_MODEL_AUGMENT_SYNTHETIC` | `false` | Opts into bundled template augmentation for experiments |

The included Render blueprint explicitly sets `CONTENT_MODEL_ENABLED=false`
and `ENABLE_EMAIL_VERIFICATION=false`. The public
demo therefore starts reliably with sender, header, structure, and content-rule
analysis, without presenting a synthetic model as production evidence.

For local research with the text model, train and package it before starting the
web service:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r website/requirements.txt
cd website
python prebuild_demo_model.py --output ../phishing-detection/data/content_model_artifact.pkl
# Copy the printed SHA-256 value into CONTENT_MODEL_ARTIFACT_SHA256.
APP_ENV=development CONTENT_MODEL_ENABLED=true \
  CONTENT_MODEL_ARTIFACT=../phishing-detection/data/content_model_artifact.pkl \
  CONTENT_MODEL_ARTIFACT_SHA256=REPLACE_WITH_PRINTED_SHA256 \
  uvicorn app:app --host 127.0.0.1 --port 8000
```

Only load artifacts produced and stored by a trusted build process. The digest
is checked before deserialization, and Python/scikit-learn compatibility metadata
is validated afterward.

To opt into network-based mailbox verification locally, additionally set
`ENABLE_EMAIL_VERIFICATION=true`. Do not expose that endpoint anonymously.

## Data and evaluation scope

### UCI website benchmark

The notebook uses the [UCI Phishing Websites dataset](https://archive.ics.uci.edu/dataset/327/phishing+websites):
11,055 rows with 30 URL, domain, and HTML features. Historical results shown in
the UI are explicitly labeled as a **website benchmark**, not email accuracy.

### Email-text corpora

The optional content model can load:

| Local file | Source/type | Automatic download |
|---|---|---:|
| `Phishing_Email.csv` | Public phishing-email mirror | Yes |
| `CEAS_08.csv` | CEAS 2008 via Zenodo | Yes |
| `Nazario.csv` | Nazario corpus via Zenodo | Yes |
| `phishnchips_*.csv` | Modern synthetic benchmark data | Yes |
| `phishfuzzer_{train,val,test}.csv` | Optional local three-class export | No |

Synthetic benchmark and template data can improve coverage but do not establish
real-world effectiveness. Report metrics only with the exact `data_source`,
`split_strategy`, threshold, and false-negative rate returned by the trained
pipeline. A future production evaluation should use a time-separated,
organization-representative holdout that is never used for threshold tuning.

### Observed email-text evaluation — 2026-09-15

The updated Logistic Regression pipeline was evaluated without bundled template
augmentation on 61,707 raw rows from the six downloaded corpus files listed by
the runtime. Global normalization retained 53,841 rows after removing 7,333
duplicate rows and 533 rows from label-conflicting families. The split kept
normalized message families, source families, and shared PhishNChips campaign
URLs together. Candidate models were selected by cross-validated PR AUC.

| Metric | Result |
|---|---:|
| Retained rows after normalization | 53,841 |
| Held-out rows | 10,768 |
| Accuracy | 98.89% |
| Precision | 97.88% |
| Phishing recall | 99.78% |
| False-negative rate | 0.22% |
| F1 | 98.82% |
| ROC AUC | 0.9996 |
| PR AUC | 0.9996 |
| Brier score | 0.0069 |
| Learned F2 threshold | 0.3515 |
| Recall at default 0.5 threshold | 99.38% |
| Recall gain from learned threshold | +0.40 percentage points |
| Train/test group overlap | 0 |

These are offline corpus results, not a production claim. PhishNChips is
synthetic, the older corpora lack campaign identifiers beyond normalized
content-family grouping, and the holdout is not time-separated. Live-email drift,
organization-specific false positives, image-only lures, QR codes, and
attachment contents remain outside this evaluation.

The included public Render profile still keeps the optional text model disabled
until a representative, versioned artifact is supplied through a trusted build
process. Rules and message-structure analysis remain available without it.

## Testing

```bash
# From repository root, after installing website dependencies
python -m unittest discover -s website/tests -v
python -m compileall -q website phishing-detection/src
node --test website/static/app.test.mjs
node --check website/static/app.js
git diff --check
```

The regression suite covers sender-score semantics, authentication-service
trust, protected-brand/IDN impersonation, SMTP public-address enforcement,
bounded rate limiting, verified model artifacts, HTML destination mismatch,
ASCII brand lookalikes, URL userinfo, attachment MIME types, raw-message sender
fusion, footer spoofing, regional-language neutrality, conservative evidence
fusion, group isolation, deployment flags, and frontend payload/rendering
behavior. Disposable-address regressions cover multi-label provider domains,
random-looking Gmail and Outlook mailboxes, privacy relays, plus aliases, Gmail
dot variants, and collision domains that must remain unclassified.

## Historical benchmark results

These values come from the UCI **website** notebook and are preserved for course
reproducibility only:

| Classifier | Accuracy | F1 | ROC AUC |
|---|---:|---:|---:|
| Random Forest | 0.9747 | 0.9746 | 0.9977 |
| SVM (RBF) | 0.9516 | 0.9515 | 0.9893 |
| Decision Tree | 0.9480 | 0.9480 | 0.9865 |
| Logistic Regression | 0.9285 | 0.9284 | 0.9808 |

Do not use these numbers to describe sender-address or full-email detection.

---

*CS 166 – Information Security | Final Project*
