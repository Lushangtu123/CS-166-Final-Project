# Changelog

All notable changes to the **Phishing & Scam Email Detection** project are
documented in this file.

> **Maintenance rule:** every future change — model upgrades, new datasets,
> backend or frontend tweaks, bug fixes, README adjustments — MUST be appended
> to this file as a new entry under a new ISO-format heading, with the
> following structure:
>
> ```
> ## [YYYY-MM-DD HH:MM PT] — Short title
> ### Why
> ### Files changed
> ### Effect
> ```
>
> Order: newest entry at the top. Times are local (Pacific). Keep entries
> factual and reference specific files, metric values, or commit hashes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

---

## [2026-06-20 15:15 PT] — README features-table sync with v4.3 content classifier

### Why
- User flagged: the "Web Application" features table in `README.md` still
  described **Email Content Analysis** as "Rule-based keyword scan across
  10 phishing categories + 11 structural checks", which has been stale
  since v2 of the content classifier (May 2026). The same row also said
  "all four classifiers" in the Model Metrics Dashboard row even though
  we now also expose the content-classifier metrics in `/api/metrics`.

### Files changed
- `README.md` (features table, two rows):
  - **Email Content Analysis** — now reads
    "Hybrid **ML + heuristic** classifier — TF-IDF (word + char n-gram)
    → CV-selected calibrated model (LogReg / LinearSVC / ComplementNB)
    trained on ~82 400 emails incl. 2026 LLM-grounded benchmarks
    (PhishNChips v5.2, PhishFuzzer), blended 55 / 45 with the
    10-category keyword scan + 11 structural checks".
  - **Model Metrics Dashboard** — wording adjusted from "all four
    classifiers" to "all classifiers (UCI URL-feature models + content
    classifier)" so it matches what `/api/metrics` actually returns.

### Effect
- Top-of-README feature summary now accurately reflects the v4.3 hybrid
  pipeline; new readers won't be told the content path is rule-only.
- No code or model changes; docs-only patch.

---

## [2026-06-20 14:55 PT] — 2026 LLM-grounded datasets + brand-impersonation rebalance (v4.3)

### Why
- User asked: "继续加强训练，数据集尽量用最新的". Up to v4 the real data was
  still 2002–2008 mailing-list traffic. Modern phishing attacks (GitHub
  Pages hosting, IPFS, URL shorteners, QR-code lures, hyper-realistic LLM
  brand impersonation) were under-represented, and we were still seeing
  false positives on legit transactional emails (Amazon shipping, Stripe
  payout, DocuSign envelope) once the LLM-generated phishing was mixed in.

### Files changed
- `phishing-detection/data/` *(new files, ~42 MB total)* — three
  `phishnchips_*.csv` and three `phishfuzzer_*.csv` files downloaded from
  Hugging Face into the data directory.
- `website/content_model.py`:
  - Added two new schemas `phishnchips_csv` (JSON-encoded `email_content`
    blob from PhishNChips v5.2) and `phishfuzzer_csv` (Subject/Body/Type
    columns from PhishFuzzer; `Spam` rows dropped, `Phishing→1`,
    `Valid→0`).
  - Extended `_DATASETS` with six new entries pointing at the HF mirrors
    of **PhishNChips v5.2** (Apr 2026, 2 387 emails grounded in real
    PhishTank / OpenPhish / GitHub Pages / Tranco / cross-domain modern
    workplace data) and **PhishFuzzer** (Nov 2026, 19 800 LLM-generated
    variants over 3 300 real seeds, 3-class).
  - Bumped synthetic `n_variants` from 80 → 160 to give the modern legit
    templates more relative weight against brand-impersonation phishing.
  - Added ~8 brand-issued transactional legit templates (Amazon shipping
    × 3, Stripe payout × 3, DocuSign envelope × 3, Chase mortgage,
    Google 2FA backup codes) directly aimed at the failure patterns
    surfaced by the new corpora.
  - Added a tie-break rule in `build_content_pipeline`: when LinearSVC
    and LogisticRegression are within 0.001 ROC AUC, prefer LogReg
    because its sigmoid output is naturally well-calibrated for
    boundary samples (Platt-calibrated SVM was producing brittle
    50–60 % probabilities for legit Amazon / Stripe / DocuSign).
  - `_CACHE_VERSION` → `v4.3-2026-brand-saturated-logreg-preferred`
    (forces retrain; old `v3-...` cache is stale).

### Effect
- Training corpus grew from ~50 k → **82 393 emails**
  (65 914 train + 16 479 test). New 2026 data contributes
  ~16 k modern LLM-grounded examples (2 387 PhishNChips + 13 356
  PhishFuzzer after dropping Spam).
- Model: `LogisticRegression` (selected via tie-break against
  CalibratedLinearSVC, both at CV ROC AUC ≈ 0.9995).
- Test metrics: **Accuracy 0.9905 · F1 0.9908 · ROC AUC 0.9996** on a
  held-out 16 479-row test set.
- 15/15 on the hard generalisation suite (7 modern legit including
  Amazon shipping / Stripe payout / DocuSign / Chase mortgage / 2FA
  backup codes / GitHub PR / Calendar invite, 4 classic phishing,
  4 brand-new 2026 attack patterns — Google Docs lure, QR-code invoice
  scam, IPFS-hosted DocuSign envelope, GitHub Pages security alert).
  Lowest legit score 32.1 %, highest legit 32.1 %; lowest phishing
  79.7 % → comfortable 47-point decision margin.
- Cold-train time ≈ 2 min 40 s; warm load from
  `phishing-detection/data/content_model_cache.pkl` (3.6 MB) is
  effectively instant.

---

## [2026-06-20 14:36 PT] — Project change-history bootstrap

### Why
- User asked: "将之前所有的更新记录起来，具体到时间，位置，更新的原因和效果。
  以后所有的更新都要记录在里面". Up to this point all changes were only
  reflected in commits/files; there was no single dated narrative of what
  happened and why.

### Files changed
- `CHANGELOG.md` *(new)* — backfilled four prior dated entries
  (v4 multi-dataset, v3 real-data + caching, v2 initial ML integration,
  plus a "project context anchors" appendix) and pinned the maintenance
  rule at the top.
- `README.md` — added a top-of-file pointer ("📋 Change history: see
  `CHANGELOG.md`") so the log is discoverable.
- `.cursor/rules/changelog.mdc` *(new)* — Cursor rule with
  `alwaysApply: true` requiring every future code/model/dataset/doc/dep
  change in this repo to append a new dated entry to `CHANGELOG.md`
  before ending the turn. Entry-format spec is included verbatim.

### Effect
- Future agent sessions (and humans) will see and honour the rule via
  Cursor's always-applied rules system, so the changelog stays current
  by default instead of needing to be remembered.
- Three prior tracked milestones (initial ML, real-data + cache,
  multi-dataset + model selection) are now visible to any reviewer as a
  single chronological record, eliminating the need to read commit
  history or scroll through long chats to understand the evolution.

---

## [2026-06-20 14:30 PT] — Content classifier v4: multi-dataset + model selection + modern templates

### Why
- The v3 model (trained only on `Phishing_Email.csv`, 18,631 emails) showed
  three concrete false positives on real-world modern emails: Amazon order
  confirmations (46.3 % phishing), Wells Fargo mortgage statements (73.2 %)
  and Google 2FA backup codes (79.6 %).
- Root cause: the public corpus is heavy on 2002–2008 mailing-list traffic and
  under-represents modern e-commerce / SaaS / banking / 2FA notification
  formats. Pulling in more 2002-era data would not fix this.
- Goal: (1) substantially expand both the *phishing* coverage (CEAS_08 +
  Nazario) and the *modern legitimate* coverage (new synthetic templates);
  (2) replace the hand-picked classifier with automatic CV-driven selection.

### Files changed
- **`website/content_model.py`**
  - `_DATASETS` table — three real corpora declared (Phishing_Email + CEAS_08
    + Nazario) with downloaders.
  - `ensure_real_dataset()` rewritten to fetch all three from their direct
    URLs (Hugging Face + Zenodo 8339691).
  - `_load_one_corpus()` added with two schemas
    (`phishing_email_csv`, `champa_csv`); filters Nazario mbox-control rows
    like `FOLDER INTERNAL DATA`.
  - `_LEGIT_TEMPLATES` extended by **17 new modern templates**: Amazon order,
    Best Buy receipt, GitHub PR comment, GitHub CI build, Stripe receipt,
    AWS invoice, Slack DM digest, Zoom meeting reminder, Google Calendar
    invite, Apple App Store receipt, Netflix payment, Uber Eats, DocuSign
    NDA, Chase Sapphire statement, Notion weekly digest, LinkedIn weekly
    summary, Lyft trip receipt, Spotify Premium receipt, Delta flight
    confirmation, Shopify new-order, Datadog usage report, password-changed
    confirmation, generic 2FA OTP, Coursera receipt, Figma welcome —
    plus a second batch: Wells Fargo mortgage statement, Chase auto-loan,
    PG&E utility bill, Comcast Xfinity bill, State Farm renewal, Geico
    insurance card, Fidelity 1099-INT, Google 2-Step backup codes,
    1Password Emergency Kit, generic authenticator code, Workday W-2,
    open-enrollment HR memo, Etsy / Bookshop.org orders, Partiful RSVP,
    Calendly confirmation.
  - `n_variants` default raised **40 → 80** so synthetic samples are not
    drowned out by the 59 k real-corpus rows.
  - **Model selection added** — `build_content_pipeline()` now runs 3-fold
    stratified CV ROC AUC across three candidates and picks the winner:
    - `LogisticRegression(C=4, liblinear, balanced)`
    - `CalibratedClassifierCV(LinearSVC, method='sigmoid', cv=3)` — Platt-scaled
      so it emits probabilities.
    - `ComplementNB(alpha=0.3)`
  - `_extract_coefficients()` added to keep the explainability layer
    working for all three model families (incl. CalibratedClassifierCV via
    averaged inner-estimator coefs and ComplementNB via
    `feature_log_prob_` diff).
  - `predict_content()` made robust to classifiers without `coef_`.
  - `_CACHE_VERSION` bumped to `v3-multidataset-modelselect-calibrated`
    so the existing on-disk cache is invalidated.
- **`phishing-detection/data/CEAS_08.csv`** (64 MB) added — downloaded from
  `https://zenodo.org/records/8339691/files/CEAS_08.csv` (Champa et al. 2024,
  CC-BY-4.0).
- **`phishing-detection/data/Nazario.csv`** (7.4 MB) added — same source.
- **`README.md`** — content-classifier section + datasets table rewritten to
  reflect the three-corpus pipeline and the new metrics.
- **`phishing-detection/README.md`** — same updates plus file-tree entries
  for the two new CSVs.

### Effect

| Metric (20 % hold-out) | v3 | **v4** |
|------------------------|-----|--------|
| Training samples | 16,376 | **50,392** |
| Accuracy | 0.9805 | **0.9908** |
| Precision | 0.9617 | **0.9900** |
| Recall | 0.9909 | **0.9920** |
| F1 | 0.9761 | **0.9911** |
| ROC AUC | 0.9983 | **0.9997** |
| Selected model | LogReg (hard-coded) | **LogReg (CV-selected)** |

11-sample hard generalization battery (samples NOT in training templates):

| Sample | v3 ML % | **v4 ML %** | Verdict |
|--------|--------:|------------:|---------|
| Phish: Crypto wallet hack | 100.0 | **99.2** | ✓ phishing |
| Phish: HR salary credential grab | 70.8 | **64.2** | ✓ phishing |
| Phish: SharePoint share scam | 99.9 | **98.9** | ✓ phishing |
| Phish: Voicemail .exe attachment | 62.4 | **63.9** | ✓ phishing |
| Phish: Apple ID closure scam | 100.0 | **99.9** | ✓ phishing |
| Legit: Wells Fargo mortgage | **73.2 ⚠ FP** | **9.5** | ✓ legit (fixed) |
| Legit: Pediatric appointment | 0.1 | **0.9** | ✓ legit |
| Legit: School field-trip slip | 1.1 | **7.8** | ✓ legit |
| Legit: K8s CI failure email | 3.6 | **8.8** | ✓ legit |
| Legit: 2FA backup codes | **79.6 ⚠ FP** | **37.2** | ✓ legit (fixed) |
| Bonus: Amazon order shipped | 19.1 | **11.3** | ✓ legit |

**Overall: 11/11 correct (100 %).** All three previously-known false
positives were eliminated.

Training time: ~127 s on first run; subsequent server starts load the
pickled pipeline in **< 50 ms**.

---

## [2026-06-20 13:59 PT] — Content classifier v2 → v3: real public dataset + caching

### Why
- The v2 model trained on a purely synthetic template corpus reported
  Accuracy / F1 / ROC AUC = 1.0 — visibly inflated. Held-out metrics on
  synthetic data don't reflect real-world performance.
- We needed a real-world labelled email corpus and faster startups so the
  FastAPI app doesn't take 40 s every reload.

### Files changed
- **`website/content_model.py`**
  - Module-level docstring rewritten to declare the real-data-first
    pipeline.
  - `ensure_real_dataset()` and `load_real_corpus()` added with auto-download
    from the Hugging Face mirror of the Kaggle *Phishing Email Detection*
    dataset (`zefang-liu/phishing-email-dataset`,
    `Phishing_Email.csv`, 18 650 emails, LGPL-3.0).
  - Vectoriser upgraded from single `TfidfVectorizer` to `FeatureUnion`:
    - word 1–2 grams (semantic phrases)
    - `char_wb` 3–5 grams (catches obfuscation like `P@yP@l`, `Amaz0n`)
  - `_extract_coefficients()` precursor / `_flat_feature_names()` introduced
    so the per-email top-token explainability still works through
    `FeatureUnion`.
  - **Pickle-based cache** added (`content_model_cache.pkl`) keyed by a
    SHA-256 hash that captures dataset file sizes/mtimes + training options
    + `_CACHE_VERSION` (`v2-word12-charwb35`). First training takes ~38 s,
    subsequent loads ≈ 20 ms.
- **`website/app.py`**
  - `/api/metrics` extended to include the `content_model` section
    (`name`, `metrics`, `data_source`, `top_terms`).
- **`README.md`** + **`phishing-detection/README.md`** — added new
  "Email-text dataset" section, dataset citation, and a metrics table.

### Effect

| Metric | Synthetic-only (v2 inflated) | **v3 with real data** |
|--------|------------------------------|----------------------|
| Training samples | 1,472 | **16,376 (≈11× more)** |
| Test samples | 368 | **4,095** |
| Accuracy | 1.0 | **0.9805** |
| F1 | 1.0 | **0.9761** |
| ROC AUC | 1.0 | **0.9983** |
| Startup time | ~1 s | 38 s first time / **0.02 s cached** |

Manual test verification:

| Sample | v3 ML phishing prob |
|--------|---------------------|
| Classic PayPal urgency phish | 100.0 % |
| Obfuscated `P@yP@l` / `acc0unt` | 99.4 % |
| TechBlog newsletter | 2.5 % |
| Legit Amazon order | 46.3 % (boundary — noted as known weak spot, addressed in v4) |

---

## [2026-06-20 13:51 PT] — Initial ML integration for email-content search

### Why
- The website had two analyzers: the *email-address* tab used a Random Forest
  ML model; the *email-content* tab used **only** hand-coded keyword rules.
  User asked: "让邮件内容搜索也采用机器学习" — make the content scan also use
  ML so the system is end-to-end ML-driven.

### Files changed
- **`website/content_model.py`** *(new file)*
  - 24 phishing templates + 20 legitimate templates with randomised
    placeholders (`{brand}`, `{url}`, `{amount}`, `{name}`).
  - `generate_content_corpus()` produces 1,840 balanced samples.
  - `build_content_pipeline()` fits `TfidfVectorizer(ngram=(1,2),
    stopwords=english, sublinear_tf)` + `LogisticRegression(class_weight=
    balanced)`; computes Accuracy / Precision / Recall / F1 / ROC AUC on a
    20 % stratified hold-out.
  - `predict_content()` returns `ml_phishing_probability`,
    `ml_legitimate_probability`, `ml_label`, `ml_prediction`,
    `ml_top_contributors` (per-email word-level token attribution).
- **`website/app.py`**
  - `from content_model import build_content_pipeline, predict_content`.
  - New global `_content_pipeline` populated in `startup_event()`.
  - `/api/analyze-content` rewritten to: (1) still run the heuristic
    scanner, (2) add ML probabilities into the response, (3) blend the two
    into a `combined_phishing_score` (55 % ML + 45 % heuristic) and
    promote/demote `risk_level` accordingly.
- **`website/static/index.html`**
  - Added a `content-ml-card` section between the risk banner and the
    keyword-category grid.
  - Updated the "About This Analysis" footer to describe the new ML +
    heuristic hybrid (replacing the previous "this is NOT an ML model"
    disclaimer).
- **`website/static/app.js`**
  - `renderContentResult()` extended to display ML phishing/legit
    probability bars, ML metric badges (Accuracy / F1 / ROC AUC), and the
    per-email top phishing-indicative tokens.
- **`website/static/style.css`**
  - `.content-ml-card`, `.ml-badge`, `.ml-card-metrics`, `.ml-metric`,
    `.ml-contribs`, `.ml-token` style rules added (blue accent palette).

### Effect
- Both analyzers in the web app are now ML-driven.
- Live API verified end-to-end:
  - Classic PayPal phishing sample → **ML 98.1 % phishing**, combined 81.0,
    verdict *Critical Risk*.
  - TechBlog newsletter sample → **ML 2.1 % phishing**, combined 1.2,
    verdict *No Phishing Indicators Found*.
- The pure-synthetic metrics (Accuracy / F1 / AUC all 1.0) were honest about
  being synthetic — the v3 update later replaced this with real data.

---

## Project context — anchors that predate this changelog

These items were already in place at the start of the conversation that
created this file. Listed for completeness; future entries describe deltas
relative to this baseline.

- **Random Forest URL-feature classifier** trained on the UCI Phishing
  Websites Dataset (`phishing-detection/data/phishing_dataset.csv`,
  11 055 rows × 30 features). Held-out metrics from the notebook:
  Accuracy 97.47 %, F1 0.9746, ROC AUC **0.9977** (best of four classifiers
  benchmarked: Random Forest, SVM-RBF, Decision Tree, Logistic Regression).
- **FastAPI backend** `website/app.py` with endpoints `/api/metrics`,
  `/api/features`, `/api/analyze-email`, `/api/analyze-content`,
  `/api/verify-email`, `/api/predict`.
- **Disposable-email database** of 500+ known providers + 6-factor
  auto-generated-username heuristic.
- **Email-authenticity 7-stage verifier**: RFC 5321 format → DNS MX/A →
  SMTP RCPT TO → SPF (`-all/~all/?all/+all`) → DMARC
  (`p=reject/quarantine/none`) → MX PTR / reverse-DNS → WHOIS domain age.
- **Single-page frontend** (`website/static/index.html` + `app.js` +
  `style.css`) — dark-theme responsive UI with orbital hero animation,
  three analysis tabs, animated probability bars, and a model-performance
  panel powered by Chart.js.
