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

The address endpoint accepts a single address with an unquoted ASCII local part
and a dotted hostname (including internationalized domain names). Plain text,
multiple addresses and unsupported syntax return HTTP 400 without a risk verdict;
use full-message input for message text or display-name headers. Plus-addresses
and the IP-domain detection examples remain supported.

Sender-only and full-message checks use the same IDNA domain normalization.
Unicode/Punycode spellings and a trailing root dot share the same scoring rules;
the submitted address is retained in sender-only responses for display.

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

Confirmed disposable-provider and privacy-relay matches are informational and
do not add phishing-risk points on their own. Independent address, domain,
link, and message risks still contribute normally. The UI separates mailbox
service type from sender risk, uses a neutral low-score banner, and does not
present `100 - risk_score` as a safety score. Scores remain heuristic and have
not been calibrated as phishing probabilities.

Apple's dedicated relay domains `privaterelay.appleid.com` and
`private.icloud.com` are recognized as privacy relays, following
[Apple's domain update](https://developer.apple.com/news/?id=1ptvdtcm).
Ordinary `icloud.com` accounts cannot be classified as relay addresses from
the domain alone.

The response declares `analysis_method: sender-domain-heuristics` so callers do
not confuse the score with model confidence. A low sender score does not prove a
message is safe; compromised legitimate accounts require full-message analysis.

The browser only displays responses for the current input. Editing, clearing,
or starting another analysis invalidates older responses, including mailbox
verification. HTTP failures appear separately from detector verdicts; rate-limit
errors use `Retry-After` when supplied. Selecting a content example clears any
uploaded email, and analysis waits while a selected file is still being read.

### Full-message mode

`POST /api/analyze-content` accepts `subject` and `body`, or `raw_email` for a
complete message represented as Unicode text. For original files, use
`POST /api/analyze-eml` with the unchanged bytes and `Content-Type: message/rfc822`
(or `application/octet-stream`). The browser uses this byte-preserving endpoint.
Uploads are limited to **60,000 bytes**, checked both before client-side reading
and while the server consumes the request stream. No file is saved or forwarded
to a third-party analysis service.

When `raw_email` is non-empty, the file's subject and decoded body are authoritative;
manual `subject`/`body` fields are ignored, including when a raw field is empty.
The browser disables manual fields while a file is selected. Empty uploads are
rejected, but messages containing only headers or attachments can be analyzed.
Unsupported MIME charsets fall back to UTF-8 replacement decoding; the response
includes `message_structure.parse_warnings` and an informational UI warning, not
a silent complete-analysis claim. Invalid encoded byte sequences also produce a
warning. Original bytes are decoded using each MIME part's charset; UTF-8,
GB18030, Latin-1, base64 and quoted-printable cases have regression coverage.
Legacy JSON text cannot recover bytes already lost by a caller's earlier decoding.

MIME text parts are inspected independently with their declared type: literal
plain text is not parsed as HTML, and unclosed markup, forms, or base addresses
cannot affect another MIME part. Recovered parser defects (including missing or
truncated multipart boundaries) are included in `parse_warnings`.
Duplicate `From`, `Subject`, `Reply-To`, and `Return-Path` fields and parsed header
defects also mark analysis incomplete. All duplicate candidates remain available
in `message_structure.header_candidates`; sender and identity checks retain the
highest-risk candidate, subjects are scanned together, and mismatching reply or
return domains remain visible. Duplicates do not add a phishing score by themselves.
Legitimately repeatable `Received` and `Authentication-Results` fields are not
flagged just because they repeat.
The content response includes `analysis_complete`; `false` means some content
could not be reliably analyzed, not evidence of phishing by itself. If there is
no detected risk and parsing is incomplete, `risk_level` is `unknown` and
`combined_phishing_score` is `null`. The UI shows “Analysis Incomplete” and a dash
instead of a green zero. Detected risks remain visible alongside the warning.
API consumers must accept this additional risk level and nullable score.

Encapsulated `message/rfc822` attachments (and parseable `message/global` parts)
are analyzed as independent messages, including their subject, sender identity,
body, and attachments. Nested analysis is limited to **3 levels and 20 messages
per upload**; exceeding either limit produces an incomplete-analysis warning.
Their authentication headers are never trusted using the outer message's
`TRUSTED_AUTHSERV_IDS`. Results include `message_structure.nested_messages`, and
indicators carry an “Attached message” prefix. The highest nested score/risk is
preserved rather than adding the same content repeatedly. Opaque `.eml` files
declared as generic binary attachments are reported as uninspected, not silently
treated as fully checked. Encapsulated messages using base64, quoted-printable,
or other unsupported transfer encodings also produce an incomplete-analysis
warning rather than a complete verdict. This does not unpack archives or execute attachments.

Raw input enables these checks:

- SPF, DKIM, and DMARC results from explicitly trusted authentication servers;
- protected-brand display-name and Unicode/IDN domain impersonation;
- From / Reply-To / Return-Path domain mismatches;
- the same sender/domain heuristics used by the sender-only workflow;
- executable, macro-enabled, disk-image, and archive attachment extensions or
  MIME types;
- HTML anchor/form targets, Markdown, and plain-text link destinations, including displayed-host
  mismatch, Unicode/IDN and ASCII digit-substitution lookalikes, URL userinfo,
  deceptive brand subdomains, and credential-themed domains;
- IP-based and shortened URLs, urgency, credential requests, threats, and
  character obfuscation.

Link checks parse destinations before inspecting hosts. HTML entity escapes,
protocol-relative targets, IPv6, and integer/hex/octal IPv4 forms retain their
destination evidence. No link is fetched to perform these checks. Generic
login/account words on an unrecognized hostname are weak context, not a standalone
high-risk verdict; brand impersonation, userinfo deception, and explicit
credential-collection wording retain stronger signals.

Text rules decode HTML entities, preserve words across inline tags, and normalize
whitespace independently of destination analysis. Script/style/comment text is
not treated as visible prose. Shortener checks use decoded destination hosts with
domain boundaries rather than substrings anywhere in a message. Form `action`
and submit-control `formaction` targets are inspected; an enabled password field
associated with a form is medium-risk evidence, not proof that a client executes it.
Relative HTML link and form targets are resolved against the document's first
`base href` when it supplies a usable HTTP(S) address, including a protocol-relative base. No base is
inferred from the sender, and no external resource is fetched. Without a usable
base, relative targets cannot identify a destination host. Medium and high
destination-risk floors are both preserved when results are combined.

Any positive rule score retains at least a low-risk verdict instead of claiming
no indicators. A narrow English combination of urgency, threats, and a direct
credential request establishes a high-risk floor. Direct negations and ordinary
password-reset notices have negative-control tests; this is not full natural-language
understanding and does not eliminate false positives or false negatives.

The default content rules are English-oriented. Small bilingual smoke checks are
not a representative evaluation: pure-text credential lures, especially Chinese,
can still be missed. Do not interpret passing regression tests or a zero score as
measured phishing recall. A held-out, labeled multilingual corpus is needed before
claiming a real-world improvement in detection accuracy.

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
| `POST /api/analyze-eml` | Original MIME bytes, maximum 60,000 bytes |
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
| `MAX_REQUEST_BYTES` | `65536` | Actual HTTP request-body byte limit before decoding; applies without Content-Length |
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

`APP_ENV=development` allows this opt-in but does not enable it by itself.
For local mailbox checks without the optional text model, run from the repository root:

```bash
APP_ENV=development ENABLE_EMAIL_VERIFICATION=true CONTENT_MODEL_ENABLED=false \
  .venv/bin/uvicorn app:app --app-dir website --host 127.0.0.1 --port 8000
```

Restart after changing environment variables, then reload the browser.
`GET /api/config` exposes `deployment_profile` and the independent feature flags;
the UI distinguishes local-disabled, public-disabled, and unavailable configuration.
DNS/WHOIS records and SMTP probes do not authenticate a particular email, and an
SMTP timeout does not prove whether a mailbox exists.
SMTP rejection is interpreted conservatively: a permanent `5.1.1` response means
the server reports a missing mailbox; `5.7.*` policy rejection, `5.2.2` mailbox-full,
and generic rejection remain inconclusive. `smtp_result` can now include
`policy_rejected` and `mailbox_full`. Existing `exists`/`verified` API values are
retained for compatibility but mean only that the server accepted the address,
not guaranteed delivery or sender authenticity. The UI uses “SMTP Accepted”.
See [enhanced SMTP status codes](https://www.rfc-editor.org/rfc/rfc3463.html).

A sole Null MX (`0 .`) returns `null_mx=true`, `mx_found=false`, and
`overall=no_mail_service`, without A-record fallback or further probing. Mixed
or nonzero-preference Null MX configurations are inconclusive. Declaring no mail
service is not phishing evidence; see [RFC 7505](https://www.rfc-editor.org/rfc/rfc7505.html#section-3).

Local verification has a **12-second response deadline**, including initial DNS
discovery. Queries use a shared pool with at most **10 outstanding jobs per
process** and no unbounded waiting queue. At capacity, discovery returns HTTP 503
with `Retry-After`; individual unavailable checks are reported explicitly.
`verification_complete=false` identifies unfinished/unavailable work. DNS timeouts
remain “Unverifiable” in the UI rather than becoming an invalid-mailbox verdict.
Each executed SPF, DMARC, WHOIS, and PTR check now carries `status`; SMTP exposes
`smtp_status`. `ok` and successful `not_found` results count as completed checks,
while `timeout`, `error`, `busy`, `unavailable`, and `skipped` do not. Completion
describes check execution, not address validity. A fast caught exception therefore
cannot produce a complete-verification claim. A partial result preserves any
SMTP evidence and visibly warns “Verification Incomplete”. Early exits such as
Null MX skip remaining checks and retain `verification_complete=false`.
DNS lookups use explicit lifetimes, WHOIS uses a 5-second socket timeout, and SMTP
uses a per-probe deadline with socket cleanup. Running threads cannot be forcibly
cancelled; they retain their capacity slot until they actually exit. The response
deadline is not a guarantee that every underlying network operation has stopped.

All HTTP request bodies are bounded by received bytes, including chunked JSON
requests and requests whose length header understates the body. The `.eml`
endpoint additionally retains its stricter 60,000-byte file limit.

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
