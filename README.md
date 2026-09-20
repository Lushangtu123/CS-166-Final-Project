# CS 166 Final Project — Phishing & Scam Email Detection

> **Course:** CS 166 – Information Security  
> **GitHub:** https://github.com/Lushangtu123/CS-166-Final-Project

PhishGuard is a FastAPI web application for explainable phishing-email
screening. It supports three distinct workflows:

- sender/domain risk analysis from an email address;
- message analysis from subject/body text or a complete RFC 5322 `.eml` file;
- public-safe DNS/MX/SPF/DMARC/PTR/WHOIS domain checks, with optional local
  SMTP mailbox probing kept separate from domain evidence.

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
The local verification endpoint uses the same address validation and normalization;
DNS, SMTP, and WHOIS receive the canonical domain/address while responses retain
the submitted address for display. Unsupported syntax is rejected before DNS.

`POST /api/analyze-email` returns an explainable `risk_score`, not a trained
probability. Signals include:

- look-alike brand names and phishing keywords in untrusted domains;
- decisive digit-substitution lookalikes such as `paypa1.com` and `g00gle.com`;
- risky TLDs, IP-literal domains, excessive subdomains, and unusual syntax;
- confirmed disposable-provider domains, separated from privacy relays;
- anchored disposable-domain patterns and multi-factor auto-generated mailbox
  patterns, reported as suspicion rather than proof;
- provider-aware plus-address aliases and Gmail-compatible dot normalization
  without added risk.

Disposable-email results include `disposable_status`,
`disposable_confidence`, `matched_provider_domain`, and
`address_alias_type`. A domain-list match confirms only the provider category;
it does not establish how long an individual mailbox exists or that its sender
is malicious.

The disposable-provider registry is stored in
`website/data/disposable_domains.json` with a schema version, release version,
entry count, and provenance note. Runtime startup validates that it is sorted,
duplicate-free, syntactically valid, and internally consistent. To rebuild it
from reviewed offline line files, run:

```bash
python website/tools/build_disposable_registry.py \
  --input /path/to/reviewed-domains.txt \
  --output website/data/disposable_domains.json \
  --version YYYY.MM.DD \
  --provenance "source name, URL, retrieval date, and license"
```

Review generated changes before committing them. Gmail and Outlook account age
or intended lifetime cannot be inferred from an address alone; random-looking
mailboxes remain heuristic suspicion rather than confirmed disposable accounts.

An optional service-retained observation history can add a second, independent
piece of context. Full raw-message analysis records that a canonical sender was
observed. Address-only analysis deliberately does not query retained history,
preventing the public sender form from becoming an arbitrary history lookup.
A first observation means only “not previously retained by this service” — it does **not** mean
the Gmail, Outlook, or other provider account was newly created. Previous
observation is also not a safety signal and never reduces phishing risk.

The history store receives only an HMAC-SHA-256 identifier, timestamps, and a
bounded count. Public API responses expose only the coarse first/previous status,
not exact observation timestamps or counts. Raw addresses and message content are not stored.
Valid plus tags share one history identity only for known supporting providers
(`gmail.com`, `googlemail.com`, `outlook.com`, `hotmail.com`, and `live.com`),
while Gmail/Googlemail dot aliases are also normalized. Unknown custom domains
keep their literal local part because their delivery semantics are not known.
Records expire after 90 days by default, and unavailable storage fails open
without changing the detector verdict. Rotating `SENDER_HISTORY_HMAC_KEY` starts
a new observation namespace; old opaque records expire under their existing TTL.

HMAC identifiers are **pseudonymization, not anonymization**. The deployment
operator remains responsible for an appropriate privacy notice, access control,
retention policy, and any legal obligations that apply to sender observations.

Privacy relays are maintained separately in
`website/data/privacy_relay_domains.json`, with provider-source URLs and a
retrieval date. Registrable-domain and subdomain calculations use
`tldextract`'s bundled Public Suffix List snapshot with runtime downloads and
cache writes disabled, so domains such as `company.co.uk` are parsed correctly
and deployment behavior stays deterministic.

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
Visible `To` and `Cc` recipients are also parsed. A sender mailbox repeated in
`To` or `Cc` adds one bounded low-risk structure point; a missing visible
recipient is informational because legitimate Bcc delivery is possible.
Within a single address-list field, each mailbox/display-name pair is checked
independently; adding another sender cannot hide a detected brand impersonation.
Quoted commas in display names remain part of that name, not an address separator.
Legitimately repeatable `Received` and `Authentication-Results` fields are not
flagged just because they repeat.
Each MIME part also checks duplicate `Content-Type`, `Content-Transfer-Encoding`,
and `Content-Disposition` headers. These always mark analysis incomplete. The
original interpretation and up to **8 alternate combinations per part**, with
**32 alternates per independently analyzed message**, are inspected for recoverable
text and attachment metadata. Candidate exhaustion is reported. Alternate MIME
trees and encapsulated messages are not reparsed; this is bounded evidence
recovery, not a claim that every possible interpretation was checked.
The content response includes `analysis_complete`; `false` means some content
could not be reliably analyzed, not evidence of phishing by itself. Attachment
items include `inspection_status`: `metadata_only` means the filename and MIME
type were checked but attachment bytes were not inspected;
`message_analyzed` means an encapsulated email was successfully traversed under
the existing detector limits. Non-text inline parts without filenames are also
reported as `metadata_only`. Opaque attachment content adds one bounded
top-level `analysis_warnings` entry, separate from MIME `parse_warnings`, but no
phishing points. If there is no detected risk and analysis is incomplete,
`risk_level` is `unknown` and
`combined_phishing_score` is `null`. The UI shows “Analysis Incomplete” and a dash
instead of a green zero. Detected risks remain visible alongside the warning.
API consumers must accept this additional risk level and nullable score.

MIME tree construction is limited to **200 message/part nodes per upload**,
including the root. This bounds deeply nested and very wide messages before
content analysis. On reaching the limit (or a parser recursion failure), the
detector falls back to outer headers only and explicitly marks the body and
attachments uninspected. Outer-header risk is retained; an otherwise risk-free
fallback is `unknown`, never a complete safe verdict. This is separate from the
attached-message analysis depth/count limits below. Long monetary digit strings
are compared without integer conversion, and monetary evidence excerpts are bounded.
Amount checks distinguish common decimal and three-digit grouping formats
(`$100.00`, `$10,000.00`, `EUR 10.000,00`); malformed grouping is ignored rather
than converted to an inflated integer. This is a heuristic, not currency or locale inference.

Malformed HTML that requires parser recovery now reports `analysis_warnings`
and `analysis_complete=false`, including manual subject/body input and nested
messages. Recovery attempts to retain text, links, and forms; if necessary it
falls back to literal text. A parsing failure is neither a server-error verdict
nor proof that the content is safe. Literal MIME `text/plain` is not parsed as HTML.
Unknown marked declarations such as `<![foo]>` explicitly trigger recovery,
even on Python versions that would silently consume them as comments. Literal
markers inside comments, quoted attributes, scripts, and styles do not trigger
this check; supported CDATA and conditional declarations remain accepted.
Visible-text extraction also handles an omitted `</head>` when body content
begins, while retaining suppression of title, script/style, and template content.
This is targeted recovery, not a complete browser DOM or CSS rendering engine.

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
warning rather than a complete verdict. Ambiguous duplicate MIME interpretations
or indistinguishable attachment names never claim `message_analyzed`. A parsed
attached email can still contain its own `metadata_only` attachment, making the
outer result incomplete. This does not unpack archives or execute attachments.

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
HTTP(S) authority slash/backslash variants are normalized before resolving an
HTML base URL, so equivalent destinations keep the same host checks. Unsupported
or malformed HTTP(S) destinations produce incomplete-analysis warnings rather
than silently disappearing. This normalization is not a full WHATWG URL engine.

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

The default content rules are English-oriented. The optional model now has a
dated Spanish holdout, but that single corpus is not representative of Gmail,
Outlook, Chinese-language mail, or organization-specific traffic. Pure-text
credential lures can still be missed. Do not interpret passing regression tests
or a zero score as universal measured phishing recall.

If the fitted vectorizer produces no usable feature for a message, the model
abstains with `ml_status=insufficient_feature_coverage` and nullable model
scores instead of inventing a prediction. Rules, sender, link, and structure
checks still run. The model also abstains with `ml_status=insufficient_context`
before vectorization when the combined subject and body contain fewer than five
Unicode word tokens or fewer than 40 non-whitespace characters; HTML tags and
attributes do not count toward this context measure. This prevents short routine
subjects from producing unsupported high-confidence verdicts.
With no independent evidence, either abstention produces an incomplete
`unknown` result rather than claiming the email is safe. The UI labels supported
outputs as a **model risk score**, not a calibrated probability or confidence claim.

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
6. The initial phishing decision threshold is selected from training-fold
   out-of-fold predictions by maximizing F2, which weights recall more heavily.
   When available, a separate 2024 SpaPhish validation slice replaces that
   initial threshold with the maximum-recall point whose legitimate-message
   false-positive rate is at most 20%. This is an observed validation-sample
   constraint, not a guarantee about the population false-positive rate.
7. Dated SpaPhish messages from 2025 form a post-selection regression slice and
   are scored after model and threshold selection. Reports include phishing recall,
   false-negative and false-positive rates, PR AUC, Brier score, threshold,
   split strategy, train/test group overlap, and Wilson 95% intervals for recall
   and false-positive rate. Repeated inspection means this slice is not claimed
   as a permanently untouched production lockbox.

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
│   ├── content_inference.py     # runtime-only verified artifact loader
│   ├── email_structure.py       # RFC 5322/MIME/header analysis
│   ├── config.py
│   ├── prebuild_demo_model.py   # explicit offline artifact builder
│   ├── static/
│   └── tests/
├── app.py                       # Vercel FastAPI entrypoint
├── requirements.txt             # Vercel inference/runtime dependencies
├── vercel.json                  # Vercel Lite-verification profile
├── render.yaml                  # safe rules/structure-only public demo
└── CHANGELOG.md
```

## API overview

| Endpoint | Purpose |
|---|---|
| `POST /api/analyze-email` | Explainable sender/domain risk |
| `POST /api/analyze-content` | Subject/body or raw-message analysis |
| `POST /api/analyze-eml` | Original MIME bytes, maximum 60,000 bytes |
| `POST /api/verify-email` | Lite domain checks or local full mailbox checks, depending on configuration |
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
Authentication-result extraction separates semicolon-delimited method clauses
from nested comments and quoted explanation strings. Text such as `dmarc=pass`
inside a comment or `reason` cannot overwrite a real `dmarc=fail` result. Common
whitespace and method-version syntax are supported. Unclosed comments or strings
produce an incomplete-analysis warning and cannot confer a trusted pass. This
does not perform live SPF/DKIM/DMARC verification or expand the trust boundary.

## Runtime configuration

| Variable | Default | Purpose |
|---|---:|---|
| `APP_ENV` | `production` | `development`, `demo`, `production`, or `test` |
| `VERIFICATION_MODE` | `off` | `off`, public-safe `lite`, or local-only `full` |
| `ENABLE_EMAIL_VERIFICATION` | `false` | Legacy local full-mode switch; public full mode is rejected |
| `ENABLE_DOMAIN_VERIFICATION` | `false` | Legacy-compatible switch for Lite domain checks when no explicit mode is set |
| `ENABLE_SMTP_VERIFICATION` | `false` | Legacy-compatible full-mode switch; rejected in public profiles |
| `VERIFICATION_WORKERS` | `10` | Bounded per-process verification jobs (`4` in the Vercel profile) |
| `CONTENT_MODEL_ENABLED` | `false` | Loads a verified offline email-text artifact |
| `CONTENT_MODEL_ARTIFACT` | empty | Path to the trusted artifact created by `prebuild_demo_model.py` |
| `CONTENT_MODEL_ARTIFACT_SHA256` | empty | Required SHA-256 digest for the configured artifact |
| `TRUSTED_AUTHSERV_IDS` | empty | Comma-separated authentication service IDs allowed to affect raw-message risk |
| `SENDER_HISTORY_ENABLED` | `false` | Enables optional service-retained sender history and distributed API limiting when all secrets are valid |
| `UPSTASH_REDIS_REST_URL` | empty | HTTPS REST endpoint for an Upstash Redis database (`*.upstash.io`) |
| `UPSTASH_REDIS_REST_TOKEN` | empty | Server-side Upstash REST token; never expose or commit it |
| `SENDER_HISTORY_HMAC_KEY` | empty | Private random key of at least 32 bytes used to derive opaque sender identifiers |
| `SENDER_HISTORY_RETENTION_DAYS` | `90` | Sliding history retention, from 1 through 365 days |
| `SENDER_HISTORY_TIMEOUT_SECONDS` | `1.0` | Fail-open Upstash deadline, from 0.1 through 3.0 seconds |
| `RATE_LIMIT_BUCKET_CAPACITY` | `4096` | Hard bound for in-process rate-limit keys |
| `MAX_REQUEST_BYTES` | `65536` | Actual HTTP request-body byte limit before decoding; applies without Content-Length |
| `CUSTOM_DOMAINS` | empty | Comma-separated custom hostnames appended to `ALLOWED_HOSTS` |
| `CONTENT_MODEL_USE_REAL` | profile-dependent | Offline training: load local public corpora |
| `CONTENT_MODEL_AUTO_DOWNLOAD` | profile-dependent | Offline training: download configured public corpora when missing |
| `CONTENT_MODEL_USE_CACHE` | `false` | Offline training: explicitly trust/load the local pickle cache |
| `CONTENT_MODEL_AUGMENT_SYNTHETIC` | `false` | Opts into bundled template augmentation for experiments |

The included Render blueprint explicitly sets `CONTENT_MODEL_ENABLED=false`
and `ENABLE_EMAIL_VERIFICATION=false`. The public
demo therefore starts reliably with sender, header, structure, and content-rule
analysis, without presenting a synthetic model as production evidence.

## Vercel Hobby deployment

The repository root is a Vercel-native FastAPI project. Its committed profile
uses one Fluid-compute Python Function, four bounded verification workers, and
`VERIFICATION_MODE=lite`. Lite mode performs format, MX/A/AAAA, SPF, DMARC, PTR,
and best-effort WHOIS checks. It never opens an SMTP connection and returns
`overall=domain_valid` rather than claiming that the mailbox or sender is
verified. The response separates `domain_verification` from
`mailbox_verification`; the latter is `unavailable` on this profile.

The Vercel runtime installs NumPy and scikit-learn for inference but not pandas.
Training remains local-only. When `website/model/content_model_artifact.pkl` is
present, `vercel.json` must contain its exact SHA-256 digest and enables the
model. Startup verifies the digest plus Python/scikit-learn compatibility before
deserializing. A rejected or missing artifact leaves rule and structure analysis
available and reports the model error through `/health`. Successful health and
metrics responses expose the loaded artifact digest and a short `model_id`, so
displayed metrics can be tied to the deployed binary rather than a different
training run.

Model explanations cache their immutable 80,000-feature name/coefficient arrays
and calculate contributors directly from the sparse request vector. This keeps
the displayed terms unchanged without allocating one dense feature array for
every request.

Before attaching a custom domain, add its apex and optional `www` hostname to
the Vercel `CUSTOM_DOMAINS` environment variable, for example
`phishguard.example,www.phishguard.example`, and redeploy. Do not include a URL
scheme or path. The default `*.vercel.app` allow-list remains active.

Deploy from the repository root with Vercel CLI 48.1.8 or newer, or import the
Git repository in the Vercel dashboard. The deployment is intended for a
personal/course demonstration. It always keeps a bounded in-memory limiter; when
the optional Upstash configuration is ready, POST requests also use an atomic,
HMAC-keyed distributed limit shared by Vercel instances. Upstash failure fails
open to the existing local limiter so detection remains available.
The Vercel profile uses only a single syntactically valid platform-normalized
`X-Forwarded-For` address as the local-limit identity; ambiguous lists and
invalid values fall back to the ASGI peer. Other deployment profiles ignore
that header rather than trusting arbitrary forwarding input.

Email bodies and attachment content are processed server-side for analysis and
are not retained by this application. When sender history is enabled, a
pseudonymous sender observation may be retained as described above. Users
should remove unrelated personal content before submitting an email.

### Optional free sender-history store

[Upstash Redis currently offers a $0 tier for hobby projects](https://upstash.com/pricing/redis),
and Vercel can provision and link it through the
[Upstash Marketplace integration](https://vercel.com/marketplace/upstash).
Limits and pricing can change, so confirm the current plan before provisioning.
The detector remains fully usable without this optional store.

1. In the Vercel project, open **Storage**, choose **Create Database**, select
   **Upstash Redis**, choose the Free plan, and connect it to this project.
2. Confirm Vercel added `UPSTASH_REDIS_REST_URL` and
   `UPSTASH_REDIS_REST_TOKEN` for the Production environment.
3. Generate a private HMAC key locally with `openssl rand -hex 32`. Add the
   output as `SENDER_HISTORY_HMAC_KEY` in Vercel; do not put it in Git.
4. Add `SENDER_HISTORY_ENABLED=true`. Optionally set retention and timeout using
   the variables in the configuration table above.
5. Redeploy, then confirm `/health` reports
   `sender_history_enabled: true`, `sender_history_configured: true`, and
   `sender_history_available: true`.

Missing, partial, malformed, or unreachable configuration disables only history
evidence. Analysis continues, and the UI reports history as unavailable rather
than treating an absent result as “never seen.”
The `configured` and backward-compatible `available` fields describe startup
configuration readiness; they are not a continuous Upstash reachability probe.

Vercel production `deployment_status` events run
`.github/workflows/post-deploy-smoke.yml`. The workflow checks out the deployed
revision and validates `/health`, `/api/config`, the exact model ID, phishing and
legitimate controls, and a unique first/previous sender-history probe against the
public production alias. It rejects cross-host redirects and non-JSON responses,
so Vercel SSO pages cannot be mistaken for application health output.
Read-only health/config readiness checks retry briefly while a deployment alias
converges; phishing, legitimate, and sender-history POST controls run exactly
once after the expected model and configuration are ready.

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
When no MX record exists, discovery tries A and AAAA records within the shared
deadline. An IPv6-only address record can establish an implicit mail host; it
does not establish mailbox existence. Only definitive absence of both address
types yields the no-records verdict. If neither succeeds and either lookup fails
or times out, the result stays `unverifiable`. Null MX never uses this fallback.

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

SPF/DMARC TXT fragments within a DNS record are concatenated without inserting
spaces or display quotes. SPF summaries use complete mechanisms in order (including
the implicit `+` in `all`), not substrings inside domain names. DMARC summaries
read individual tags, not policy-looking text inside reporting addresses. Multiple
policy records, recognized malformed SPF term shapes, duplicate DMARC tags, and
invalid DMARC policy/percentage values report an error and incomplete verification.
These are bounded policy summaries: they do not recursively evaluate SPF
include/redirect, expand macros, implement full SPF syntax validation, or authenticate
a particular message. DMARC organizational-domain policy discovery remains unsupported.
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
| `SpaPhish.csv` | Human-annotated Spanish email corpus via Mendeley Data | Yes, SHA-256 pinned |
| `phishfuzzer_{train,val,test}.csv` | Optional local three-class export | No |

Synthetic benchmark and template data can improve coverage but do not establish
real-world effectiveness. Report metrics only with the exact `data_source`,
`split_strategy`, threshold, and false-negative rate returned by the trained
pipeline. SpaPhish provides a dated cross-language slice, but it is not a Gmail
or Outlook inbox sample and 791 training rows lack dates. A future production
evaluation still needs a strictly dated, organization- and provider-
representative holdout.

### Observed email-text evaluation — 2026-09-19

The committed Logistic Regression artifact sampled 30,000 rows from the globally
deduplicated legacy and PhishNChips pool, reserved 6,000 group-isolated rows for
the original mixed-corpus test, and then added 1,008 SpaPhish training rows plus
1,044 unique grouped synthetic legitimate hard negatives. The hard negatives span 87
transactional, workplace, and personal-correspondence template families and are
added only after the original split; 37 normalized families already present in
reserved data were excluded. SpaPhish normalized families are assigned
to their latest dated partition: 2024 supplies 128 threshold-validation messages
and 2025 supplies 211 post-selection regression-slice messages. The published
CSV is pinned to SHA-256
`fdd74842d0a19fd4332bd91f90b0bcb06e045ceb2b599051b4598b65055a9cc5`.

| Metric | Result |
|---|---:|
| Training rows | 26,052 |
| Original mixed-corpus held-out rows | 6,000 |
| Original held-out accuracy | 98.80% |
| Original held-out precision | 98.13% |
| Original held-out phishing recall | 99.32% |
| Original held-out false-negative rate | 0.68% |
| Original held-out PR AUC | 0.9994 |
| Original held-out Brier score | 0.0095 |
| Training-fold F2 threshold | 0.4352 |
| Effective threshold after 2024 validation | 0.3736 |
| Train/test group overlap | 0 |
| 2024 validation phishing recall | 86.30% (95% CI 76.59%–92.39%) |
| 2024 validation false-positive rate | 14.55% (95% CI 7.56%–26.16%) |
| 2025 SpaPhish holdout rows | 211 (179 phishing / 32 legitimate) |
| 2025 holdout accuracy | 94.31% |
| 2025 holdout precision | 96.65% |
| 2025 holdout phishing recall | 96.65% (95% CI 92.88%–98.45%) |
| 2025 holdout false-negative rate | 3.35% |
| 2025 holdout false-positive rate | 18.75% (95% CI 8.89%–35.31%) |
| 2025 holdout PR AUC | 0.9942 |
| 2025 holdout family overlap | 0 |

The 2025 labels are not used for model selection or threshold tuning, but the
slice has now been repeatedly inspected and is described as a regression slice,
not a permanently untouched holdout. The temporal guarantee remains partial
because 791 SpaPhish training rows have no usable date. These are offline corpus
results, not Gmail/Outlook production claims. PhishNChips and the added hard
negatives are synthetic, provider-specific drift remains unmeasured, and
image-only lures, QR codes, and attachment contents remain outside this
evaluation. The committed artifact is identified by SHA-256
`a0a503a0cd6122e722933add91f49cc72e3fa74abaf1129c4df3fe0450401746`.
Its metrics include the build seed, cache-policy version, training options, and
SHA-256 digest of every local source corpus used for reproducibility checks.

The included public Render profile still keeps the optional text model disabled
until a representative, versioned artifact is supplied through a trusted build
process. Rules and message-structure analysis remain available without it.

## Testing

GitHub Actions runs the development suite on both Python 3.12 and 3.13,
including HTML recovery regressions that must not depend on standard-library
exceptions. A separate Python 3.12 job installs the root Vercel dependencies,
checks their consistency, verifies the committed model digest, starts the real
Lite profile with ML enabled, and performs phishing-positive and legitimate-
negative prediction smoke tests.
A separate deployment-status workflow checks the completed public Vercel
deployment rather than assuming that the source checkout represents its bundle.

```bash
# From repository root, after installing website dependencies
python -m unittest discover -s website/tests -v
python -m compileall -q website phishing-detection/src
node --test website/static/app.test.mjs
node --check website/static/app.js
git diff --check
```

The regression suite covers sender-score semantics, authentication-service
trust, protected-brand/IDN and digit-substitution impersonation, Public Suffix
registrable-domain parsing, SMTP public-address enforcement,
bounded rate limiting, verified model artifacts, HTML destination mismatch,
ASCII brand lookalikes, URL userinfo, attachment MIME types, raw-message sender
fusion, footer spoofing, regional-language neutrality, conservative evidence
fusion, group isolation, deployment flags, and frontend payload/rendering
behavior. Disposable-address regressions cover multi-label provider domains,
random-looking Gmail and Outlook mailboxes, versioned privacy relays,
provider-aware plus aliases, Gmail/Googlemail dot variants, and custom-domain
local parts that must not be merged without known provider semantics.

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
