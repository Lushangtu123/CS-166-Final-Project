# Reproducible evaluation for a personal project

## Reviewed user feedback draft

Each public report dialog owns its pending request and retry key. Closing or
replacing a dialog invalidates work still preparing the request; a response from
an older dialog cannot change a new report. Once a request has been sent,
closing the dialog cannot undo server retention. Retrying an unchanged report
in the same dialog reuses the exact payload and key. Keep the dialog open after
a network error to retry safely; reopening starts a separate report.

The public **Report an issue** flow now has a separate, optional consent for
private evaluation of retained content or original EML. Only a report with both
source-retention and evaluation consent, a closed analyst review with structured
reason and evidence basis, and a human `phishing` or `legitimate` verdict can
enter a curation draft. Older reports,
source-free reports, images, sender-only reports, legacy unstructured reviews,
reporter-only evidence, open reviews and uncertain verdicts are excluded.
Reports with the same retained message and conflicting human labels are excluded
together; matching duplicates count once. Each exported row preserves the union
of all eligible duplicates' `case_reviewer_ids` and their `source_case_ids`.
An analyst who reviewed any of those duplicates cannot be the independent
reviewer. Regenerate older drafts from the private archive before using this check.

New feedback uses `source_schema: 2`: a missing subject stays empty in the
retained message, while the queue receives a separate report title. Exported
rows preserve this marker. Older records with subjects exactly matching generated
titles such as `User feedback · false_positive` are ambiguous: the title may
have been injected by the old handler, or may genuinely belong to the email.
The exporter excludes them and counts `ambiguous_legacy_subject`; the cohort
builder also rejects such rows in existing drafts without schema 2. Verify the
original email and re-submit/review it through the corrected flow before evaluation.
Do not simply strip the title or add the schema marker to an old draft. Other
legacy messages remain eligible under the existing consent and review checks.

First make and verify a private archive using the commands in
[case-workflow.md](case-workflow.md#storage-limits-and-responsibility), then run:

```sh
.venv/bin/python website/tools/export_reviewed_feedback.py \
  --archive /absolute/private/path/cases-archive.json \
  --output /absolute/private/path/reviewed-feedback-draft.jsonl
```

The draft is an owner-only local file outside Git. It contains original message
text or base64-encoded EML bytes, a human verdict, timestamps, the reported
risk and model ID; it omits analyst notes. Treat it as sensitive. It is **not yet an evaluation
cohort**: user reports are selected by perceived errors, provider and email
arrival date are unknown, the analyst verdict still needs independent label
review, and training/campaign overlap has not been checked. A separate local
cohort builder accepts a second reviewer's annotations and enforces that their
ID differs from every analyst who reviewed that case. It also checks dates,
provider, language, message fingerprints and family separation across
development and holdout inputs. The identities and labels are self-attested;
the tool cannot prove independence, consent or training-set isolation.

Create a private owner-only annotations JSONL outside Git. Each selected draft
record needs one line like this, with independently verified values:

```json
{"id":"00000000-0000-4000-8000-000000000001","label":"legitimate","provider":"gmail","received_at":"2026-09-21","language":"en","family_id":"campaign-1","cohort_role":"holdout","independent_reviewer":"reviewer-b"}
```

Then run:

```sh
.venv/bin/python website/tools/build_private_cohort.py \
  --draft /absolute/private/path/reviewed-feedback-draft.jsonl \
  --annotations /absolute/private/path/annotations.jsonl \
  --output-dir /absolute/private/path/cohort
.venv/bin/python website/tools/evaluate_serving_pipeline.py \
  --input /absolute/private/path/cohort/holdout.jsonl
```

The builder writes new owner-only `development.jsonl`, `holdout.jsonl`, EML
files and a lineage record. Annotations may select a subset of the draft, but
one family cannot be split across roles; conflicting independent labels stop
the build for manual resolution. `received_at` must come from verified provider
or organization evidence, not an untrusted mail `Date` header. Keep the
holdout untouched while developing rules and review training overlap before
claiming independent performance. Never copy private inputs into public fixtures.

The first goal is to measure changes honestly with a small, repeatable local
workflow. These tools do not certify enterprise readiness, train a new model,
change production thresholds, or require a paid service. Start with owned controls,
then public research data, then consented and independently labeled inbox samples.

## 1. Public email research pilot

Use the existing Python 3.12 environment and committed model. From the repository
root, explicitly download a seeded, fixed-version pilot:

```sh
.venv/bin/python website/tools/prepare_public_pilot.py --output .evaluation-data/public-pilot --count 100 --seed 42
.venv/bin/python website/tools/evaluate_public_corpus.py --manifest .evaluation-data/public-pilot/manifest.json --output .evaluation-data/public-pilot/report.json
```

The downloader preserves existing directories, checks the SpamAssassin archive
SHA-256 and each Git blob, never executes email content or follows its links, and
writes original EML bytes to a gitignored, deployment-excluded directory. Only this
preparation command needs network access. Evaluation uses the committed Vercel
profile with history, external verification, cases and trusted-authserver overrides
disabled, ignoring ambient app configuration.

The initial pilot uses 100 [phishing_pot](https://github.com/rf-peixoto/phishing_pot)
messages at commit `49f63777126b0bdb9eb1f6e770a5c3f9df2b0306` and 100 historical
[SpamAssassin easy_ham](https://spamassassin.apache.org/old/publiccorpus/readme.html)
messages. The former has a CC-BY-NC-4.0 license and repository collection labels,
which can include scam/spam and need human review. The latter retains sender
copyright and is a historical research corpus. Keep raw messages local; these
sources are not a commercial redistribution package. Size eligibility is at most
60,000 bytes per EML, excluding 1,025 phishing repository messages and 2 easy_ham
messages in the pinned inventories. Sampling is balanced and seeded; it does not
represent production prevalence. Do not interpret precision on this pilot as inbox
precision.

### Bring another corpus

Create a manifest with `schema_version: 1`, a relative `records` JSONL path,
`exploratory_only: true`, and `sources`. Each source requires `id`, `url`, a fixed
`revision`, `license`, and `label_basis`. Each JSONL row requires `id`, `source_id`,
`label` (`phishing` or `legitimate`) and either a relative `eml_path` or `subject`
and `body`. `content_sha256` can verify raw EML bytes or canonical subject/body JSON.
Provider, language and `received_at` are optional. Unknown values remain unknown;
provider is not guessed from sender addresses and arrival time is not guessed from
an untrusted Date header. Do not put private data in source metadata or record IDs.

The evaluator snapshots bounded files and validates the full cohort before
analysis. Exact duplicates are excluded, conflicting labels fail, and normalized
text templates are reported. An optional `--reference-manifest PATH` uses the same
format to exclude exact and heuristic template overlap with supplied reference
records. A clean comparison does **not** prove that the full model training corpus
is independent: its original files are not available in this checkout. There is no
claim of temporal isolation. Retain these qualifiers when publishing results.

Aggregate reports include recall, false-alert rate, undetermined rate, complete
analysis and model availability, 95% Wilson intervals, source/language/provider/month
groups, explicit exclusions and failures, actual included-cohort hashes, scoring
hashes, code/model hashes and package versions. Inference failures remain in the
undetermined denominator and cause a nonzero exit. An empty post-filter cohort also
fails. Reports omit original email text and file paths.

Keep the stricter existing `evaluate_serving_pipeline.py` for consented Gmail and
Outlook data with known provider and arrival date. Public corpus labels must not be
passed off as provider-specific real-world testing.

## 2. Browser OCR and QR controls

```sh
python3 website/tools/vision-benchmark/serve.py --port 8930
```

Open `http://127.0.0.1:8930/`, select the supplied
`website/tools/vision-benchmark/synthetic-manifest.json` and five PNGs from
`website/tests/fixtures/vision/`, then run and download the report. This calls the
same browser worker as the website. It measures exact QR payloads, strict OCR
character error rate, exact OCR URL spelling, unexpected Han characters on English
images, extraction status and timing. It validates original image hashes and keeps
missing, cancelled or failed inputs in the denominator. No screenshot goes to a
cloud service. See [harness instructions](../website/tools/vision-benchmark/README.md)
for your own annotated datasets and optional local risk assessment.

Five synthetic controls establish that the workflow functions; they cannot estimate
real screenshot accuracy. Expand with independently transcribed, authorized images,
including mixed language, scaled/compressed text, multiple QR codes and difficult
negatives. Record languages and exact URLs before running OCR. Do not use the
recognizer's own output as ground truth. Public QR datasets whose URL mappings or
rights have not been verified are not bundled. Target 30 or more independently
labeled screenshots and 30 QR images in the next evidence-collection stage.

Optional risk assessment reports unavailable and undetermined outputs explicitly.
The external local backend's configuration/model identity is not attested by the
harness. Record how that backend was started; extraction-only reports are the
reproducible default. Browser evidence remains unverified and does not become
trusted simply because a benchmark was run. OCR language is now recorded per
observation rather than always displaying the mixed-language engine label.

## 3. Compare a baseline before release

```sh
.venv/bin/python website/tools/compare_evaluations.py --baseline baseline.json --candidate candidate.json --output comparison.json
```

The gate requires the same input, included cohort, ground truth, overlap policy and
scoring implementation. Detector/model or extraction implementation may change.
It rejects missing/nonfinite metrics, changed denominators and inference/extraction
failures, and checks per-group as well as overall changes. Recall, coverage and QR/
URL matches must not decrease; false alerts, unknown rate and CER must not increase.
Existing partial visual extractions are retained, but their count cannot increase.
Timing is diagnostic because browser cache and machine load vary; it is not a gate.
No tolerance is silently applied. A scorer or annotation correction needs a newly
reviewed baseline; do not overwrite a baseline just to make a failing change pass.

The Vercel-runtime CI job evaluates four project-owned email controls with the
committed model and compares against `website/tests/fixtures/evaluation/baseline.json`.
Unit tests include deliberately worse, missing, changed and failed results to prove
that the gate rejects them. CI never downloads public mail or private screenshots.
The real OCR browser run is manual; Node metric tests do not assert OCR accuracy.

A green gate means no measured regression on that fixed cohort. It is not a claim
of statistical significance or acceptable enterprise accuracy. Review the actual
false alerts and misses before tuning, retain a separate future holdout set, and
keep a changelog explaining model/rule changes. This project currently prioritizes
making errors visible over displaying an unsupported accuracy percentage.

## Initial local findings (2026-09-21)

On the 200-message unreviewed public pilot, medium/high/critical count as alerts:

| Measure | Result |
| --- | --- |
| Upstream phishing messages alerted | 89/100; 89%, Wilson 95% interval 81.37–93.75% |
| Upstream legitimate messages alerted | 28/100; 28%, interval 20.14–37.49% |
| Undetermined | 7/200; 3.5% |
| Analysis complete | 94/200; 47% |
| Content model available | 185/200; 92.5% |
| Inference exceptions / duplicate exclusions | 0 / 0 |

These figures expose substantial false-alert work; they are not enterprise or
Gmail/Outlook performance estimates. Size filtering, historical normal mail,
unreviewed upstream labels and unverified training overlap limit interpretation.
The model and detection thresholds were not tuned on this pilot. The first useful
follow-up is manual error categorization with a separate held-out sample, not a
threshold change chosen solely to improve these 200 results.

## Follow-up routing policy candidate (2026-09-21, not released)

Error inspection found all 28 initial normal-mail alerts were medium, with the
content model predicting legitimate. Reply-To and Return-Path domain differences
were being added as independent impersonation evidence. The candidate keeps each
routing observation but applies one combined two-point weak concern. Claimed list
headers do not confer trust. Trusted authentication failures, brand impersonation,
dangerous attachments and malicious-link evidence retain their independent rules.

Also, a low-scoring message dominated by an uninspected remote image now remains
unknown, preserving strong alerts. The previous logic could display low risk based
on a few routing points despite having very little inspected content.

| Cohort | Normal-mail alerts before → after | Phishing alerts before → after | Unknown before → after |
| --- | --- | --- | --- |
| Original pilot, 200 messages | 28/100 → 3/100 | 89/100 → 89/100 | 7 → 8 |
| Follow-up, 194 messages | 24/96 → 9/96 | 83/98 → 82/98 | 10 → 11 |

The follow-up uses seed 20260921 from the same pinned sources. Five exact and one
normalized-template matches against the first pilot were excluded before inference.
Both versions used the same committed model and settings, with zero inference
exceptions. The original-parser baseline was captured before the incomplete-image
change; component identity and settings are recorded in the local controlled
validation report. This is additional evidence from the same sources, not an
independent enterprise dataset. It has now been inspected and is no longer an
untouched holdout.

**The strict no-regression gate rejects this candidate**: fewer false alerts come
with one fewer phishing alert and more explicitly unknown outcomes. The affected
follow-up message has insufficient model text and an uninspected remote image;
its new result is unknown, not an assurance of safety. Do not relabel unknown as an
alert, overwrite the baseline, or weaken the gate to claim a pass. Passing the
synthetic CI controls and unit tests does not override the public-cohort finding.
The change remains a local policy candidate requiring a release decision.

OCR diagnostics reproduced `1`/`l` substitutions and malformed URL punctuation.
The local benchmark now offers literal expected/extracted text comparison using
text-only rendering, excluded from downloaded aggregate reports. Visual evidence
adds a server-side instruction to check addresses against the original image
character by character even when OCR confidence is high. No OCR engine, language
model, URL correction or recognition-accuracy improvement is claimed in this step.

## Hidden text / linked image review signal (phase 3)

The local candidate now emits one medium review signal when the same HTML document
contains at least 500 non-whitespace, non-format hidden characters, fewer than 80
visible characters, at least a 10:1 hidden/visible ratio, and a visible image inside
an explicit HTTP(S) anchor. Hidden prose stays excluded from model input. Short
preheaders, zero-width/NBSP filler, inert script/style/template/comment content,
text-rich mail and separate MIME parts do not meet this conjunction. Uncertain CSS,
MSO conditional rendering and recovery parsing suppress the added structural floor.
Nested anchors do not inherit an older web action. This is a suspicious layout for
manual review, not proof of phishing; a legitimate image campaign can also have
large hidden text. Picture/source-only image resources remain a conservative gap.

The 500-character policy was informed by an inspected development failure (779
hidden characters); that case is now a regression example, not holdout evidence.
On the second cohort it restores the lost alert: 83/98 phishing alerts, 9/96 normal
alerts and 10 unknown, matching baseline recall while reducing false alerts.

Third-batch confirmation uses seed 20260922 and excludes both prior batches: 6 exact
and 6 template overlaps are removed, leaving 188 messages (92 upstream phishing,
96 normal). Compared with exact HEAD serving/parser modules under the same model
and settings, normal alerts fall from 19/96 to 6/96, but phishing alerts fall from
81/92 to 79/92; unknown outcomes rise from 9 to 11. No model weights, score threshold
or metric definitions were changed to produce these numbers. A reviewer-found
format-character negative-control fix was applied before inspecting batch results;
the confirmation was rerun afterward. The batch has now been evaluated, so it must
not be treated as untouched evidence for further tuning.

**The third-batch no-regression gate still fails.** Engineering tests and owned CI
controls pass, but the routing policy remains an unreleased experiment. Retain the
current production policy until the recall/unknown tradeoff is explicitly resolved;
do not treat restored performance on a development example as universal recovery.

## Jev shadow evaluation

The optional TypeSafe adapter is an experimental semantic opinion. It pins
`jev-1.13.0`; official contracts checked on 2026-09-21:
[HTTP API](https://docs.typesafe.ai/api), [Noul questions](https://docs.typesafe.ai/primitives/noul),
[model limits and languages](https://docs.typesafe.ai/models).
Noul values are estimated probabilities of a proposition, not severity scores.
An output with the right type can still be wrong. English is the provider's
strongest language; this repository has not established multilingual gains.

### Local preflight (no external processing)

```sh
.venv/bin/python website/tools/evaluate_jev.py \
  --manifest website/tests/fixtures/evaluation/manifest.json \
  --output /tmp/jev-preflight.json
```

Default mode validates provenance, hashes, labels, duplicates and optional
`--reference-manifest` overlap. It loads neither detector nor remote model, sends
no message, and reports no detection accuracy. Even a configured API key cannot
turn a dry run into a live call.

### Authorized live experiment

First arrange authorized, independently labeled, minimized test data and confirm
provider data handling and spending controls. Store `TYPESAFE_API_KEY` privately
in the process environment and set `PHISHGUARD_JEV_ENABLED=true`. Do not paste
keys in source, command arguments, Git, reports or chat. Then explicitly opt in:

```sh
.venv/bin/python website/tools/evaluate_jev.py \
  --manifest /absolute/private/corpus/manifest.json \
  --live --allow-external-processing --max-calls 20 \
  --output /absolute/private/jev-report.json
```

The call limit is required (1–1000). Rows after that budget remain in denominators
as undetermined. Choose a balanced, predeclared cohort small enough for the budget;
the tool takes eligible rows in input order and does not silently sample for you.
Local inference uses the committed Vercel model/profile with sender history and
verification disabled. Jev receives readable text, never original MIME bytes or
attachments. MIME plain text stays literal; HTML hidden text is excluded by the
existing parser. Missing nested-message text and other incomplete evidence force
the auxiliary evaluation decision to remain undetermined, even if Jev returns a
high probability. OCR remains unverified text; Jev cannot correct it from pixels.

Reports compare the baseline, auxiliary judgments, and a **hypothetical OR** rule
that retains all original alerts and only adds auxiliary alerts. The exploratory
default threshold is 0.8 for deceptive intent, with insufficient-evidence >=0.5
treated as undetermined. These thresholds are not validated production policy.
Metrics include recovered phishing, new normal-mail alerts, unknown/failure counts,
language/source groups, available-output Brier score, timing and reported token
usage. Failures/skips remain in class denominators and make live CLI runs fail;
Brier excludes missing outputs and states its own denominator. Provider failures
may still incur charges; reported usage is not a complete bill. No pricing-derived
cost claim or automatic deployment gate is produced. Input/cohort/question/model
identities are recorded without mail bodies, raw response errors or file paths.
New independent samples are required after changing prompts or thresholds.

### Optional authenticated workbench

Set the two variables on the server and restart/redeploy only when enabling is
authorized. The case workspace then shows **Jev auxiliary opinion** for analysts.
The checkbox and explicit button call `POST /api/cases/{id}/auxiliary` with
`{"allow_external_processing":true}`. Authentication, no-store headers and existing
rate limiting apply. The browser receives only structured opinions, never the key.
Opinions do not change risk or verdict. Switching cases/signing out clears the
display; **View existing result** reads the current analyst's 24-hour receipt
without sending a new provider request. An analyst may explicitly confirm **Save
opinion to history** to retain a successful server-owned opinion with model/input
provenance under the case retention policy. This appends a case event without
changing human assessment; it neither labels evaluation data nor retrains the model.
Failed, missing, expired or mismatched receipts cannot create a new opinion event.
Legacy raw-email cases without separately saved
MIME text skip auxiliary analysis rather than reinterpreting plain text as HTML.

The adapter masks email local parts and removes HTTP(S) URL credentials, queries
and fragments. This is **data minimization, not full anonymization**: names, URL
paths and free prose can still contain private data. Analyst notes and images are
never sent. Input over 12,000 total subject/body characters is skipped, not silently
truncated. Responses are bounded to 16 KB and strictly validated. Redirects, proxy
environment variables, provider error-body logging and automatic retries are disabled.
The caller has a six-second external-request deadline. At most two daemon requests
can continue waiting on an underlying socket/DNS operation; they retain their
slots until completion, preventing an unbounded retry/thread queue.

Web calls share a daily workspace/environment attempt budget in Upstash (SQLite
locally), default 20, configurable with `PHISHGUARD_JEV_DAILY_LIMIT` (1–1000).
The budget resets at UTC midnight. Requests reserve an attempt before contacting
TypeSafe; failures and uncertain outcomes also consume it. Identical inputs,
actor, case, pinned model and questions reuse a 24-hour receipt, even across a
midnight reset. This limits attempts, not monetary spending; retain provider/account
controls. CLI calls keep their separate explicit budget and do not use web receipts.
The web server releases a reservation only for a confirmed local worker-capacity
rejection before provider I/O; this allows a later deliberate retry. Provider
timeouts, HTTP errors and unknown outcomes retain their existing receipts.
Missing or invalid configuration disables the optional feature without breaking
existing analysis. The production `--require-jev` smoke gate checks only safe
configuration flags and never calls TypeSafe. See [operations](case-workflow.md#jev-availability-and-request-controls).

No live Jev call or accuracy test was performed during implementation. Synthetic
contract/failure tests establish integration behavior, not model effectiveness.
