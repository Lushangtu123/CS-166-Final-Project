# Local image evaluation

This developer harness calls the application's actual `PhishGuardVision.recognize`
function and module worker, including its image bounds, scaling, QR limits, OCR
languages and timeouts. It has no production route and needs only Python's
standard library and a browser. No dependency installation is necessary.

From the repository root:

```sh
python3 website/tools/vision-benchmark/serve.py --port 8930
```

Open `http://127.0.0.1:8930/`. Select `synthetic-manifest.json` from this directory
and the five matching PNG images from `website/tests/fixtures/vision/`. Click
**Run evaluation**, then **Download report**. Selecting the fixture folder also
works; its extra files are ignored. For nested datasets, use the folder input:
manifest paths are relative to the selected folder, with its top-level directory
removed. Files are never fetched from URLs. A missing or wrong-hash file is scored
as a failure; it is never silently omitted.

The **Local text comparison** panel displays literal standard answers, extracted
text and extraction warnings inside this page for error diagnosis. It uses plain
text, never opens detected links, and is cleared at the next run. This text is not
included in the downloaded report.

The supplied controls are project-generated images, with manually transcribed
visible text. They test integration and metric regressions. They are too small
and too artificial to estimate enterprise detection accuracy. No personal
screenshots, real mail, or third-party datasets are bundled.

## Manifest format

The schema version is `phishguard-vision-benchmark/v1`. Each manifest has a
`dataset_id` and 1–1000 records. Each record requires:

- `id`: unique nonempty ID; avoid including private information in IDs.
- `filename`: safe relative PNG/JPEG/WebP path; unique per manifest.
- `sha256`: lowercase SHA-256 of the original image bytes.
- `language`: `eng`, `chi_sim`, or `eng+chi_sim`.
- `expected_text`: human-reviewed literal text, including punctuation and layout
  whitespace. Empty is valid for QR-only images. Do not derive this from OCR.
- `expected_qr_payloads`: complete, unique list of literal expected payloads.
- `expected_urls` (optional): exact HTTP(S) tokens expected in OCR text; not QR
  payloads. An empty list explicitly tests false URL extraction. Omission means
  the record has no URL ground truth, and the report records that count.
- `label`: `benign`, `phishing`, or `unknown`. Image distortion or `tampered`
  annotations alone are not evidence of a phishing label.

Also record dataset source, revision, license, review process, provenance and
limitations in manifest metadata. The downloaded report identifies the exact
manifest bytes by SHA-256. Keep the manifest with the local report to audit it.
The report omits raw recognized text, URLs and QR payloads, but includes record
IDs, source/resource hashes, browser identity, timings, labels and metric rows.

## Metrics and limits

- CER uses Unicode code-point edit distance with no punctuation, whitespace, case
  or URL repair. CER can exceed 1. For a corpus with no reference characters, CER
  is null; false OCR text on empty references is counted separately.
- Exact text, QR sets and OCR URL sets count every applicable record, including
  failures, timeouts, hash mismatches, absent results and user cancellations.
- QR-positive exact rate and payload recall expose multi-code omissions even if
  another code decodes. Unexpected QR payloads are counted separately.
- English records count unexpected Han characters; failures remain in the English
  denominator. Inspect this together with failure rate, not in isolation.
- Per-language summaries and p50/p95/mean elapsed time are included. Missing files
  have no runtime measurement. Sequential runs include cold worker initialization;
  browser caches and machine load can affect timings.
- The worker currently reports inner OCR timeout and failure together; only its
  outer deadline is distinguishable as `timeout`. Partial results preserve QR
  data. Read the combined failed/partial counts when interpreting coverage.

Asset hashes are verified against the vendored resource manifest at server startup.
Reports include actual extraction source hashes and Git commit/dirty state.
Restart the harness after source changes. Do not edit files during an evaluation.
The metrics module is importable in Node for reproducible scoring and comparison.

## Optional local risk assessment

Start the existing application locally using the normal documented development
configuration. For strictly offline evaluation, disable outbound enrichment and
case management in that backend. The harness does not change backend settings.
Then pass its port:

```sh
python3 website/tools/vision-benchmark/serve.py --port 8930 --api-port 8912
```

Check **Also assess extracted evidence** in the page. The harness forwards only
`POST /api/analyze-visual` to `127.0.0.1` at that fixed port, without credentials,
redirect following, cases, or original image bytes. Network access inside the
backend depends on its own configuration. Missing/failed risk calls stay in the
labeled denominator as unavailable. If risk assessment is disabled, all risk
metrics and predictions are null and `risk_evaluation` is `not_requested`; labels
remain counted, but no model quality or failed risk-call rate is reported.
Medium/high/critical maps to phishing, low/safe to benign, and all other levels to unknown.
This threshold is explicit in the report and does not imply that low risk is safe.

## Regression checks

```sh
node --test website/static/vision-benchmark.test.mjs
python3 -m py_compile website/tools/vision-benchmark/serve.py
python3 website/tools/vision-benchmark/test_server.py
```

Negative controls cover dropped records, malformed labels, altered punctuation,
wrong URLs, missed and extra QR payloads, English/Han errors and hash integrity.
Metrics tests do not substitute for running the actual browser worker.
