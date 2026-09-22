# User Feedback Reporting Design

## Goal

Add a private review path for users who believe PhishGuard produced an incorrect
result. The public demo will accept bounded feedback without exposing the case
workspace or changing the analysis result. Analysts will review submitted
feedback inside the existing authenticated case workspace.

The same change will move the Email Content actions to a right-aligned action
row so the primary action is visually anchored at the end of the form.

## Scope

This design covers:

- feedback entry points for Email Address and Email Content results;
- false-positive, false-negative, risk-level, evidence, and other reports;
- explicit consent before retaining original input;
- isolated feedback storage using the existing case-storage credentials;
- authenticated review in the case workspace;
- responsive right alignment for Analyze Content, Clear, and Cancel scan;
- validation, rate limiting, idempotency, privacy, and regression tests.

It does not retrain a model automatically, change a submitted prediction,
publish reports, send feedback to TypeSafe, or store an uploaded image file.

## User Experience

### Report entry points

After a successful analysis, its result area displays a secondary **Report an
issue** action. Both demo tabs support the action. Clearing the form, switching
to a new input, or starting another analysis invalidates the report context so a
stale result cannot be reported as if it belonged to the current input.

The action opens an accessible dialog with:

- a required issue type: `false_positive`, `false_negative`,
  `incorrect_risk`, `incorrect_evidence`, or `other`;
- an optional explanation of at most 2,000 characters;
- an unchecked consent control labelled **Include the original email content
  for private review**;
- a concise description of what will be retained with and without consent;
- Cancel and Submit report actions.

Submission locks the form until the request completes. Success replaces the
form with a receipt containing the opaque feedback ID. A failed request keeps
the selections and note so the user can retry. The dialog never implies that a
report has changed the current verdict.

### Input-specific consent behavior

Without consent, PhishGuard stores only a bounded diagnostic snapshot, the
issue type, the user's note, the input mode, and a one-way input fingerprint.
It does not store the sender address, subject, body, raw MIME, extracted OCR
text, QR destinations, or image bytes.

With consent:

- Email Address reports may include the submitted address.
- Manual Email Content reports may include subject and body.
- `.eml` reports may include the original message within the existing 60 KB
  limit.
- Image reports may include locally extracted OCR text and QR evidence, but
  never the image file or inline image data.

The client sends source material only when the consent control is selected. The
server also rejects source fields when consent is false, so a modified client
cannot silently attach content.

### Content action layout

Email Content uses one `.content-input-actions` row aligned to the right. Its
visual order is Cancel scan, Clear, Analyze Content. Cancel scan is present only
while browser recognition is active. Analyze Content remains the primary
button. On narrow screens the group wraps without overflowing and remains end
aligned; controls may expand to a comfortable touch width.

## Architecture

### Reusing the case domain with isolated storage

`CaseService` will own two stores with the same case-record contract:

- `store` for analyst-created investigation cases;
- `feedback_store` for public user feedback.

On Upstash, the feedback store uses a separate key derived from the configured
case workspace, with a deterministic length-safe suffix. An optional
`CASE_FEEDBACK_WORKSPACE` setting can override the derived name. On SQLite, the
feedback store uses a private sibling database file. This keeps feedback
capacity, idempotency keys, and list operations separate from formal cases
without requiring a second cloud database.

Feedback records reuse case status, verdict, version, events, and review rules.
Their provenance includes `record_kind: user_feedback`, report type, user note,
consent state, input mode, and diagnostic schema version. List summaries expose
the record kind so the workspace can show a **USER FEEDBACK** badge and filter
between all records, cases, and feedback.

Feedback IDs remain opaque. Authenticated case reads and updates locate a
record in the correct store without revealing which IDs exist to public users.

### Public submission API

`POST /api/feedback` accepts JSON and requires a UUID `Idempotency-Key` header.
The Pydantic request model forbids extra fields and bounds every string and
collection. The request contains:

```json
{
  "report_type": "false_positive",
  "note": "The sender and authentication results are legitimate.",
  "include_source": false,
  "input_mode": "content",
  "input_fingerprint": "sha256:...",
  "analysis": {
    "risk_level": "high",
    "risk_score": 78,
    "risk_label": "High risk",
    "analysis_complete": true,
    "model_id": "sha256:...",
    "evidence_codes": []
  },
  "source": null
}
```

The analysis object is an allowlisted snapshot for triage, not a trusted model
evaluation. Stored provenance marks it as client-reported. If source is
included, the server validates the consent and source type, removes inline data,
and enforces the existing address, text, MIME, OCR, and QR limits.

The API returns `201` with the feedback ID for a new record and the same record
for a matching idempotent retry. It does not expose a public read endpoint.

### Browser state

`app.js` keeps separate latest-result contexts for sender and content analysis.
Each context contains an allowlisted analysis snapshot, an input fingerprint,
and a lazy source builder. The source builder is called only after the user
selects the retention consent. Starting, clearing, or invalidating an analysis
also invalidates its feedback context.

A focused feedback module controls the dialog, builds the request, submits it,
and renders success or failure. The module receives the latest context through
a narrow interface so reporting logic does not depend on result-rendering
internals.

### Case workspace

The authenticated list endpoint accepts `kind=all|case|feedback`, defaulting to
`all`. It queries the necessary store or stores, merges summaries by creation
time, and applies pagination after the merge. Detail and review routes resolve
the record from the appropriate private store.

The workspace adds a record-kind filter and a **USER FEEDBACK** badge in the
queue and detail header. Feedback detail shows report type, consent state, user
note, and whether source material is available. Analysts use the existing
pending, in-progress, closed, verdict, and note controls. Source-free reports
are clearly marked as limited-context feedback.

## Privacy and Security

- The privacy notice will explain that ordinary analysis is transient and that
  only an explicitly submitted report is retained.
- Original source is omitted by default and is never reconstructed from page
  state on the server.
- Image bytes and inline data URLs are never accepted by the feedback API.
- Feedback is available only through the existing analyst authentication.
- Stored user text is rendered with text nodes, never trusted HTML.
- The API uses the existing host, security-header, request-body, and general API
  rate-limit protections plus a stricter feedback limit of five submissions per
  client per hour. Distributed limiting uses the configured Upstash-backed
  limiter when available; the bounded local limiter remains the fallback.
- Client addresses are used for limiting and are not stored with a report.
- Feedback submission never calls Jev or another external AI provider.

## Failure Handling

- Invalid types, consent/source mismatches, or oversized values return `422`.
- Oversized request bodies return `413` before JSON decoding.
- Rate-limited requests return `429` with `Retry-After`.
- Missing or invalid case configuration returns `503` for feedback submission
  while the public analyzer continues to operate.
- Storage uncertainty returns a retryable `503`; idempotency prevents a retry
  from creating a duplicate if the first write completed.
- Workspace list failures do not mislabel a partial list as complete.
- A reporting failure leaves the analysis result and dialog input intact.

## Test Plan

Backend tests will cover:

- request-model bounds and rejection of extra fields;
- source rejection without consent and allowlisted retention with consent;
- omission of address, content, MIME, OCR, QR, and image data by default;
- input fingerprint and idempotent retry behavior;
- isolated case and feedback capacities and keys;
- rate limits without persisted client addresses;
- authenticated list, detail, update, kind filters, and record badges;
- unavailable or malformed storage behavior;
- request-body limits and private cache/security headers.

Frontend tests will cover:

- report actions appearing only for current successful results;
- invalidation after clear, new analysis, and stale asynchronous responses;
- dialog validation, focus behavior, escape/cancel, and submission locking;
- source builders running only after explicit consent;
- success receipt, retry state, and duplicate-click protection;
- sender, manual content, `.eml`, and image payload shaping;
- feedback badges and filters in the case workspace;
- right-aligned controls, scan-only Cancel visibility, and mobile wrapping.

Release verification will run the complete Python and Node test suites, Vercel
runtime smoke, static asset checks, and browser flows for both reporting modes
and the authenticated workspace. Production deployment remains gated by the
existing CI and post-deploy smoke workflow.

## Rollout

The feature is available only when case management and its feedback store are
configured. No new external service is required. The first deployment will
verify a synthetic, content-free report in Preview, review and close it in the
workspace, and remove the test record before Production promotion. Production
verification will submit only synthetic text and will not call Jev.
