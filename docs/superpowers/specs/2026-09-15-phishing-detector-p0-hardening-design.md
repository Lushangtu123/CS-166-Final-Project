# Phishing Detector P0 Hardening Design

## Goal

Close three reproduced production false negatives without enabling the optional
text model, adding network lookups, or changing the public API incompatibly. The
rules-only Render deployment must detect suspicious senders inside uploaded
`.eml` messages, common ASCII link deception, and dangerous attachment MIME
types while preserving low-risk results for canonical domains and ordinary
documents.

## Scope

This pass implements only the approved P0 items:

1. Reuse sender/domain heuristics when a complete raw email is analyzed.
2. Detect ASCII brand lookalikes, URL userinfo deception, and protected-brand
   labels embedded in noncanonical link destinations.
3. Evaluate attachment MIME types in addition to filename extensions.

ML shadow mode, OCR/QR analysis, archive extraction, Public Suffix List
integration, external reputation lookups, observability infrastructure, and
large module decomposition remain out of scope.

## Design

### Shared sender analysis

Extract the response construction currently embedded in `POST
/api/analyze-email` into a pure sender-analysis helper. The existing endpoint
will call the helper so its response contract and scoring remain unchanged.

When `POST /api/analyze-content` receives `raw_email`, it will parse the mailbox
from the normalized `From` header and call the same helper. The response will
include an additive `sender_analysis` object. Sender evidence will be fused into
the content result using a bounded mapping:

- critical sender verdict: add 6 points and set a high-risk floor;
- high sender verdict: add 5 points and set a high-risk floor;
- medium sender verdict: add 3 points and set a medium-risk floor;
- low verdict with a nonzero sender score: add 1 point;
- a clean low verdict: add no points.

Sender indicators will be copied into the explainable indicator list with a
clear sender prefix. This reuses one source of truth and prevents the sender-only
and raw-email workflows from drifting apart.

### Link destination hardening

Keep the existing URL parser and canonical-domain allowlist. Add three
conservative checks after parsing each HTTP(S) destination:

1. Treat a nonempty URL username or password as high risk because userinfo can
   make an attacker URL appear to begin with a trusted domain.
2. Normalize individual hostname labels with the existing Unicode skeleton plus
   common digit substitutions used in brand lookalikes (`0`, `1`, `3`, `4`,
   `5`, and `7`). If the normalized label contains a protected brand but the
   destination is not one of that brand's canonical domains, set a high-risk
   floor.
3. Apply the protected-brand check to every label, not only the first label, so
   destinations such as `paypal.com.evil.example` cannot borrow a trusted brand
   in a deceptive subdomain chain.

The checks will not perform DNS requests or follow redirects. Canonical domains
and their subdomains remain negative controls. Findings stay deduplicated by
type so repeated links cannot inflate the score without bound.

### Attachment MIME classification

Extend raw-message attachment metadata with its normalized MIME type and compare
that value against explicit dangerous and archive MIME registries. A dangerous
extension or MIME type will add one high-risk finding; an archive extension or
MIME type will add one medium-risk finding. A single attachment that matches
both filename and MIME rules will be counted once.

The dangerous registry will cover executable/script payloads, Java archives,
macro-enabled Office documents, and disk images. The archive registry will
cover ZIP, 7z, RAR, TAR, and gzip types. Ordinary PDF and image attachments will
remain unscored. Payload bytes will not be opened or executed.

## Data Flow

1. Parse request text and, when present, the raw RFC 5322 message.
2. Analyze subject/body content and link destinations.
3. For raw messages, analyze headers, sender address, and attachment metadata.
4. Merge bounded sender and structure contributions into the heuristic score.
5. Apply the strongest risk floor, then run the existing conservative fusion
   path. The optional ML path remains unchanged and disabled in Render.
6. Return existing response fields plus additive sender details for raw input.

## Error Handling and Compatibility

- A missing or malformed `From` mailbox produces no sender contribution and
  does not abort content analysis.
- Invalid or malformed link destinations retain the current safe parsing
  behavior and explanatory finding.
- MIME values are compared case-insensitively after removing parameters.
- Unknown MIME types fall back to filename-extension analysis.
- Existing endpoint fields remain unchanged; `sender_analysis` is additive and
  appears only when a usable raw-message sender is present.
- No dependency, environment-variable, database, or deployment change is
  required.

## Test Strategy

Implementation will follow red-green-refactor cycles. Each new behavior must be
observed failing before production code changes.

Focused positive controls:

- `billing@secure-account.xyz` in a raw message contributes sender risk;
- `https://paypa1.com` receives a high-risk brand-lookalike finding;
- `https://paypal.com@evil.example` receives a high-risk userinfo finding;
- `https://paypal.com.evil.example` receives a high-risk deceptive-brand finding;
- an extensionless `application/x-msdownload` attachment is high risk;
- an extensionless `application/zip` attachment is medium risk.

Negative controls:

- a canonical sender such as `user@gmail.com` does not raise raw-message risk;
- `https://paypal.com` and its ordinary subdomains are not brand-lookalike
  findings;
- `invoice.pdf` with `application/pdf` is not a dangerous attachment.

Final verification will run the focused regression class, all backend tests,
frontend tests, Python and JavaScript syntax checks, `git diff --check`, and the
original production-style attack examples locally.

## Acceptance Criteria

- The four reproduced sender/link false negatives no longer return safe or low
  risk when analyzed through their original workflow.
- Dangerous MIME types cannot evade detection by omitting a filename extension.
- Canonical brand domains and benign attachment controls remain below the new
  high-risk floors.
- Sender-only API behavior and existing response fields remain compatible.
- The Render rules-only profile remains valid and requires no additional
  services or credentials.
- All existing and new tests pass, and unrelated files remain untouched.
