# HTML-visible model input and inline-image coverage design

## Goal

Prevent HTML that the reader cannot see from changing the text-model verdict,
and prevent an email containing an uninspected embedded image from receiving a
complete Safe result. These are two boundaries of the same HTML-message analysis
path. The detector must preserve independent link, sender, authentication, and
attachment evidence rather than assuming that an image or hidden text is itself
phishing.

## Evidence and scope

The current rules derive visible text from each HTML MIME part, but the optional
classifier receives the raw combined body. With the committed Vercel model, a
local constructed message with visible phishing text scored 98.8%; adding
benign text inside `<style>` lowered its model score to 15.4% and the combined
verdict from Critical to Low. The converse hidden-text probe raised a visible
benign message's model score from 2.2% to 98.1%. These are regression probes,
not measured production accuracy. An HTML `data:image/png` probe with ordinary
visible text returned Safe and `analysis_complete=true`, whereas a MIME image
attachment returned Unknown and incomplete.

This change covers the full-message and manual content endpoints, their
inference input, HTML inline-image coverage reporting, frontend copy, tests,
and documentation. It does not change the committed model artifact or global
decision threshold; decode QR codes, perform OCR, render HTML/CSS, fetch remote
resources, unpack archives, collect inbox samples, or claim improved Gmail or
Outlook recall.

## Considered approaches

1. **Recommended: score the existing visible-text view.** Reuse the current
   MIME-aware visibility policy for rule and model input while retaining raw
   HTML for destination/link checks. This removes the observed hidden-text
   influence with a small, testable change. Because inference input changes,
   committed-model controls and regression tests are release gates; no new
   accuracy claim follows from those controls.
2. **Disagreement abstention.** Score raw and visible versions and return
   Unknown when they disagree. This is conservative but doubles inference work
   and leaves an otherwise detectable phishing message unclassified.
3. **Retrain now on canonical HTML.** This would align train and serving input,
   but the project lacks a representative, strictly later real Gmail/Outlook
   evaluation set. It is a separate model-development cycle.

## Canonical text and data flow

The content-analysis path will derive one bounded, normalized visible text view
from the subject and body parts. MIME `text/plain` remains literal text;
`text/html` uses the same visible-text parser already used by the rules, so
script, style, comments, titles, and other currently suppressed content cannot
alter the model vector. The manual subject/body path retains its existing rule
visibility convention. MIME parts stay independent: markup in one part cannot
hide text in another part. The model receives this visible view rather than the
raw HTML body. Its context gate and feature vector must derive from that same
visible view at the endpoint boundary; the direct inference API remains
backward compatible for callers that provide plain text.

The current raw HTML remains available only to checks that need structure,
especially link and form destinations, URL parsing, and inline-image discovery.
No HTML is rendered and no destination is fetched. Existing parser-recovery
warnings continue to make the result incomplete. This change does not remove
any independent risk floor or turn a positive rule score into Safe.

Inference-only preprocessing must not silently rewrite the model artifact,
threshold, or benchmark metrics. If committed-model positive/negative controls
or existing regressions fail, the change is not released by adjusting the
threshold to fit the constructed probes. The failure must be reported and the
model-input change reconsidered with representative labeled data.

## Embedded image coverage

For HTML parts, detect embedded `data:image/...` references in image-bearing
locations: `img`/`source` image attributes (including `srcset`) and CSS
`url(data:image/...)` in style attributes or style elements. Ignore text in
comments and script elements. Treat every recognized image format, including
SVG, as opaque; do not decode or sanitize its bytes in this change. A malformed
HTML recovery path remains incomplete under the existing parser warning.

Expose a top-level `inline_image_coverage` object in both manual and raw-message
results. It contains a count capped at 20 and an `inspection_status` of
`metadata_only` when at least one image is present, or `not_applicable` when
none is present; it never returns data-URI payloads or image bytes. At least
one such image adds one distinct top-level analysis warning saying that
embedded image content was not inspected. It adds
zero phishing-risk points and sets `analysis_complete=false`. If the other
checks would return Safe, use the existing Unknown/null-score rule; independent
High or Critical evidence remains visible. The frontend distinguishes this
warning from MIME attachment coverage, parser failure, and unavailable model
scoring. Plain-text literals and non-image data URIs do not create an image
coverage warning.

Remote image URLs are not fetched or decoded. Their destination text continues
through existing URL checks, but this phase does not claim to inspect the
remote image itself. The documentation must keep that limitation explicit.

## Tests and acceptance

Write failing regression tests before production changes. Backend tests cover:

- visible phishing text plus benign hidden HTML and visible benign text plus
  hidden phishing HTML, including actual committed-model positive/negative
  controls and the endpoint verdict;
- a short visible body with long hidden markup, which must not gain model
  context from the hidden text;
- literal `text/plain` markup, multiple MIME alternatives, link/form targets,
  and malformed HTML recovery without cross-part contamination;
- HTML embedded PNG/SVG data images with benign visible text: one bounded
  warning, incomplete Unknown, nullable score, and no added risk points;
- suspicious independent link evidence alongside an embedded image: risk floor
  preserved while completeness remains false;
- comments/scripts and non-image data URIs: no false inline-image claim;
- ordinary text-only and MIME-image-attachment behavior unchanged.

Frontend tests verify distinct wording for embedded images, MIME attachments,
parse warnings, and model abstention, and verify Unknown never renders a green
zero. Final verification runs the full Python and frontend suites, syntax
checks, `git diff --check`, and the Vercel runtime smoke test with the committed
model. The constructed probes are controls for a specific failure mode, not a
substitute for a real, dated provider-specific holdout.

## Compatibility and rollout

The inline-image response fields are additive. Some HTML messages that
previously returned Safe/complete will return Unknown/incomplete, and HTML
model scores may change because hidden text no longer contributes. API
consumers must already accept `unknown` and nullable combined scores. No new
dependency, environment variable, storage, network access, migration, or
deployment is required. Pushing and deployment remain separate actions.
