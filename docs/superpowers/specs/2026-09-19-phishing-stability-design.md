# Phishing Detector Stability Design

## Objective

Reduce false positives and unsupported-language overconfidence without weakening
existing structural, sender, authentication, link, or attachment-metadata checks.
This batch deliberately excludes PDF, QR-code, image, and SVG content scanning;
those require a separate resource and sandbox design.

## Scope

1. Make the text model abstain when the fitted vectorizer produces no usable
   features. The result must expose an explicit unavailable/insufficient-
   coverage status. Rule and message-structure analysis must continue, and an
   abstention must never be presented as proof that the message is safe.
2. Add hard-negative regression cases for ordinary English and multilingual
   correspondence, including representative Gmail and Outlook raw-message
   fixtures. Preserve positive controls for credential phishing, BEC, callback
   fraud, and QR-code lure text.
3. Require both a positive and a negative control in the local Vercel runtime
   smoke test and the post-deployment HTTP smoke test.
4. Rename UI probability/confidence language to model score language. Continue
   to expose the learned threshold and model identifier.
5. Report Wilson 95% intervals for validation and temporal-holdout false-
   positive rate and phishing recall. The threshold constraint remains an
   observed validation-sample constraint, not a population guarantee.
6. Parse `To` and `Cc` header candidates. Add bounded, non-decisive indicators
   for self-addressed messages and messages with no visible recipient. These
   indicators may raise suspicion but cannot independently establish phishing.

## Runtime Contract

The text inference result gains an `ml_status` field. Supported inference uses
`available`; zero-feature inference uses `insufficient_feature_coverage`, sets
the ML probabilities and prediction to `null`, supplies no contributors, and
does not contribute an ML value to risk fusion.

The UI hides probability bars when ML abstains and explains that the rule,
sender, link, and message-structure checks still ran. Supported ML output is
labelled a model risk score, not calibrated confidence.

## Evaluation Contract

The committed artifact records interval bounds alongside point estimates. The
existing 2025 SpaPhish slice is documented as a regression evaluation slice,
not a permanently untouched release lockbox. A future provider-specific
lockbox remains required for Gmail/Outlook production claims.

## Recipient Signals

Raw-message parsing preserves all bounded `To` and `Cc` candidates alongside
the existing `From`, `Reply-To`, and `Return-Path` candidates. Self-addressed or
recipient-hidden patterns generate informational or low/medium evidence only;
they do not override trusted authentication or make a message malicious by
themselves.

## Tests and Acceptance Criteria

- Harmless Chinese, Japanese, and unknown-Unicode inputs with zero model
  features cause ML abstention rather than a high-risk intercept prediction.
- Ordinary meeting, personal, and monthly-report messages are not classified
  high or critical by the committed model.
- Existing phishing positive controls remain high or critical.
- Runtime and deployed smoke tests fail if the positive control is missed or
  the legitimate control is labelled phishing.
- Wilson interval calculations have deterministic boundary tests.
- `To`/`Cc` parsing and recipient anomaly signals have positive and negative
  controls.
- Backend, frontend, artifact, syntax, dependency, and Vercel runtime checks
  pass after the final change.

## Deployment and Compatibility

This stability batch introduces no additional runtime dependency. The
`tldextract` change visible in the shared worktree belongs to the preceding,
separately approved public-suffix update and is not introduced by this design.
The artifact schema may be extended
only through optional metadata so the current verified loader remains usable.
Any rebuilt model receives a new SHA-256 digest in `vercel.json`. This work does
not commit, push, or deploy.
