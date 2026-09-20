# Attachment inspection coverage design

## Goal

Make full-message results honest about attachment coverage. The detector currently
checks ordinary attachment names and MIME types but does not inspect their body
bytes. A benign-looking message with an image can therefore return
`analysis_complete: true` and `risk_level: safe`, even though the image may carry
a QR-code lure. This change must prevent that misleading result without treating
every attachment as malicious.

## Scope

This change covers `.eml`/raw-message analysis, attachment status in the API,
analysis completeness, result copy, regression tests, and documentation. It does
not decode QR codes, perform OCR, unpack archives, execute attachments, change
the text-model artifact or threshold, or send attachment bytes to a third party.

## Attachment status contract

Every returned `message_structure.attachments[]` item keeps its existing
`filename` and `content_type` fields and gains `inspection_status`:

- `metadata_only`: the detector checked the name and MIME type but did not
  inspect the attachment's content. This applies to ordinary attachments,
  including text files, images, PDFs, and archives, and to non-text MIME leaves
  such as inline images even when they have no filename or attachment
  disposition.
- `message_analyzed`: a `message/rfc822` or `message/global` attachment whose
  child message was successfully traversed within the existing depth and count
  limits. This means the child message was analyzed under the current detector
  capabilities; any opaque attachment inside it remains `metadata_only` and
  makes the overall result incomplete.

If an attached message cannot be parsed, uses an unsupported transfer encoding,
or exceeds the nesting limits, it remains `metadata_only` and retains the
existing parse warning. When duplicate MIME interpretations or identically
named parts cannot be distinguished, the status must conservatively remain
`metadata_only`; the API must not claim that every copy was analyzed.

The `metadata_only` status is not a risk signal. It adds no phishing points and
does not replace the existing dangerous-extension/MIME and archive checks.

## Analysis completeness and verdict

Any `metadata_only` item adds a bounded attachment-coverage warning to the
top-level `analysis_warnings`, separate from `message_structure.parse_warnings`.
The warning states that only filename and MIME type were inspected, not
attachment content. `analysis_complete` becomes `false`.

If the available checks otherwise yield `safe`, the existing incomplete-result
rule changes the public result to `unknown` and clears the combined risk score.
Independent risk evidence still determines the verdict: a dangerous executable
or suspicious URL can remain `high` or `critical`, accompanied by the
incomplete-coverage warning. A small nonzero sender/heuristic score is not
automatically upgraded to phishing because of an opaque attachment; its
existing risk level is retained with `analysis_complete: false`.

Successfully analyzed attached messages do not by themselves make the result
incomplete. Parser errors, model abstention, or opaque children can still do so.
Messages without opaque attachments preserve their current behavior.

## User interface

The content result will explicitly say when attachment contents were not
inspected. Parser problems and unavailable model scoring will use separate,
accurate wording; the generic incomplete banner must not claim every
incomplete result is a parsing failure. The attachment list/status and warning
must not expose raw attachment bytes.

## Tests and acceptance

Tests are written before production changes and observed failing for the
missing behavior. Backend tests cover:

- a benign long message with an image attachment: `metadata_only`, incomplete,
  and `unknown`, not `safe`;
- an inline non-text image with no filename: represented and `metadata_only`;
- attachment-only benign content: `unknown`;
- dangerous extension or MIME type: existing high-risk floor is preserved while
  the result is incomplete;
- successfully parsed attached `.eml`: `message_analyzed` and no new attachment
  warning when the nested message itself is fully analyzable;
- malformed/opaque or depth-limited attached messages: `metadata_only` and
  incomplete;
- ordinary text-only messages: unchanged verdict and completeness.

Frontend tests verify distinct attachment-coverage wording and that an
incomplete, otherwise safe result renders Unknown without a green zero.

Final verification includes the full Python suite, frontend suite, Vercel
runtime smoke test, syntax checks, `git diff --check`, and a real-model
positive/negative control. No deployed service is changed by this work unless
the user separately asks to push or deploy it.

## Compatibility

The attachment item change is additive. `analysis_complete` and `risk_level`
can change for emails containing uninspected attachments; API consumers must
already handle the documented `unknown` level and nullable combined score.
Existing request limits, sender-history boundaries, and no-storage behavior
remain unchanged.
