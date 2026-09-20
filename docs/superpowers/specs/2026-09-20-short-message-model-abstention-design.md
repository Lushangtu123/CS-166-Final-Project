# Short-message model abstention design

## Goal

Prevent the optional text classifier from turning very short, low-context email
text into an overconfident phishing verdict. A short message without independent
risk evidence must be reported as `unknown`, not `safe` and not `critical`.

This change must preserve the existing rule, link, sender, authentication,
message-structure, and attachment analysis. Independent evidence can still
produce a risk verdict when the text model abstains.

## Scope

This change includes:

- a deterministic minimum-context gate before vectorization and classification;
- a distinct `insufficient_context` model status;
- conservative fusion behavior for that abstention;
- user-facing copy that explains that the message contains too little text for
  reliable model scoring;
- committed-model and endpoint regressions for short legitimate and phishing
  controls;
- documentation and changelog updates.

This change does not include:

- retraining or replacing the committed model artifact;
- changing its SHA-256 digest or global decision threshold;
- adding multilingual training data, OCR, QR decoding, or DMARC discovery;
- treating short text as evidence that a message is safe.

## Context gate

`predict_content` will normalize the combined subject and body for the sole
purpose of measuring available context. The model will abstain before calling
the vectorizer or classifier unless the input contains both:

- at least five Unicode word tokens; and
- at least 40 non-whitespace characters.

Requiring both conditions prevents character n-grams from making inputs such as
`Hello`, `Meeting notes`, or `File shared with you` appear well supported. URL,
header, attachment, and rule analysis remain outside this gate and continue to
run normally.

When the input fails either condition, the model result will contain:

- `ml_status: insufficient_context`;
- nullable model prediction and score fields;
- the configured decision threshold;
- no model contributors.

The existing `insufficient_feature_coverage` status remains for inputs that pass
the context gate but produce no fitted vectorizer features.

## Risk fusion and API behavior

The content endpoint already excludes nullable model scores from fusion. The new
status will follow that path. If no independent heuristic or structure evidence
exists, the final response will have:

- `risk_level: unknown`;
- `combined_phishing_score: null`;
- `analysis_complete: false`;
- an analysis warning that model scoring was not applied because the input had
  insufficient context.

If rules or message structure find risk, their score and risk floor remain
visible. A model abstention must never erase detected evidence or downgrade an
existing risk floor.

## User interface

The current model-abstention presentation will recognize
`insufficient_context` and explain that the message contains too little text for
reliable model scoring. It will not show model probability bars or label the
message safe. Existing incomplete-analysis and independent-evidence rendering
remain unchanged.

## Tests

Tests will be written before production changes and observed failing for the
missing behavior.

Unit coverage will verify that:

- short input returns `insufficient_context` without calling the vectorizer or
  classifier;
- sufficiently detailed text still reaches the classifier;
- zero-feature text that passes the context gate still returns
  `insufficient_feature_coverage`.

Committed-artifact and endpoint regressions will cover short legitimate subjects
including `Hello`, `Meeting notes`, `File shared with you`, `Your receipt`, and
`Document available`. With no independent evidence, they must not receive an ML
phishing prediction or a final phishing verdict.

Short phishing controls will verify that independent evidence remains active.
Examples with a suspicious destination, explicit credential request plus
pressure, or dangerous attachment metadata must still receive the appropriate
rule or structure risk even when the text model abstains.

Frontend tests will verify the new explanation and the absence of probability
bars for `insufficient_context`.

Final validation will include the full Python suite, frontend suite, Python and
JavaScript syntax checks, Vercel runtime smoke test, and `git diff --check`.

## Compatibility and operational impact

The response schema remains additive: existing model fields remain present and
nullable, while `ml_status` gains one documented value. No environment variable,
database migration, external service, model rebuild, or deployment secret is
required.

The change deliberately favors an honest unknown result over an unsupported
classifier verdict. It does not claim improved recall for short, text-only
phishing messages; those require representative labeled data in a separate
model-development cycle.
