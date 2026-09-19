# Vercel Almost-Full Deployment Design

## Goal

Deploy the current PhishGuard application to a Vercel Hobby preview with the
largest honest feature set that fits the platform. The deployment must not
claim that a mailbox or sender is authenticated when only domain-level evidence
is available.

## Runtime profile

The root `app.py` exports the existing FastAPI application as one Vercel Python
Function. Static assets remain served by FastAPI so the existing frontend and
API retain the same origin. The deployment uses Python 3.12, one application
bundle, a 30-second function ceiling, and four bounded verification threads per
warm instance.

The public profile enables:

- sender/domain heuristics;
- content, MIME, header, and `.eml` analysis;
- a SHA-256-verified, prebuilt TF-IDF model when a compatible artifact is
  included and passes startup validation;
- bounded DNS MX, SPF, DMARC, PTR, and best-effort WHOIS checks.

SMTP `RCPT TO` probing remains disabled. It is an invasive, unreliable public
service primitive and is not required to describe the domain evidence.

## Verification contract

Configuration exposes `off`, `lite`, and `full` modes. Public `production` or
`demo` profiles may use `lite` but reject `full`; local development may opt into
`full`. Legacy `ENABLE_EMAIL_VERIFICATION=true` continues to mean local full
mode unless an explicit mode is supplied.

The verification response keeps existing flat fields for compatibility and
adds two explicit summaries:

- `domain_verification`: `valid`, `partial`, `invalid`, `no_mail_service`,
  `unavailable`, or `invalid_format`, plus a completion flag;
- `mailbox_verification`: `accepted`, `rejected`, `inconclusive`, or
  `unavailable`.

Lite mode returns `overall=domain_valid` when mail-routing records exist. It
never returns `verified`. A recently registered domain can still escalate the
overall result to `suspicious`. `verification_complete` remains false when the
mailbox check is unavailable, while `domain_verification.complete` can be true.

## ML artifact

Training is an explicit local build step and never runs in a request or service
startup. The deployment artifact is generated from the locally present public
corpora with grouped train/test isolation and the existing fast Logistic
Regression profile. The artifact must be compatible with the deployed Python
and scikit-learn minor versions, pass its configured SHA-256 digest, fit within
Vercel's bundle limit, and load successfully in a production-profile smoke
test. If any gate fails, the deployment falls back to rules-only analysis and
reports the model error through `/health`.

Inference loading is separated from the training module so the Vercel runtime
does not need pandas. NumPy and scikit-learn remain runtime dependencies because
the serialized vectorizer and classifier require them.

## Failure handling and resource bounds

All outbound checks share the existing request deadline and bounded executor.
DNS, WHOIS, or capacity failures produce partial/unavailable evidence, not an
invalid-mailbox verdict. Public configuration uses a lower request rate and
four verification workers. The in-process rate limiter is a per-instance safety
bound, not a globally consistent quota across serverless instances.

## Acceptance checks

1. Public Lite configuration starts without enabling SMTP.
2. `/api/config` exposes Lite/domain/mailbox capabilities accurately.
3. A mocked successful domain lookup returns `domain_valid` and mailbox
   `unavailable`; SMTP is never called.
4. Local Full mode retains the existing SMTP result behavior.
5. Frontend copy shows domain checks and labels SMTP as unavailable.
6. Model loading verifies digest and runtime compatibility, and the application
   starts without importing pandas.
7. Python, frontend, and production-profile HTTP smoke tests pass before the
   preview deployment is created.
