# Case workflow: shared online pilot

The accepted scope is case creation from analyzed mail, filtering, evidence,
phishing/legitimate/uncertain reviews, notes, pending → in progress → closed,
reopening, and actor/timestamp history. The user selected the existing Vercel
project for multiple analysts. This supersedes the original local-only design.

## Deployment and access

Vercel uses Upstash REST, reusing the deployment's existing Redis connection
under an independent `phishguard:cases:v1:<workspace>` hash. No new dependency or
paid resource is required. SQLite remains an optional local/test adapter and is
rejected on Vercel. There is no cloud-to-local fallback.

Every case data API requires a distinct analyst bearer token; only SHA-256 token
hashes are configured on the server. Generate 256-bit random tokens with
`website/manage_case_access.py`. Tokens stay in browser memory, are transmitted
only in Authorization headers over HTTPS, and are cleared on logout/navigation.
All analysts share access to this one organization. This is not multi-tenancy,
SSO, role-based authorization, or tamper-proof audit logging against database admins.

## Evidence and workflow

The ordinary analyzer stays transient. Explicit case creation runs the existing
server detector and stores extracted text (bounded to 60,000 characters), analysis,
input SHA-256, deployed code/registry digest, model digest and Git commit where
available. Attachment metadata is retained, original attachment bytes are not.
Message HTML is shown as text, with a strict workspace CSP and no remote assets.
Case responses, errors and page are marked no-store.

UUID creation keys are scoped to an authenticated actor. Reusing a key with a
different input is a conflict. Versioned updates reject stale writes with 409.
Closing requires a human verdict; verdict changes require explanatory notes.
The server generates actor IDs and UTC timestamps. The API has no evidence
mutation, event editing or deletion endpoint.

## Atomic cloud storage and limits

A single Redis hash holds `r:<id>` full records with embedded event histories,
`s:<id>` summaries, and `q:<actor-key-hash>` idempotency references. Lua validates
existence/version/capacity then updates every affected field with ONE HSET.
Creation and review histories cannot be partially committed by separate writes.
A timeout is reported as uncertain; creation retries retain their UUID, reviews
require reloading the latest version before another decision.

Pilot caps: 100 cases/workspace, 200 events/case, 750 KB encoded record, 4 MB
response, 5-second REST timeout. The total worst-case record content is below
the existing free provider's 100 MB per-record cap; summaries are read separately.
Lists filter small bounded summaries on the server. Reaching a cap refuses writes;
no evidence/history is silently discarded. Cases have no expiry. Provider eviction
must remain OFF. Capacity/retention/export/backup operations need an administrator;
there is no automated deletion or backup feature in this first version.

Only configure enablement/access in Production. Preview deployments remain
disabled unless explicitly assigned a separate workspace AND separate analyst
credentials. Never share production case storage with preview/test deployments.

## Verification

Local suites cover real detector/EML integration, auth, disabled defaults,
restart persistence, filters, close/reopen, idempotency, simultaneous edits,
cloud transport failure/secret redaction, and frontend stale responses/XSS/logout.
Browser verification uses synthetic mail through the entire workflow.
`website/tests/case_cloud_cli_smoke.py` prints a console command exercising the
actual Lua scripts with synthetic data in a unique one-hour test namespace.
Full Vercel HTTP-to-storage verification follows deployment with configured access.
