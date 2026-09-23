# Case workspace operations

## Jev availability and request controls

Normal cases show a Jev status panel even when the optional feature is disabled.
**Refresh** reads `/api/cases/me` again and keeps unsaved review notes. It never
calls TypeSafe. Environment changes in Vercel still require a new deployment.
The panel distinguishes disabled, invalid configuration, unavailable control
storage, daily quota exhausted and configured states. "Configured" does not
prove that the provider will accept the key. User feedback is not eligible for Jev.

`PHISHGUARD_JEV_DAILY_LIMIT` defaults to 20 attempts per UTC day (range 1–1000).
The shared budget uses a separate Redis hash,
`phishguard:jev:v1:<CASE_WORKSPACE>:<VERCEL_ENV>`, so Production and Preview have
separate counts and receipts. The existing case hash is untouched. All instances
must use the same workspace, environment and limit. Local SQLite installations
use transactional `jev_budget` and `jev_receipts` tables in the case database.

Before sending a request, the server atomically reserves one attempt and stores
a pending receipt. The identity covers analyst, case, minimized input, pinned
model and question hash. Review notes and case revision are excluded because
they do not change the model input. An identical request by that analyst reuses
the structured result for **24 hours**, including errors, and does not consume
another attempt. Other analysts and other cases have separate request identities
but share the daily budget. A quota-exhausted workspace can still retrieve an
existing receipt. Empty or oversized inputs consume no attempt.

A timeout may still have incurred a provider charge. A failed/uncertain storage
operation or provider outcome never triggers an automatic retry. If no result
could be saved, the receipt stays pending until it expires; a later deliberate
request can try again after expiry and subject to that day's allowance. Do not
delete receipts or switch namespaces to retry an uncertain call. The daily count
limits attempts, not money; keep provider-side spending controls.

One exception is `local_capacity_exhausted`: the adapter could not acquire a
worker slot and made no TypeSafe request. The server atomically releases that
pending claim and its same-day allowance, allowing a later manual retry. It
does not refund another day's budget, a different claim, or any completed result.
If releasing the claim fails, the request remains protected against duplicates.
Older cached failures keep their original expiry; they are not migrated or erased.

Receipts hold hashes, claim IDs, timestamps and structured model results, never
email text, tokens or raw provider responses. These temporary receipts are excluded
from case archive/restore/purge tools. Redis makes receipts
unusable after 24 hours, removes expired entries on the next successful reservation,
and expires the whole hash 48 hours after its last reservation. In local SQLite,
expired receipts are unusable immediately and physically removed on the next
successful reservation; ordinary host backup/retention policies still apply.

**View existing result** uses authenticated `GET /api/cases/{id}/auxiliary` to
read the current analyst's receipt for the current input, model and questions.
It works even when new Jev calls are disabled or quota is exhausted. It never
contacts TypeSafe, reserves an attempt, cleans up receipts or extends their expiry.
Missing/expired and pending results are shown explicitly; retrieval does not
automatically request a replacement. Provider failure receipts remain failures.

After viewing a successful result, **Save opinion to history** asks for explicit
confirmation before `POST /api/cases/{id}/auxiliary/save`. The server retrieves
the matching unexpired receipt; the browser submits only its identifier, expected
case revision and confirmation, never probabilities or model content. The history
records the saving analyst, save time, original request time, model, question and
minimized-input hashes, bounded probabilities and evidence-coverage flag. It copies
no message text or provider response. Everyone with workspace access can read the
saved opinion. It follows the case's retention policy and is included in existing
archive/restore/purge operations, even after the temporary receipt expires.
Saving increments the case revision with the same atomic conflict checks as a
review; risk, status, verdict and original detection evidence are unchanged.
Only open formal cases support a new opinion entry; reopen closed cases first.
Ordinary history writes reserve the final workflow steps within the 200-event
limit; ordinary writes also preserve closing space within the 750 KB byte limit.
Retrying the same analyst/receipt returns
the existing record without another event, including after receipt expiry.
The response's `auxiliary_save.outcome` distinguishes `saved` from `already_saved`,
with the submitted `base_version` and `receipt_id`. Only an actual new opinion
write can automatically advance a matching review draft. A repeated save that
returns somebody else's newer review keeps the draft conflict visible.
A concurrent writer may cause a conflict: reload the case before retrying.

`/health` and `/api/config` expose only `jev_enabled` and `jev_configured` flags.
Production smoke uses `--require-jev` to detect missing deployment configuration
without contacting TypeSafe or exposing keys. This is a post-deployment check,
not a provider connectivity test or an automatic rollback. CI also runs the Lua
control tests against its own disposable Redis, using random synthetic namespaces.

## Opening and reviewing cases

Pagination commits a new page only after its request succeeds. A failed Next or
Previous request keeps the displayed page and offset; retry requests the same
target page. Late responses cannot replace a more recent filter or page result.

While a review save is in progress, newer edits to the note or review selections
remain in the form after the saved revision arrives. The notice identifies them
as unsaved. The next save uses the new revision. If a draft status is no longer
allowed, select an available status before saving. Leaving the page still
requires saving your draft first. Review drafts now stay
in this tab's memory when switching or reloading cases. A draft restored against
a newer server revision blocks saving until you compare the latest evidence and
history and choose **I reviewed the latest revision — keep my draft**. Invalid
status transitions still require choosing a valid status. **Discard draft**
restores the saved fields. The page asks before leaving with unsaved work;
browsers may suppress that prompt. Sign-out clears all drafts, and manual
sign-out asks before discarding them. Drafts are not written to browser storage
and cannot survive a refresh, tab closure, browser crash or expired session.
Late detail responses cannot replace a newer revision already observed in the tab,
including a review or opinion saved while a detail read was still in flight.

The combined queue reports source availability separately. If one namespace cannot
be read, it shows records and counts only from healthy sources and displays a
partial-results warning. It returns 503 if no requested source can be read.
Refreshing retries both sources; the warning disappears on recovery. Opening,
reloading and reviewing a row specifies `kind=case` or `kind=feedback`, so an
unrelated namespace failure cannot block that record. Legacy API callers omitting
kind retain the original lookup order. Pagination and total counts during an
outage refer only to the available sources and may change when storage recovers.

Use the homepage **Case login** button (also visible on mobile) to open
`https://phishguard-email-analyzer.vercel.app/cases` and sign in with your
individual analyst token. Bookmark this stable address, not a deployment-specific
Vercel URL. For local development, open `/cases` on the local server. Create a case from
subject/body, an original `.eml` file, or a PNG/JPEG/WebP image. Creation saves extracted text and detection
evidence; the public analyzer does not automatically create cases. Everyone
configured for this workspace can read and review its cases.

Users can select **Report an issue** after either public analysis result.
Reports are saved to a separate private feedback namespace and appear in the
same analyst queue with a **USER FEEDBACK** badge. Use the **Type** filter to
show feedback only. Each report records its issue type, note, client-reported
diagnostic summary, and whether the user consented to retain original input.
The report does not change the prediction or retrain the model. An analyst
should verify the evidence before recording a human verdict.
The public report action appears only while the case workspace is configured.

Reports omit the sender address, email text, raw EML, OCR text, QR payloads and
image bytes by default. With explicit consent, they can retain the address,
manual text, an original EML up to 60 KB, or extracted OCR/QR text. Images
themselves are never saved. Feedback has its own 100-record Upstash capacity,
separate from formal cases. The public endpoint accepts at most five reports
per client per hour; it has no public read route. Set
`CASE_FEEDBACK_WORKSPACE` only if the derived feedback namespace must differ
from the default; changing it selects different feedback data. Local SQLite
uses a sibling `.feedback` database. Include that file in backups.
For content or original EML, users may separately opt into **private detection
evaluation**. This requires retaining original input; private review consent alone
does not grant evaluation use. Existing reports remain ineligible. Evaluation
consent does not retrain the model or send content to TypeSafe.
Feedback closure now requires a structured review reason, evidence basis and
explanatory note in the existing case history. A definite verdict based only on the reporter's claim
is rejected. Select **Retained message** only when the original input was saved;
otherwise use external verification or close as **Uncertain**. Existing closed
feedback without these fields remains readable, but is excluded from new
evaluation drafts until it is reopened and reviewed again.

1. Open a case and inspect detection evidence, warnings and saved message text.
2. Set **In progress**, choose a human verdict and explain it in a note.
3. Set **Closed** after review. A verdict is mandatory for closure.
4. Reopen to **In progress** if new evidence arrives. Every change records the
   authenticated analyst and server time; original detection evidence is unchanged.
5. On a conflict, copy your unsaved note, reload, and review the latest version.
   On a storage timeout, reload before deciding whether an operation needs retrying.

## Vercel setup

Use the existing private Upstash database with eviction **disabled**. In Vercel
project environment settings, configure these **Production-only** variables:

| Variable | Value |
| --- | --- |
| `CASE_STORE` | `upstash` |
| `CASE_WORKSPACE` | `production-cases` (stable; changing this selects different data) |
| `CASE_ANALYST_TOKEN_HASHES` | JSON map from analyst ID to lowercase SHA-256 token hash |
| `CASE_MANAGEMENT_ENABLED` | `true`, after the other variables are ready |

`CASE_REDIS_REST_URL` / `CASE_REDIS_REST_TOKEN` may point at a dedicated database.
If omitted, the existing `UPSTASH_REDIS_REST_URL` / `UPSTASH_REDIS_REST_TOKEN` are
used. Secrets must remain in Vercel settings, never in `vercel.json` or Git.
Invalid enabled configuration disables every case API with HTTP 503 while the
independent public analyzer remains available. No unprotected case data is exposed. Set `CASE_MANAGEMENT_ENABLED=false` to disable this feature.
Environment changes apply to a new deployment, not an existing one.

Run `python website/manage_case_access.py` in your own interactive terminal for
each analyst. Choose `y` at the existing-token prompt if you already saved one;
the hidden prompt regenerates its hash without changing that token. First paste
the current JSON at the hidden prompt so the helper can preserve every analyst.
It refuses to replace an existing analyst unless you explicitly type `ROTATE`;
rotation revokes that analyst's old token on new deployments. Copy the final
complete JSON line into Vercel, not the token or an individual hash. Save generated
tokens in a password manager and deliver them privately. The helper refuses
redirected output. Do not send raw tokens in chat. Browser refresh signs out;
tokens are not saved in localStorage or cookies. Refreshing the browser requires
the same token again, while an unchanged Production hash remains valid across code
releases.

Vercel Secret values cannot be read back after saving. If the old JSON was not
kept and **exactly one analyst** should retain access, run
`python website/manage_case_access.py --recover-single-analyst` in your own
terminal. It asks for the saved token through a hidden prompt and emits a complete
one-analyst JSON map. Replacing Production with that map revokes every other
analyst token on the next deployment. Never use this recovery mode for a team.
After redeploying, run `python website/tools/verify_case_login.py` in your own
terminal. It sends the hidden token only to the fixed Production `/api/cases/me`
endpoint, reports the analyst ID or a safe error, and does not print the token.
The automatic deployment smoke also requires anonymous `/api/cases/me` to return
401; this confirms the access boundary, **not** that a particular saved token
matches the current Secret. A positive check still requires a token holder.

Preview needs its own workspace and own analyst credentials. Leaving it disabled
is the default. Configure credentials in the intended Vercel project and scope;
another project connected to the same GitHub repository has separate environment
variables. Bookmark the stable Production address above and do not use a Preview
or project-specific deployment URL for normal analyst work. Deployment URLs retain
their original configuration: revoking a
token for a new deployment does not revoke it on older deployments. Protect or
remove outdated deployments through Vercel as part of revocation, and verify an
old token returns 401 on every retained accessible deployment.

## Storage, limits and responsibility

This is a single-organization team pilot: 100 cases and 100 feedback reports,
200 normal history events per record and a 750 KB encoded case limit. It has no
automatic expiry/deletion, mailbox actions, SSO,
roles, tenant isolation, or guaranteed provider SLA. A full workspace requires an
administrator-managed archive/export/migration before accepting more cases.
Provider plan limits can reject writes earlier; failures never claim success.

History limits are shared by SQLite and Upstash. An open case reserves two
entries while pending (start and close), or one while in progress (close).
Ordinary notes and auxiliary opinions cannot consume those reserved entries.
The detail panel shows remaining history slots and bytes and disables actions that no
longer fit. Existing full records can use at most two additional entries, up to
202 total, only to advance pending → in progress → closed. Those recovery slots
cannot be used for notes, opinions or reopening. Full closed cases require a
new follow-up investigation. Existing history is never truncated or deleted.
Byte reservations use 50 KB per remaining workflow step: pending records reserve
100 KB, and in-progress records reserve 50 KB. This includes a full 4,000-character
note even when non-BMP characters require 12 bytes each in escaped JSON. New
records and ordinary notes/opinions cannot consume these reservations.
Older records that already used this space may advance only through start/close,
with the same per-step reservation inside a hard 850 KB recovery ceiling. They
cannot use recovery space for ordinary notes, auxiliary opinions or reopening.
Archives and local restore accept the bounded 202-entry, 850 KB recovery history.
Existing records are not rewritten. The UI shows exact encoded storage use;
the submitted note and event are checked again within the transaction or before
the atomic cloud compare-and-set operation.

## Feedback overview and review filters

The authenticated `GET /api/cases/feedback-overview` returns counts only, without
message text, titles, analyst identities or notes. The overview covers all
retained feedback, independently of queue filters: pending/in-progress reports,
closed reports, confirmed false alerts and confirmed missed threats. A confirmed
finding requires a closed record with the matching human verdict and structured
reason, plus external verification or a consented retained-message evidence basis.
New closures require consistent choices: false alert → legitimate, missed threat
→ phishing, and insufficient evidence → uncertain. Other reasons do not prescribe
a verdict. In-progress reviews may keep provisional choices until closure.
Uncertain, reopened, reporter-only and inconsistent reviews do not contribute to
confirmed counts. Duplicate reports can still be counted separately. These are
reviewed-report counts, not overall model false-positive or false-negative rates.
Unavailable storage is shown as unknown, never zero. Refresh retries the read.

The queue accepts `verdict=phishing|legitimate|uncertain`. When `kind=feedback`,
`feedback_reason` accepts the existing structured review reasons. Filters use the
latest review-field changes and apply before totals and pagination. Redis reads
project compact review metadata from existing records without changing indexes
or retaining new copies of message text. SQLite uses the same review semantics.

## Workspace capacity and backups

The workspace displays unfiltered case and feedback counts separately, refreshes
them with the queue, and warns at 80% of each cloud limit or when full. Counts
include closed records: closing a case does not free a slot. The authenticated,
read-only `GET /api/cases/capacity` endpoint returns each store independently;
an unavailable count is never presented as zero and does not prevent loading
the queue. SQLite reports the actual count with `limit: null` because it has no
application count cap; that does not imply unlimited disk space. The display is
advisory: another writer can consume capacity after it is read. Existing atomic
write limits remain authoritative. Only an administrator should remove records
after making and verifying a private archive through the workflow below.

The current free database has no enabled paid encryption-at-rest or backup/SLA
package. HTTPS protects transport, and application authentication controls case
access. Before retaining sensitive company mail, choose and verify the required
storage encryption, backup/recovery, retention and access policies. Do not enable
eviction to solve capacity issues: it can erase the entire workspace hash.

Before production use, run and schedule backups for the dedicated
`phishguard:cases:v1:<workspace>` and derived feedback hashes. The following
read-only export captures both namespaces, including idempotency indexes. Supply
the Upstash REST URL and standard token through the local process environment;
never put them in command arguments, chat, Git, or a shell transcript. Save the
archive on encrypted private storage **outside this repository**:

```sh
.venv/bin/python website/tools/case_archive.py export \
  --case-workspace production-cases \
  --output /absolute/private/path/cases-archive.json
.venv/bin/python website/tools/case_archive.py verify \
  --archive /absolute/private/path/cases-archive.json
.venv/bin/python website/tools/case_archive.py restore-local \
  --archive /absolute/private/path/cases-archive.json \
  --output-dir /absolute/private/path/restore-check
```

Pass `--feedback-workspace` if Production overrides the derived name. Files are
created with owner-only permissions and are never overwritten. The local recovery
drill builds separate case and feedback SQLite databases and compares every
restored record. The original request keys cannot be recovered from their Redis
hashes, so these local copies verify record recovery rather than original
idempotent retry behavior. Export checks index consistency, but Upstash scans
are not an atomic snapshot; pause case and feedback writes during export and retry if it
reports a change. The SHA-256 in the archive detects accidental corruption, not
malicious replacement. The local drill does **not** restore the production Redis
database. Test an Upstash restore separately in an isolated database before
claiming cloud disaster recovery; native whole-database import can replace the
target database and must not be run against the shared Production database.
There is still no automatic expiry or deletion schedule. Set a retention policy
for your organization before removing real records. To inspect closed records
last updated before a cutoff, use a freshly verified private archive:

```sh
.venv/bin/python website/tools/case_retention.py \
  --archive /absolute/private/path/cases-archive.json \
  --kind feedback --before 2026-01-01
```

For a single eligible record, add `--record-id <UUID>` and
`--case-workspace production-cases`; if configured, also add
`--feedback-workspace <name>`. The tool
requires an interactive `DELETE <UUID>` confirmation, compares the archived
record, summary and creation index to current Upstash values inside one atomic
Lua operation, deletes exactly those three fields, then checks they are absent.
It never purges open or recently updated records. If the connection fails after
the mutation, inspect the cloud record before any retry. The private archive,
evaluation drafts and other copies still retain the deleted content; apply the
chosen retention policy to each copy separately. These controls were tested with
synthetic stores; no Production record has been deleted by this workflow.
Database administrators can alter records directly; application history is not
an externally immutable audit trail.

## Local development and verification

Set `CASE_STORE=sqlite`, an absolute private `CASE_DB_PATH`, token hashes and
enablement on a persistent local host. Never place the DB in served static files.
SQLite is rejected when `VERCEL` is set. Local SQLite does not validate the cloud
adapter; cloud REST transport and Lua tests are separate gates.

```
python -m unittest discover -s website/tests -v
node --test website/static/*.test.mjs
python website/tests/vercel_runtime_smoke.py
python website/tests/case_cloud_cli_smoke.py
```

The last command only prints a Redis CLI command. Execute it in the selected
provider console to test the actual Lua scripts; expected `CASE_LUA_SMOKE_OK`.
It creates only synthetic records under a unique one-hour namespace. For end-to-end
Vercel validation, use an individual test analyst and synthetic mail, verify
creation/reload across invocations, second-analyst review, stale-version rejection,
closure/reopening and unauthenticated denial. Keep test data out of real cases.

## Visual evidence

Email/image uploads up to 2 MiB run QR and English/Simplified Chinese OCR in the
browser (four images maximum). **Image text language (OCR)** defaults to English;
select Simplified Chinese or English + Chinese when appropriate. Changing it
cancels recognition and discards any pending creation payload, so the next submit
uses the new selection. It does not change QR decoding or original EML text.
The server recomputes risk from extracted strings.
Drop a local screenshot or EML onto the upload area, or focus the area and paste
an image with Ctrl/Cmd+V. The file picker remains available. Only one nonempty
file up to 2 MiB is accepted; dropped links are not fetched. Selecting, dropping
or pasting does not create a case: click **Analyze & create case** to submit.
The **Image & QR evidence** section shows payloads, OCR text/confidence, statuses
and warnings; all links remain plain text. Original EML bytes remain authoritative
for headers/body. Recognition cannot lower risk from the original message.

Client extraction is marked `browser_extracted_unverified`: the server has not
independently verified pixels or OCR output, and an image digest is not proof of
correct recognition. Saved cases include extracted text and provenance, never
original image attachments. For visual submissions, saved HTML bodies are converted
to visible text and inline image data URIs are removed after analysis. Original
EML bytes are sent to the server for message parsing but are not retained.
OCR/QR does not certify image safety or inspect malware,
all animation frames or remote images. Review limitations before closing a case.
Refreshing/signing out clears the current scan and token. Retrying a failed save
uses the same idempotency key and recognized evidence until the input changes.
