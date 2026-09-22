# Case workspace operations

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
the hidden prompt regenerates its hash without changing that token. Copy the
ENTIRE JSON line (including braces and double quotes) into Vercel, not the token
or the hash alone. Save the generated token in a password manager and deliver it
privately to that analyst. Merge the generated hash into the JSON map, preserving
other analysts. The helper refuses redirected output. Do not send raw tokens in
chat. Browser refresh signs out; tokens are not saved in localStorage or cookies.

Preview needs its own workspace and own analyst credentials. Leaving it disabled
is the default. Deployment URLs retain their original configuration: revoking a
token for a new deployment does not revoke it on older deployments. Protect or
remove outdated deployments through Vercel as part of revocation, and verify an
old token returns 401 on every retained accessible deployment.

## Storage, limits and responsibility

This is a single-organization team pilot: 100 cases and 100 feedback reports,
200 events per record, 750 KB
encoded case limit. It has no automatic expiry/deletion, mailbox actions, SSO,
roles, tenant isolation, or guaranteed provider SLA. A full workspace requires an
administrator-managed archive/export/migration before accepting more cases.
Provider plan limits can reject writes earlier; failures never claim success.

The current free database has no enabled paid encryption-at-rest or backup/SLA
package. HTTPS protects transport, and application authentication controls case
access. Before retaining sensitive company mail, choose and verify the required
storage encryption, backup/recovery, retention and access policies. Do not enable
eviction to solve capacity issues: it can erase the entire workspace hash.

Before production use, establish a backup procedure for the dedicated
`phishguard:cases:v1:<workspace>` and derived feedback hashes and test
restoration to separate namespaces.
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
