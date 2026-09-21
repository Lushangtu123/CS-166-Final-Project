# Case workspace operations

Open `/cases` and sign in with your individual analyst token. Create a case from
subject/body or an original `.eml` file. Creation saves extracted text and detection
evidence; the public analyzer does not automatically create cases. Everyone
configured for this workspace can read and review its cases.

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

This is a single-organization team pilot: 100 cases, 200 events per case, 750 KB
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
`phishguard:cases:v1:<workspace>` hash and test restoration to a separate namespace.
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
