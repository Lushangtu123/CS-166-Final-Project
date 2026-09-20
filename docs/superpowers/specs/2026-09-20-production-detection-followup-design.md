# Production Detection Follow-up Design

## Objective

Harden the deployed detector after the sender-history release without weakening
phishing recall or presenting synthetic evaluation as real Gmail/Outlook
evidence. This pass fixes the Vercel request-identity boundary, makes sender
alias history more accurate, makes deployment readiness checks tolerate alias
propagation, and gives users an explicit server-side processing notice.

## Scope

This change will:

1. derive Vercel rate-limit identities from the platform-overwritten public
   client-IP header while retaining the ASGI peer address everywhere else;
2. canonicalize plus tags only for explicitly supported mailbox providers;
3. wait for the production alias to expose the expected model before running
   stateful post-deploy controls;
4. distinguish configured sender history from live verification in public
   health/config output without breaking existing clients;
5. explain at the upload boundary that content is processed server-side and
   that only a pseudonymous sender observation may be retained;
6. add regression tests for each changed boundary.

This change will not:

- infer Gmail or Outlook account age, lifetime, ownership, or intent;
- change the content-model threshold from a handcrafted example;
- claim that synthetic hard negatives measure production accuracy;
- add QR, OCR, archive extraction, or attachment execution to the Vercel
  runtime;
- collect, commit, or generate purportedly real inbox messages.

## Considered Approaches

### Recommended: deployment-aware trust and bounded readiness polling

Use the Vercel deployment profile as the trust switch. In that profile only,
accept Vercel's overwritten `X-Forwarded-For` value after strict single-IP
validation; otherwise use `request.client.host`. Poll only the read-only
health/config readiness boundary before running the existing prediction and
sender-history controls. This resolves the identified production risks with
small, testable changes.

### Alternative: trust forwarding headers on every deployment

This is simpler, but unsafe on local or self-hosted installations where a
caller can supply the header directly. It is rejected.

### Alternative: retry the entire smoke test

This handles alias propagation but repeats prediction requests and creates
additional sender-history records. It can also consume the ten-request public
quota during one deployment. It is rejected in favor of readiness-only polling.

## Design

### Trusted client identity

Add a small request-identity helper in `website/app.py`.

- When `PHISHGUARD_DEPLOYMENT_PROFILE=vercel-free`, read
  `X-Forwarded-For`, require exactly one syntactically valid IPv4 or IPv6
  address, and use it as the rate-limit identity.
- If the trusted header is absent or invalid, fall back to the ASGI peer.
- On every other deployment profile, ignore forwarding headers and use the
  ASGI peer exactly as today.
- Continue appending the API path so each endpoint retains an independent
  quota.
- Continue HMAC-pseudonymizing the identity before it reaches Upstash.

Tests must prove that a caller-supplied forwarding header is ignored outside
the Vercel profile, that two Vercel client IPs produce distinct keys even with
the same ASGI peer, and that malformed or multi-value input falls back safely.

### Provider-aware sender canonicalization

Create one shared set of mailbox domains for which this application explicitly
supports plus-address canonicalization. The initial set is limited to the
Gmail and Microsoft consumer domains already covered by the product:
`gmail.com`, `googlemail.com`, `outlook.com`, `hotmail.com`, and `live.com`.

Gmail dot normalization remains limited to Gmail-compatible domains. For every
other domain, a `+` remains part of the local address because the application
cannot assume that the provider implements subaddressing. Sender heuristics and
sender-history HMAC identity must use the same policy.

Tests must prove equivalence for supported providers and separation for custom
domains such as `alice+sales@example.com` and `alice@example.com`.

### Deployment readiness polling

Separate read-only readiness from stateful smoke controls.

- Before the existing validation, poll `/health` for the expected model digest
  and `/api/config` for the required deployment flags.
- Retry only readiness failures that can result from alias propagation or a
  transient HTTP/network response.
- Use a bounded default attempt count and delay suitable for GitHub Actions.
- After readiness succeeds, execute the phishing control, legitimate controls,
  and two sender-history observations exactly once.
- Keep the existing redirect-host and JSON-content validation.

The retry helper will accept an injected sleep function in unit tests so tests
do not wait in real time. A failed final attempt must preserve the actionable
error.

### Health semantics

Keep `sender_history_enabled` and the existing
`sender_history_available` compatibility field. Add
`sender_history_configured`, which explicitly means that configuration passed
validation. Documentation will state that neither configuration field proves
continuous Upstash reachability; the post-deploy first/previous probe is the
live integration check.

This avoids a breaking response change while removing the misleading
interpretation of `available`.

### User privacy notice

Place a concise notice next to full-message upload and manual content input:

- analysis occurs on the server;
- the application does not retain message body or attachment content;
- when sender history is enabled, a pseudonymous sender observation may be
  retained for the configured period;
- users should remove unrelated personal content before submitting messages
  they do not have authority to process.

The notice must be static text, readable by assistive technology, and covered
by the frontend regression test.

## Model Quality Follow-up

The observed short legitimate-invoice false positive and unsupported Chinese
gift-card lure remain measured gaps, not silently fixed claims. The next model
artifact may be changed only after a versioned evaluation set contains broader
real legitimate transactional mail and multilingual phishing examples. That
evaluation must report per-language/provider recall and false-positive rate and
must keep a strictly later lockbox unavailable to threshold selection.

QR/OCR and attachment-content inspection require a separate resource and threat
model because decoding attacker-controlled images changes dependency size,
memory, CPU, and parser risk on Vercel's free runtime.

## Verification

Implementation follows red-green-refactor for each behavior. Final validation
will run:

1. focused request-limit, sender-history, post-deploy, configuration, and
   frontend tests;
2. the complete backend and frontend suites;
3. the Vercel runtime smoke test;
4. Python compilation, JavaScript syntax checking, and `git diff --check`;
5. a final diff review confirming no model artifact, dataset, secret, or
   unrelated file changed.

## Acceptance Criteria

- Two public Vercel users do not share a distributed rate-limit identity merely
  because the function sees the same proxy peer.
- Forwarding headers cannot change the identity on non-Vercel deployments.
- Supported Gmail/Microsoft plus aliases share sender history; arbitrary custom
  domain mailboxes do not.
- Alias propagation can recover without repeating stateful smoke requests.
- Health/config output distinguishes configuration from live integration
  verification without removing existing fields.
- The UI accurately explains server-side processing and pseudonymous history.
- All repository checks pass and the working tree contains only intended
  changes.
