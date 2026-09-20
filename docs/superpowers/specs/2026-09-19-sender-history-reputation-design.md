# Privacy-Preserving Sender History Design

## Objective

Add service-retained sender history so the application can distinguish a
Gmail or Outlook sender that this service has never observed from one it
has observed repeatedly. The history is context only: it must not claim to
know an account's provider-side creation date, intended lifetime, ownership,
or legitimacy.

The feature must run on Vercel's serverless runtime with Upstash Redis's free
plan, preserve the existing stateless detector when storage is absent or
unavailable, and avoid storing email addresses or message content.

## Scope

This change will:

- add an optional Upstash REST-backed sender-history service;
- pseudonymize canonical sender addresses with HMAC-SHA256 before storage;
- record history only when a complete raw email is analyzed;
- expose bounded history and account-observability fields in raw-email results;
- distinguish provider-account observability from disposable-provider status;
- render the new information as neutral context in the web interface;
- use the same opaque-key Upstash boundary for a distributed public-API limit;
- add configuration, privacy, unit, integration, and frontend regression tests;
- document Vercel/Upstash setup and behavior when storage is unavailable.

This change will not:

- query Google or Microsoft for account creation dates;
- store raw addresses, subjects, bodies, headers, links, recipients, IPs, or
  attachment contents in Redis;
- treat first-seen, frequently seen, Gmail, Outlook, disposable-provider, or
  privacy-relay status as proof of phishing or safety;
- add user accounts, shared allowlists, blocking, or automatic model training;
- collect user feedback or retain samples for a future dataset.

## Selected Architecture

### Storage adapter

Create a focused `website/sender_history.py` module with a small interface and
two implementations:

- `DisabledSenderHistoryStore` returns a disabled result without network
  access. It is selected when required configuration is absent.
- `UpstashSenderHistoryStore` uses the Upstash Redis REST endpoint over HTTPS.

The adapter is initialized once during application startup. It does not expose
the Redis token, HMAC secret, raw Redis response, or internal key in API output
or logs.

The Upstash implementation uses a single server-side atomic operation per
observation. The operation initializes `first_seen`, updates `last_seen`,
increments `seen_count`, and refreshes the key's expiration. A read-only lookup
must not change the record. Atomic updates preserve the minimum first-seen and
maximum last-seen timestamps so concurrent requests cannot invert their order.

### Configuration

The service is enabled only when all of these environment variables are set:

- `SENDER_HISTORY_ENABLED=true`
- `UPSTASH_REDIS_REST_URL=https://...upstash.io`
- `UPSTASH_REDIS_REST_TOKEN=<secret>`
- `SENDER_HISTORY_HMAC_KEY=<random secret with at least 32 bytes of entropy>`

Optional settings:

- `SENDER_HISTORY_RETENTION_DAYS`, default `90`, constrained to `1..365`;
- `SENDER_HISTORY_TIMEOUT_SECONDS`, default `1.0`, constrained to `0.1..3.0`.

Credentials and the HMAC key are configured in Vercel environment variables,
never in `vercel.json`, source control, client JavaScript, or API responses.
Invalid partial configuration disables history and reports a sanitized startup
configuration error through health metadata.

### Address canonicalization and privacy

The history identity is derived from the normalized mailbox already accepted by
the sender parser, including IDNA domains and trailing-root-dot normalization.
Gmail dots and plus-address tags follow the application's
existing canonicalization rules; non-Gmail plus-address tags are removed only
where the existing detector already classifies them as subaddresses.

The Redis identifier is:

`sender-history:v1:<HMAC-SHA256(secret, canonical-address)>`

HMAC prevents a leaked Redis key set from being directly reversed with a simple
dictionary of common email addresses. Key rotation deliberately starts a new
history namespace. The record contains only integer timestamps and a bounded
counter. A 90-day TTL limits retention.

This is pseudonymization, not anonymization. Documentation must state that the
deployment operator remains responsible for its privacy notice and applicable
retention obligations.

## Data Flow

### Sender-only analysis

`POST /api/analyze-email` continues to analyze the address without recording or
looking up an observation. It returns `raw_message_required` so an anonymous
caller cannot use the address form as an arbitrary service-history lookup.

### Raw-email analysis

After the outer raw message parser has produced at least one valid `From`
mailbox:

1. Canonicalize and locally analyze each unique sender mailbox.
2. Select the highest-risk sender that drives the returned sender result.
3. Record one observation for only that selected canonical sender, bounding the
   external history work to one request per message even with ambiguous headers.
4. Attach the relevant history context to that sender's analysis.
5. Continue content, link, structure, authentication, and attachment analysis
   independently of storage success.

Repeated appearances of the same address inside one message count once. An
invalid or missing outer `From` header does not create a record. Encapsulated
messages still contribute risk evidence but do not access sender history.

### Returned contract

Sender analysis gains these fields:

```json
{
  "account_observability": "provider_account_unverifiable",
  "sender_history_status": "first_seen",
  "sender_history_scope": "this_service_history"
}
```

`account_observability` values:

- `provider_account_unverifiable`: Gmail, Outlook, Hotmail, iCloud, Yahoo, or
  another configured major provider whose provider-side age is unavailable;
- `not_applicable`: confirmed disposable-provider and privacy-relay categories;
- `unknown`: other domains.

`sender_history_status` values:

- `first_seen`: the atomic observation created the record;
- `previously_seen`: the service observed the sender before;
- `raw_message_required`: address-only analysis intentionally skipped history;
- `disabled`: history was intentionally not configured;
- `unavailable`: configured storage failed or timed out;

When no valid sender mailbox is available, raw-message output omits
`sender_analysis` and no history request is made.

Exact observation timestamps and counts remain internal to the store and are
not returned by the public API. The coarse status describes only observations
submitted to this service, not provider-side account activity.

## Risk Semantics and User Interface

Sender history is neutral context and contributes zero risk points. It must
never reduce an existing score or suppress stronger evidence. In particular:

- `first_seen` is not labelled disposable, malicious, new at Google/Microsoft,
  or high risk;
- `previously_seen` is not labelled trusted or safe;
- random-looking Gmail/Outlook names retain the current
  `suspicious_mailbox_pattern` heuristic;
- known disposable domains remain `known_disposable_provider`;
- privacy relays remain `privacy_relay`;
- complete-message rules and the content model remain decisive when they find
  phishing evidence.

The frontend shows a separate **Sender history** row. Copy uses phrases such as
“First observed by this service” and “Observed previously by this service.”
Address-only analysis explains that a complete message is required. Disabled or
failed history does not show a misleading zero count.

## Failure and Abuse Handling

- Redis timeout, quota exhaustion, malformed responses, DNS failures, and 4xx or
  5xx responses fail open: email analysis continues and history is
  `unavailable`.
- The timeout is shorter than the request deadline and cannot consume the full
  analysis budget.
- Errors returned to users and health endpoints are sanitized and never contain
  tokens, HMAC material, full URLs, Redis keys, or raw addresses.
- HTTP redirects are rejected so the Upstash bearer token cannot leave the
  configured, validated `*.upstash.io` origin.
- Existing request-size and rate-limit controls remain in force.
- When Upstash is configured, POST requests also use a one-minute atomic
  HMAC-keyed distributed limit; only an opaque client/path identifier is stored.
  Storage failure falls back to the existing bounded in-process limit.
- History remains informational because a public caller can submit fabricated
  raw messages. It is not an authentication or reputation authority.
- A single raw message records only the selected highest-risk sender once,
  limiting count inflation and external-call amplification within one request.

## Upstash Free-Plan Budget

Each public POST uses one distributed-limit REST request when Upstash is ready.
A raw-message analysis that reaches the endpoint uses one additional sender-history
request and atomic Redis operation. The design stores only a few integers per
active pseudonymous sender or short-lived opaque rate-limit key and applies TTLs.

If the free command quota is exhausted, only sender history becomes unavailable;
the phishing detector remains operational. The application never upgrades a
database, adds a payment method, or changes an Upstash plan.

## Testing Strategy

Development follows red-green-refactor. Tests must first fail against the
existing implementation and then cover:

1. deterministic HMAC keys without exposing the input address;
2. canonical equivalence for Gmail dot and supported plus variants;
3. distinct keys for distinct canonical addresses and secrets;
4. configuration validation, including partial configuration and secret length;
5. atomic first/previous observation behavior and TTL refresh;
6. address-only sender analysis that does not query or increment history;
7. raw-email analysis recording only the selected canonical sender once;
8. no record for invalid or missing sender headers;
9. timeout, quota, malformed response, and network-error fail-open behavior;
10. neutral risk semantics for first-seen and previously-seen senders;
11. coexistence with random-mailbox, disposable-provider, privacy-relay,
    authentication, content-model, link, and brand-impersonation results;
12. frontend rendering and escaping for every history status;
13. health/config output that reports capability without exposing secrets;
14. Vercel runtime smoke behavior with history disabled by default.
15. post-deploy smoke behavior against the public alias, including first and
    repeated observations plus protected/non-JSON deployment responses.

Focused tests run before the full backend and frontend suites. Final validation
also includes Python compilation, JavaScript syntax, dependency consistency,
artifact verification, and `git diff --check`.

## Deployment Procedure

1. Create or connect one Upstash Redis free database through the Vercel
   Marketplace.
2. Confirm Vercel injected `UPSTASH_REDIS_REST_URL` and
   `UPSTASH_REDIS_REST_TOKEN` for the intended environments.
3. Generate a separate random `SENDER_HISTORY_HMAC_KEY` and add it as a secret.
4. Set `SENDER_HISTORY_ENABLED=true` only after all secrets are present.
5. Deploy first to Preview and verify fail-open behavior plus first/previous
   observation behavior.
6. Promote the verified revision to Production.

Local development and CI keep history disabled unless tests inject isolated
fake adapters. No test contacts a real Upstash database.

## Acceptance Criteria

- No raw email address or message data is persisted by the feature.
- A first raw-email observation returns `first_seen`; the next returns
  `previously_seen` with an incremented count.
- A sender-only query does not query, create, or increment history.
- Gmail/Outlook account age remains explicitly unverifiable.
- History never changes the phishing risk score or lowers a stronger verdict.
- Missing, invalid, slow, or exhausted storage never prevents analysis.
- Existing clients remain compatible with the retained status and scope fields;
  exact observation metadata is intentionally removed from the public contract.
- Public history output omits exact timestamps and counts.
- All focused and repository-wide checks pass.
