# Phishing Detector Optimization Design

## Goal

Improve phishing detection reliability without making the public demo depend on network access or expensive model training at startup. The detector must treat uploaded email headers and domains as attacker-controlled input, preserve rules-only availability, and make its reported risk evidence auditable.

## Scope

This change implements the approved priority-fix approach:

1. Establish a trust boundary for `Authentication-Results` headers.
2. Detect protected-brand impersonation through display names, IDN/Punycode domains, and common Unicode confusables.
3. Prevent local SMTP verification from connecting to private or special-purpose network addresses.
4. Make rate limiting resistant to spoofed forwarding headers and unbounded bucket growth.
5. Remove the nonfunctional legacy `/api/predict` surface and its unused startup model state.
6. Make content-model training an explicit offline operation; web startup loads only a verified artifact and otherwise uses rules.
7. Strengthen evaluation grouping and add adversarial regression tests for the above behaviors.

A distributed rate limiter, full malware sandbox, archive extraction, OCR/QR scanning, complete Public Suffix List integration, major UI redesign, and a full decomposition of `app.py` are out of scope for this pass.

## Architecture and Components

### Authentication trust boundary

Runtime configuration will expose a comma-separated list of trusted authentication service identifiers. Raw-message parsing will examine each `Authentication-Results` header separately, extract its leading service identifier, and use SPF, DKIM, or DMARC outcomes for scoring only when that identifier is explicitly trusted.

Untrusted results may be returned as unverified claims for transparency, but neither a pass nor a failure from an untrusted header may suppress or increase risk. A trusted DMARC pass may suppress isolated forwarding-related SPF failure as before. The default trusted list is empty because the application cannot infer which receiving system created an uploaded message.

### Brand and internationalized-domain identity checks

Sender parsing will compare protected brand names in the display name with the organizational identity of the address domain. A small, explicit registry will map supported brands to canonical domains and aliases. Domains will be IDNA-decoded and normalized; a conservative confusable skeleton will cover common Latin-lookalike Cyrillic and Greek characters.

The detector will add an identity-mismatch indicator when a protected brand is presented from an unrelated domain, including generic mailbox providers. It will also flag a domain whose decoded or confusable form resembles a protected brand while using a noncanonical domain. The logic will avoid treating arbitrary display names as brands and will include negative controls for legitimate canonical domains.

### SMTP network boundary

Before an SMTP probe, the verifier will resolve candidate MX addresses and reject loopback, private, link-local, multicast, reserved, unspecified, and otherwise non-global IPv4 or IPv6 results. The probe will connect to a validated numeric address rather than resolving the user-controlled hostname again, closing the DNS-rebinding gap between validation and connection.

If no public address remains, verification will report the mailbox as unverifiable without opening a socket. Existing public-service gating remains in place, so SMTP verification is still local-only and explicitly enabled.

### Rate limiting

Application middleware will derive its key from the framework-provided peer address and will no longer parse `X-Forwarded-For` itself. Deployments that need proxy-aware client addresses must configure the ASGI server's trusted-proxy support.

The in-memory bucket store will have a hard capacity. Stale empty buckets are removed first; if capacity is still reached, the least recently active bucket is evicted before a new key is accepted. This preserves bounded memory while retaining the existing single-process demo behavior.

### Model lifecycle and legacy endpoint

`CONTENT_MODEL_ENABLED` will default to false. When enabled, startup will require an explicit artifact path and SHA-256 digest, verify the digest before deserialization, validate artifact schema and runtime metadata, and load it without downloading data or fitting models. Any artifact error will leave the rules detector available and expose a degraded model state through health/config output.

Training and dataset downloads remain available only through an explicit offline command. The command will build the current pipeline, write a versioned artifact, and print its digest for deployment configuration. Artifacts are trusted build outputs, not user uploads.

The permanently unavailable `/api/predict` route and its unused UCI model globals/training path will be removed. The historical benchmark may remain documented, but it will not be represented as a live email-classification API.

### Evaluation safeguards

Corpus grouping will normalize whitespace, case, URLs, email addresses, and volatile numeric tokens before hashing fallback message families. URL campaign grouping remains preferred where an authoritative campaign URL exists. Metrics will state the grouping policy and report per-source sample counts so users can distinguish synthetic and observed corpora.

This pass does not claim that grouped public-corpus metrics measure production performance. Documentation will continue to require a time-separated, organization-representative holdout before deployment decisions.

## Data Flow

1. Startup validates runtime configuration and initializes the rules detector.
2. If content ML is enabled, startup verifies and loads the configured offline artifact; it performs no training or downloading.
3. Raw email analysis parses sender identity and authentication headers as untrusted input.
4. Only authentication results from configured service identifiers influence risk.
5. Brand/domain findings, structural evidence, content rules, and optional ML evidence remain separately visible before verdict fusion.
6. Local email verification resolves MX targets, filters them to public addresses, and connects only to an already validated numeric address.

## Error Handling and Compatibility

- Missing or invalid trusted-service configuration results in no authentication header being trusted.
- Invalid IDNA input is analyzed conservatively and never crashes the request.
- A missing, mismatched, incompatible, or corrupt model artifact produces rules-only degraded operation rather than process failure.
- A blocked MX address produces an `unverifiable` result with no socket connection.
- Removing `/api/predict` is an intentional API cleanup because the current route always returns 503 and is not used by the frontend.
- Existing `/api/analyze`, `/api/analyze-content`, `/api/verify-email`, public config, and health response shapes remain compatible except for additive diagnostic fields.

## Test Strategy

Implementation will use red-green-refactor cycles. Each behavior will first receive a focused failing test and a positive or negative control:

- forged `Authentication-Results` cannot create trusted DMARC status;
- configured trusted service results are honored;
- PayPal, Microsoft, Apple, Punycode, and Unicode-confusable impersonation is detected while canonical senders remain clean;
- private, loopback, link-local, and mixed public/private MX answers never reach SMTP;
- a spoofed `X-Forwarded-For` value cannot change the application-level rate-limit key;
- the bucket store remains within its hard bound;
- web startup never calls dataset download or model fitting;
- valid artifact digest loads, while invalid digest or metadata degrades safely;
- the legacy route is absent;
- near-duplicate fallback messages receive the same evaluation group.

Final verification will run the focused tests, the complete Python suite, frontend tests and syntax checks, Python compilation, `git diff --check`, and direct attack controls for forged authentication, display-name/IDN impersonation, and private MX targets.

## Acceptance Criteria

- Attacker-supplied authentication headers cannot lower or raise risk unless their service identifier is configured as trusted.
- Protected-brand display-name and IDN/confusable impersonation examples produce visible risk indicators.
- SMTP verification cannot open connections to non-global addresses, including through DNS rebinding after validation.
- Rate-limit storage is bounded and does not trust raw forwarding headers.
- Default web startup performs no dataset download or model training and remains usable without an artifact.
- The dead legacy prediction endpoint is no longer exposed.
- All pre-existing relevant tests and all new adversarial tests pass.
- Existing unrelated working-tree changes remain preserved.
