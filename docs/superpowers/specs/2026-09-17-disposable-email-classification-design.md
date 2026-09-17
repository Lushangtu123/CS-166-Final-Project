# Disposable Email Classification Design

## Goal

Make sender analysis accurately describe what it can and cannot determine about
temporary addresses. The detector must catch known disposable providers across
multi-label public suffixes, surface strongly randomized Gmail and Outlook
mailboxes as uncertain rather than confirmed disposable, and stop treating
privacy relays or innocent domain substrings as confirmed phishing evidence.

This change remains local and deterministic. It does not enable SMTP probing in
the public deployment, send addresses to third parties, or claim access to
provider account age or lifetime data.

## Scope

This pass will:

1. replace naive last-two-label disposable-domain lookup with normalized full
   domain and boundary-safe suffix matching;
2. introduce an explicit disposable classification contract;
3. distinguish known temporary providers, privacy relays, suspicious mailbox
   patterns, suspicious domain-name patterns, and no known match;
4. apply a stricter mailbox-randomness threshold to major providers such as
   Gmail and Outlook;
5. identify subaddressing without treating it as malicious;
6. remove duplicate disposable-evidence scoring;
7. correct the frontend's unsupported “not disposable” claim;
8. normalize, deduplicate, and validate the local provider registry; and
9. add positive and negative regression coverage for these boundaries.

External reputation APIs, account-tenure lookups, user/device reputation,
challenge emails, scheduled background data refresh, and automatic production
deployment are out of scope.

## Classification Contract

`POST /api/analyze-email` will keep its existing response fields and add:

- `disposable_status`, one of:
  - `known_disposable_provider`;
  - `privacy_relay`;
  - `suspicious_mailbox_pattern`;
  - `suspicious_domain_pattern`;
  - `no_known_match`;
- `disposable_confidence`, one of `confirmed`, `heuristic`, or `unknown`;
- `matched_provider_domain`, containing the normalized disposable or privacy
  relay registry entry when one exists;
- `address_alias_type`, set to `subaddress` when a `+tag` is present and
  otherwise `null`.

Compatibility fields will use corrected semantics:

- `is_disposable` is true only for `known_disposable_provider`;
- `is_suspected_disposable` is true for either suspicious-pattern status;
- `disposable_service` contains only a confirmed matched temporary-provider
  domain.

Privacy relays and subaddresses are informational. They do not set either
boolean and do not increase the phishing score by themselves. A matched privacy
relay is treated as a recognized provider so it does not also receive the
generic “unrecognized provider” indicator.

## Domain Classification

All input domains and registry entries will be lowercase and have a trailing
dot removed. A helper will match either an exact domain or a subdomain boundary:
`domain == candidate` or `domain.endswith("." + candidate)`. This makes
`10minutemail.co.uk`, `guerrillamail.co.uk`, and `relay.firefox.com` reachable
without assuming that every registrable domain consists of two labels.

The existing registry will be divided into:

- confirmed temporary/disposable providers; and
- explicit privacy relay providers, initially covering the clearly identified
  AnonAddy, SimpleLogin, Firefox Relay/Mozilla Relay, and Duck aliases already
  present in the repository.

Entries will be normalized and deduplicated at module load. A validation test
will reject mixed-case and malformed source entries. The UI may report the
matched canonical entry but must not claim that the individual inbox expires.

Substring matches such as `discard`, `lastmail`, or `jetable` will no longer be
confirmed disposable results. Pattern detection will use reviewed, anchored
regular expressions against one complete hostname label instead of an
unbounded `pattern in label` check. A match becomes
`suspicious_domain_pattern` with heuristic confidence and a medium explanatory
indicator. This prevents domains such as `discardrecords.com` and
`jetableconsulting.com` from receiving a confirmed label solely from a
substring.

## Mailbox Pattern Classification

The current six randomness factors remain the starting point, but their result
will be separated from provider identity:

- unknown domains: two or more factors produce
  `suspicious_mailbox_pattern`, preserving current sensitivity;
- known high-traffic providers: at least four factors are required;
- recognizable first-name/last-name and common-word patterns remain negative
  controls.

For a high-traffic provider, the explanation must say that the mailbox pattern
looks automatically generated while account age and disposability cannot be
confirmed. It must not call Gmail or Outlook itself disposable.

The local part used by all username-only heuristics will exclude a `+tag`. A
plus tag is reported as `address_alias_type: subaddress` and contributes no
phishing score. For consumer `gmail.com` addresses, the normalized comparison
form will remove dots, but dotted addresses remain ordinary provider addresses
and are never treated as separate temporary services.

## Scoring

Each disposable-related fact will contribute at most once:

- confirmed disposable provider: one high-severity indicator;
- suspicious mailbox pattern: one medium-severity indicator;
- suspicious domain pattern: one medium-severity indicator;
- privacy relay, subaddress, and no known match: informational only.

The separate `+25` and `+10` disposable bonuses will be removed from sender
score calculation because the corresponding indicators already contribute to
the score. Message content, authentication, link, and structural evidence keep
their existing weights and floors.

## Frontend Behavior

The disposable card will render classification fields rather than infer three
states from two booleans:

- confirmed provider: “Known disposable-email provider”;
- privacy relay: “Privacy relay / masked address”;
- suspicious mailbox: “Mailbox pattern is suspicious; lifetime unknown”;
- suspicious domain pattern: “Domain name resembles a disposable service; not
  confirmed”;
- no match: “No known disposable-provider match”.

The card will explicitly state that Gmail/Outlook account age and intent cannot
be determined from the address alone. Existing HTML escaping rules remain in
place for all server-provided text.

## Error Handling and Compatibility

- Empty or malformed addresses retain the existing format findings.
- Registry or normalization failures must degrade to `no_known_match`, not abort
  the endpoint.
- New fields are additive. Existing clients can continue using the old fields,
  with the corrected boolean meanings documented in the README.
- No network calls, secrets, new environment variables, or dependencies are
  required.
- The public Render profile remains rules-only and does not enable the existing
  local SMTP/WHOIS verification endpoint.

## Test Strategy

Implementation will follow red-green-refactor. Every behavior below must first
be observed failing against the current implementation.

Positive controls:

- `user@mailinator.com` is a confirmed disposable provider;
- `user@10minutemail.co.uk` and `user@guerrillamail.co.uk` are confirmed;
- a five-factor randomized Gmail or Outlook mailbox is suspicious but not
  confirmed disposable;
- `user+tag@outlook.com` reports subaddressing without a risk increase;
- a domain whose label clearly follows a temporary-mail naming pattern is a
  heuristic result, not confirmed.

Negative and classification controls:

- ordinary Gmail and Outlook addresses remain no-match/low risk;
- dotted Gmail addresses are not disposable;
- SimpleLogin, Duck, and Firefox Relay are privacy relays with no phishing
  contribution;
- `discardrecords.com`, `lastmailbox.com`, and `jetableconsulting.com` are not
  classified as confirmed disposable providers;
- registry entries are lowercase, unique, and syntactically plausible;
- frontend labels never claim “Not a Disposable Address”.

Final verification will run focused backend and frontend tests, the complete
backend and frontend suites, Python and JavaScript syntax checks, and
`git diff --check`.

## Acceptance Criteria

- The multi-label disposable-provider examples are detected as confirmed.
- Strongly randomized Gmail/Outlook examples are visible as heuristic
  uncertainty while ordinary controls remain low risk.
- Privacy relays and innocent substring collisions are not scored as confirmed
  disposable or high-risk solely because of their domain.
- No UI or API message claims knowledge of an individual mailbox's lifetime.
- Disposable evidence is not counted twice.
- Existing API fields remain present, all new behavior is regression-tested,
  and the public deployment requires no new external service.
