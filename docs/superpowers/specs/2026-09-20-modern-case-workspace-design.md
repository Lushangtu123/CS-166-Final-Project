# Modern case workspace

## Approved direction

Use a dark security operations interface with graphite-green surfaces and mint actions. The user approved the recommended direction on 2026-09-20. Preserve the existing authentication, case lifecycle, persistence and API contracts.

## Interface

- Persistent desktop navigation for the case workspace and email analyzer; compact navigation on phones.
- Compact page header and collapsed new-case form so investigations have priority.
- Case queue with text-labelled risk badges, status, verdict, timestamp and an explicit selected state. Filters remain available in a native disclosure.
- Detail sections for detection evidence, human assessment and an activity timeline. Saved message text and provenance remain separate disclosures.
- Purposeful signed-out and empty states. No invented activity counts or detection statistics.
- Desktop queue/detail columns become stacked sections below 960px; navigation becomes a horizontal block below 640px.

## Implementation boundaries

Use the existing static HTML/CSS/JavaScript with local font fallbacks and no new dependencies or external assets. Preserve element IDs, text-only evidence rendering, no-store responses, strict CSP, memory-only tokens, stale-response guards and idempotency handling. Add allowlisted risk styling and keep selected-row accessibility state synchronized with the loaded case and queue refresh.

## Verification

Run frontend tests and JavaScript syntax checks. Inspect the actual local application at desktop and mobile widths with synthetic records, checking login, queue selection, filtering, case creation and review persistence. Check for horizontal overflow at small widths and ensure logout clears case evidence. Production publishing is a separate step.
