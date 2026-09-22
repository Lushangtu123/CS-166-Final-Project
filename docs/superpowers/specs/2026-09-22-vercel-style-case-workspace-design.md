# Vercel-inspired case workspace design

## Objective

Give the authenticated PhishGuard case workspace the clarity and density of a modern Vercel dashboard while retaining PhishGuard's own identity, security controls, data model, and deployment footprint.

The observable result is a responsive workspace where analysts can scan a table-like case queue, filter records, open an investigation in a stable detail pane, and create or review cases without losing context. The existing case API, token handling, OCR, Jev consent, review history, feedback records, automatic theme, and light/dark modes must continue to work.

## Approaches considered

### 1. Progressive native redesign — selected

Keep the current server-rendered HTML, CSS, and plain JavaScript. Recompose the page into a compact shell, toolbar, table-like queue, sticky investigation pane, and create-case drawer. Extend the current DOM rendering only where the richer layout needs structured columns.

This approach has the smallest operational risk, adds no dependencies, preserves the current content security policy, and fits the existing Vercel deployment.

### 2. Full single-page application rewrite

Rebuild the workspace with React or Vue and a component library. This could provide more reusable UI primitives, but it would add a build pipeline and dependency surface for one page, require a larger test rewrite, and increase deployment and maintenance risk without improving detection or case storage.

### 3. CSS-only visual reskin

Change only colors, spacing, and borders. This is the fastest option, but it leaves the current stacked disclosures and card-oriented queue intact, so it would not achieve the clearer dashboard hierarchy the user requested.

## Visual direction

The interface uses restrained enterprise minimalism inspired by Vercel's information density, neutral palette, precise borders, and compact controls. It does not copy Vercel logos, icons, product names, or exact page composition.

- Neutral gray surfaces with one PhishGuard signal color for focus and active state.
- Thin borders and restrained shadows instead of large decorative cards.
- Compact 48-pixel top navigation and a narrow project sidebar.
- A readable sans-serif UI stack and monospaced metadata for identifiers and timestamps.
- Light, dark, and system theme modes using the existing preference mechanism.
- Short opacity and transform transitions that respect `prefers-reduced-motion`.

## Authenticated workspace layout

### Application shell

The sidebar becomes a compact project navigation rail with the PhishGuard project identity, Cases and Analyzer links, workspace identity, signed-in analyst, and sign-out action. The top bar shows the Cases breadcrumb, connection state, theme switcher, and primary New case action.

The large marketing-style workspace heading is replaced after login by a concise page header with the queue title, record count, and one-line description. The login screen remains a focused standalone card and keeps the current token privacy explanation.

### Case queue

The queue is presented as a table-like list with explicit columns:

- Risk
- Case or feedback title
- Status
- Human verdict
- Created time

Rows remain keyboard-accessible buttons and preserve the current selected state. On narrow screens, secondary columns fold under the title instead of forcing horizontal scrolling.

The existing type, status, risk, and date filters move into a compact toolbar. Filtering remains server-backed through the current API. This redesign does not add partial client-side search, because searching only the loaded page could hide matches and mislead analysts.

Pagination remains explicit and reports the current page. Refresh stays available in the queue toolbar.

### Investigation pane

The selected case opens in a persistent right-hand detail pane on wide screens. Its header contains the case title, metadata, risk/status/verdict badges, and reload action. Detection evidence, optional Jev opinion, analyst review, and history retain their current order and security language.

The pane is sticky within the viewport on large screens. On smaller screens it becomes the next block below the queue. It never renders saved email HTML and continues to display all untrusted values as text.

### Create case drawer

New case becomes a native dialog presented as a right-side drawer on desktop and a full-height sheet on mobile. The existing form, drag/drop and paste flow, file limits, OCR language control, progress, cancellation, idempotency, and privacy language remain unchanged.

The dialog supports Escape and an explicit close button. It does not close while a submit is in flight unless the existing cancellation path has completed. After successful creation it closes and the newly created case remains selected in the investigation pane.

## State and behavior

The current JavaScript remains the state owner. New behavior is limited to:

- opening and closing the create-case dialog;
- rendering queue rows into defined visual columns;
- keeping the primary action and queue state synchronized;
- resetting the dialog safely on sign-out and successful creation.

Authentication tokens remain memory-only and are sent only through the Authorization header. No credentials, email source, or case data are placed in local storage, URLs, DOM data attributes, analytics, or logs.

## Responsive and accessibility behavior

- At desktop widths, sidebar, queue, and detail pane are visible together.
- At tablet widths, the sidebar becomes a compact top navigation and the queue/detail layout uses one column.
- At mobile widths, controls wrap, table columns collapse, and the create form becomes a full-screen sheet.
- Existing skip navigation, visible focus states, accessible labels, live status region, and button semantics remain.
- Dialog focus is constrained by the native `dialog` element and returns to the New case button when closed.
- Colors maintain readable contrast in both themes; risk is communicated by text as well as color.

## Error and empty states

The existing live notice remains the authoritative operation status. Authentication failures return to the login panel. Empty queues use a compact table empty state. A failed case load leaves the queue usable. Creation and review errors preserve analyst input, including the existing stale-review note protection.

## Implementation boundary

Expected files:

- `website/static/cases.html`: shell, toolbar, native dialog, and queue headings.
- `website/static/cases.css`: new tokens, responsive layout, table rows, detail pane, drawer, themes, and motion handling.
- `website/static/cases.js`: structured row rendering and dialog lifecycle.
- `website/static/cases.test.mjs`: dialog, selected-row, rendering, sign-out, and successful-creation behavior.
- `website/static/cases-theme.js` and its tests only if theme metadata needs updated colors.

The case API, Upstash schema, risk engine, and Jev contract remain unchanged.

## Verification

1. Run the focused Node tests for cases, theme, file intake, feedback, and vision UI.
2. Run the relevant Python case API and security tests to confirm the UI change did not require a contract change.
3. Serve the app locally and exercise login, filters, selection, create drawer, image/email intake, review, sign-out, and all three theme modes in a real browser.
4. Check desktop and mobile layouts, keyboard focus, reduced-motion behavior, and that no saved message HTML is rendered.
5. Inspect the final diff for dependency additions, credential exposure, or unrelated changes.

## Acceptance criteria

- The authenticated page reads as a compact operations dashboard rather than a collection of large cards.
- Analysts can distinguish risk, status, verdict, and age without opening each record.
- Selecting a record keeps queue context visible at desktop widths.
- New case creation uses the drawer without changing upload, OCR, or idempotency behavior.
- Existing authentication, evidence, feedback, Jev, review, history, pagination, and theme tests continue to pass.
- No new runtime or build dependency is introduced.
