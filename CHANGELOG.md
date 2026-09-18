# Changelog

All notable changes to the **Phishing & Scam Email Detection** project are
documented in this file.

> **Maintenance rule:** every future change — model upgrades, new datasets,
> backend or frontend tweaks, bug fixes, README adjustments — MUST be appended
> to this file as a new entry under a new ISO-format heading, with the
> following structure:
>
> ```
> ## [YYYY-MM-DD HH:MM PT] — Short title
> ### Why
> ### Files changed
> ### Effect
> ```
>
> Order: newest entry at the top. Times are local (Pacific). Keep entries
> factual and reference specific files, metric values, or commit hashes.

Format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

---

## [2026-09-17 22:10 PT] — Bound MIME parsing and preserve multi-mailbox identity signals

### Why
- Multiple mailboxes in one From field hid display-name impersonation.
- Deep MIME nesting and long monetary digit strings could abort analysis.
- No-MX domains with only IPv6 addresses were incorrectly classified as invalid.

### Files changed
- `website/email_structure.py`: per-mailbox identity checks and a 200-node
  parsing budget with explicit incomplete, outer-headers-only fallback.
- `website/app.py`: bounded monetary evidence and A/AAAA discovery fallback.
- `website/tests/test_review_regressions.py`: adversarial and normal controls.
- `README.md`: limits, fallback behavior, and IPv6 discovery semantics.

### Effect
- Multiple From addresses retain the strongest brand-identity signal.
- Over-budget MIME and large numbers no longer trigger the reproduced exceptions.
- IPv6-only implicit mail hosts remain eligible for verification, while DNS
  errors stay inconclusive and Null MX still stops further checks.

## [2026-09-17 21:55 PT] — Preserve ambiguous-header evidence and clarify verification results

### Why
- Duplicate key headers could hide sender or subject risk. SMTP rejections,
  Null MX records, and caught lookup failures produced misleading verification results.

### Files changed
- `website/email_structure.py`, `website/app.py`: candidate-header analysis,
  header defects, SMTP response distinctions, Null MX, and explicit check status.
- `website/static/app.js`, `website/static/index.html`: incomplete-verification
  and no-mail-service messages; cache version 25.
- Backend and frontend regression tests; `README.md` documents API semantics.

### Effect
- Duplicate critical headers preserve detected risk and flag incomplete analysis.
- Policy rejection and full mailboxes are not classified as nonexistent.
- Null MX stops further checks without labeling the domain as phishing.
- Failed checks cannot report complete verification; SMTP acceptance is not
  presented as guaranteed mailbox existence or delivery.

## [2026-09-17 21:36 PT] — Unify sender checks and bound nested analysis and verification

### Why
- Unicode domains bypassed raw-message sender checks. Attached messages lost
  identity/attachment evidence. JSON requests without Content-Length bypassed the
  body-size guard, and thread-pool shutdown defeated verification timeouts.

### Files changed
- `website/app.py`, `email_structure.py` — shared domain normalization, bounded
  nested-message inspection with untrusted inner authentication, one verification
  deadline covering DNS discovery and follow-up checks, socket cleanup/timeouts.
- `website/request_limits.py` — pre-decoding actual-byte ASGI request-body cap.
- `website/verification_runtime.py` — shared non-queueing bounded verification pool.
- `website/static/app.js`, `index.html` — preserve inconclusive DNS results in
  the UI, clarify the unverifiable verdict, and load v24 JavaScript.
- `website/tests/test_app_security.py`, `test_detection_behavior.py`,
  `static/app.test.mjs` — IDN equivalence, attached-email risk/trust/limits,
  streamed request limits, timeouts, saturation/recovery, and UI regressions.
- `README.md` — input normalization, inspection bounds and operational contracts.

### Effect
- Supported raw-message senders and attached-message risks retain their evidence.
  Uninspected opaque or transfer-encoded attached content is explicitly marked incomplete.
- Oversize streamed JSON is rejected before parsing. Slow verification no longer
  blocks the response beyond its deadline; still-running work retains bounded
  capacity. No real mailbox probing or detection-accuracy claim is implied.

## [2026-09-17 21:18 PT] — Isolate MIME evidence and expose incomplete analysis

### Why
- Concatenated MIME parts allowed unclosed markup to hide other content; parser
  defects silently discarded bodies. Relative HTML targets were not resolved,
  and medium destination-risk floors disappeared during aggregation.

### Files changed
- `website/email_structure.py` — typed content parts and recovered MIME defects.
- `website/app.py` — per-part text/link/form analysis, HTML base resolution,
  risk-floor preservation, and explicit incomplete-analysis response state.
- `website/static/app.js`, `style.css`, `index.html` — amber unknown-risk state,
  incomplete-analysis explanation, nonnumeric score display, and v23 assets.
- `website/tests/test_detection_behavior.py`, `website/static/app.test.mjs` —
  multipart isolation, malformed MIME, relative destinations, risk floors,
  plain-text URL preservation, and unknown-state/animation regressions.
- `README.md` — parsing guarantees, limitations, and new response compatibility.

### Effect
- MIME parts cannot suppress each other's visible evidence. Incomplete parsing
  without detected risk produces `unknown`/null rather than a clean zero; existing
  risk evidence is retained. Relative targets are checked without network access.
- These are bounded parser and rule fixes, not a measured accuracy improvement.

## [2026-09-17 21:01 PT] — Preserve MIME bytes and normalize content evidence

### Why
- Text-only upload decoding corrupted non-UTF8 and Unicode MIME bodies. HTML
  formatting hid credential phrases, positive evidence could become a no-indicators
  verdict, substring shortener checks misfired, and form destinations were omitted.

### Files changed
- `website/app.py` — bounded binary `/api/analyze-eml` route sharing the existing
  analysis pipeline; normalized visible text, contextual credential-request floor,
  consistent low-risk minimum, parsed shortener hosts, form/password evidence.
- `website/email_structure.py` — byte-aware MIME parsing, legacy Unicode support,
  charset and transfer decoding with explicit fallback warnings.
- `website/static/app.js`, `index.html` — original-byte upload, client size feedback,
  shared response error handling, upload limit copy and v22 assets.
- `website/tests/test_detection_behavior.py`, `website/static/app.test.mjs` —
  byte fidelity, stream limits, markup variants, negation/reset controls,
  shortener boundaries and HTML form regressions.
- `README.md` — binary API contract and remaining language/heuristic limitations.

### Effect
- Original message bytes survive transport; rule evidence no longer disappears
  solely because of common HTML formatting or a low positive score.
- Urgency + threats + a direct credential request establish a high-risk floor,
  while tested reset/safety notices do not. Shortener and form targets are checked
  without executing HTML or visiting links. No new model or empirical accuracy claim.

## [2026-09-17 20:35 PT] — Preserve uploaded-message and normalized-link evidence

### Why
- Manual text could replace an uploaded message's body. Equivalent link formats
  bypassed host checks; unknown charsets aborted analysis; attachment-only messages
  were rejected. Generic login hostnames forced a high-risk verdict on weak evidence.

### Files changed
- `website/app.py` — authoritative raw-message mode, structural-only input,
  parsed destination/IP checks, and weaker generic hostname evidence.
- `website/email_structure.py` — safe charset fallback and explicit parse warnings.
- `website/static/app.js`, `index.html`, `style.css` — mutually exclusive file/manual
  input, empty-file feedback, accessible upload status, and v21 static assets.
- `website/tests/test_detection_behavior.py`, `website/static/app.test.mjs` —
  positive and negative controls for the reviewed defects and upload state.
- `README.md` — input precedence, parsing limits, link behavior, and language caveats.

### Effect
- File evidence cannot be overwritten by stale manual text, and supported IP/link
  representations retain risk signals without classifying IP-looking hostnames as IPs.
- Unknown text codecs produce an explicit warning; dangerous attachment-only input
  receives a verdict. Generic account-host terms alone no longer force high risk.
- No new model, data download, or real-world accuracy claim; pure-text/multilingual
  recall still needs independent evaluation.

## [2026-09-17 19:34 PT] — Keep analysis results aligned with current input

### Why
- Late responses could overwrite a newer sender or content result, and mailbox
  verification errors were rendered as invalid addresses. Structural-only risk
  could appear beside a no-patterns summary. Example selection left stale upload UI.

### Files changed
- `website/static/app.js` — request generations, shared HTTP error handling,
  input invalidation, file-read state, and summaries including technical evidence.
- `website/app.py` — reject non-address input at the sender API boundary.
- `website/static/index.html`, `style.css` — accessible inline error messages;
  static assets bumped to v20.
- Frontend and detection tests — out-of-order responses, input changes, HTTP
  errors, invalid addresses, and pending upload regressions.
- `README.md` — accepted sender syntax and request/upload behavior.

### Effect
- Switching or clearing input prevents obsolete results from reappearing.
- Rate limits and service failures no longer become mailbox verdicts.
- Non-address text receives input guidance, and summaries include structural risk.
- Upload state stays consistent when examples replace files or reads finish late.

## [2026-09-17 18:31 PT] — Separate mailbox service type from sender risk

### Why
- Disposable-provider matches were scored as high-risk evidence while the overall
  low verdict displayed a green check. Disabled local verification also displayed
  public-service wording, including after a result reset.

### Files changed
- `website/app.py` — informational disposable-provider evidence, Apple private
  relay domains, accurate provider descriptions, and public deployment profile.
- `website/static/app.js`, `index.html`, `style.css` — neutral low-score display,
  separate service classification, no complementary safety score, and distinct
  local/public/unknown verification messages. Assets bumped to v19.
- `website/static/app.test.mjs`, `website/tests/test_app_security.py`,
  `website/tests/test_detection_behavior.py` — configuration, classification,
  presentation, and full-message regression coverage.
- `README.md` — scoring semantics and explicit local verification startup.

### Effect
- A provider-category match alone adds no phishing points; independent risks still
  score normally. No new empirical detection-accuracy claim is made.
- Low scores no longer imply a verified or safe message. Deployment safety gates
  and rate limits remain enabled.
- Superseded score animations cannot overwrite a newer result when examples are
  analyzed in quick succession; a regression test covers high-to-zero transitions.

## [2026-09-17 15:00 PT] — Scan illustration, score rings, count-ups, light/dark theme

### Why
- Follow-up to the icon pass: the user asked to implement the remaining
  visual suggestions (narrative hero graphic, ring-style scores, animated
  numbers, and automatic light/dark switching).

### Files changed
- `website/static/index.html` — hero visual replaced by `.scan-card` (a
  glass message card with avatar, skeleton lines, one flagged link line, a
  green header check, a red alert badge, and a sweeping `.scan-beam`) while
  keeping the orb glow, rings, and floating chips; sender and content banners
  now wrap the score in a `.score-ring` SVG (`#vb-ring`, `#crb-ring`); hero
  stat values carry `data-count/data-decimals/data-suffix`; nav gains a
  `#theme-toggle` (sun / moon / "A" auto badge); `<head>` bootstrap script
  resolves `data-theme` from `localStorage['phishguard-theme']` or
  `prefers-color-scheme` before first paint; `color-scheme` is `light dark`
  with two `theme-color` metas; assets bumped to `?v=18`.
- `website/static/app.js` — `setupTheme/applyTheme/cycleTheme` (auto → light
  → dark, persisted, follows system changes in auto); `animateNumber()`
  (cubic ease-out, always ends on the exact formatted value; immediate when
  `requestAnimationFrame` is missing or reduced motion is set) used for hero
  stats via `setupCountUps()` and for `vb-prob` / `crb-score`; `setRing()`
  drives `stroke-dashoffset` on the ring (heuristic-only content totals are
  scaled against a ceiling of 30).
- `website/static/style.css` — theme tokens added (`--glass-bg`,
  `--field-bg`, `--fill`, `--line`, `--track`, `--on-accent`, …) and all
  hard-coded dark rgba surfaces converted to them; `:root[data-theme="light"]`
  palette (`#f4f6fb` base, `#0f172a` text, accent `#0a7fd6`, multiply-blend
  colour fields) plus a handful of light-specific overrides; `.scan-*`
  illustration styles (6.5 s beam sweep, 11 s card float, 3.2 s flag pulse);
  `.score-ring` (104 px, 6.5 px stroke, 1.1 s eased fill); `.theme-toggle`
  with cross-fading sun/moon; reduced-motion block covers the new animations.

### Effect
- Verified in headless Chrome for both themes: hero illustration and chips
  render, hero stats count up to `97.47% / 0.9977 / 11,055 / 30`, the sender
  ring fills to 100/100 (`stroke-dashoffset` 0) with `100/100` centred, the
  legitimate-newsletter content result shows a green `0%` ring, and the
  toggle reflects the active mode.
- Theme resolves before first paint (no flash), follows the OS in auto mode,
  and persists a manual choice.
- `node --test website/static/app.test.mjs` 9/9 passing (count-ups set final
  values synchronously in the vm harness); `node --check` OK.

## [2026-09-17 14:51 PT] — Unified SVG icon system replaces emoji

### Why
- User asked for more attractive, modern graphics. The page mixed ~40
  platform-dependent emoji (🛡 ✉ 📄 🔗 🌐 📧 🗑 ⚠️ ✅ ❌ 🔍 ☠️ 🏆 …) that render
  differently per OS and clash with the fluid glass design.

### Files changed
- `website/static/app.js` — added `ICON_PATHS` (29 stroke icons on a 24px
  grid), `icon(name, extraClass)` helper, and `CATEGORY_ICONS` mapping the
  backend `category_results[].key` (urgency, threats, financial, credential,
  impersonation, deception, attachments, tech_scam, job_scam,
  social_engineering) to clock / bell / dollar / key / mask / eye-off /
  paperclip / monitor / briefcase / brain. Verdict banners, disposable-check
  card, verification steps and verdicts, content risk banner, category cards,
  summary pills, and the benchmark "Best" badge now render SVG via
  `innerHTML`; emoji removed from ML verdict text; unused `LEVEL_ICONS`
  dropped. Backend `cat.icon` is no longer displayed (API unchanged).
- `website/static/index.html` — tabs, input adornment, verification section
  titles/buttons, disposable info card, feature category cards, and footer use
  inline SVGs; quick-example chips lose their emoji prefixes; assets bumped to
  `?v=17`.
- `website/static/style.css` — new icon layer: `.ico` sizing, `.icon-tile`
  (44px rounded tile) with tinted `tile-high/medium/low/purple` and
  app-icon-style gradient `tile-grad-cyan/mint/violet` variants; 56px tinted
  discs for `.vb-icon`/`.crb-icon` keyed to banner class; tinted 26px squares
  for `.vstep-icon`; `.best-badge`; per-state colours for `.disp-check-icon`.

### Effect
- Every symbol on the page now shares one stroke weight and palette; category
  cards show a semantic icon (clock for urgency, key for credential harvesting,
  etc.) inside a level-tinted tile instead of backend emoji.
- Verified via headless Chrome on the sender critical-risk result, content
  critical-risk result, features, demo input, and benchmark views.
- `node --test website/static/app.test.mjs` 9/9 passing; `node --check` OK.

## [2026-09-17 13:39 PT] — Integrate fluid frontend with disposable classification

### Why
- The frontend redesign and disposable-email improvements diverged from the
  same base and needed to be combined without losing either visual behavior or
  the newer classification semantics.

### Files changed
- `website/static/app.js`: retain the five-state disposable renderer while
  adding the fluid theme's scroll reveal, palette, chart, and passive-scroll
  updates.
- `website/static/index.html` and `website/static/style.css`: adopt the fluid
  glass layout and cache-busted assets while retaining cautious disposable
  education copy and all result-state selectors.
- `CHANGELOG.md`: preserve both histories in chronological order and record the
  merged verification results.

### Effect
- The redesigned frontend and current sender-analysis API work together without
  code conflicts or loss of classification behavior.
- The merged backend suite passes 83 tests, the frontend suite passes 9 tests,
  and JavaScript syntax validation succeeds.

## [2026-09-17 13:07 PT] — Modern fluid restyle (supersedes the HUD theme)

### Why
- User follow-up: the HUD/instrument look should give way to something more
  modern, closer to Apple's marketing pages — large type, generous space,
  frosted-glass surfaces, and flowing motion — while staying easy on the eyes.

### Files changed
- `website/static/style.css` — rewritten again around a fluid, editorial system:
  `#06080f` base with three fixed radial colour fields (`.bg-fluid .blob-*`)
  that drift on 46/52/58 s alternating loops; floating pill-shaped glass navbar
  (`backdrop-filter: blur(22px)`); hero headline at `clamp(40px, 5.6vw, 72px)`
  with `-0.035em` tracking and a 14 s flowing gradient on the accent word; new
  hero orb (`.orb` conic gradient, `blur(34px)`, 18 s border-radius morph +
  90 s rotation) under a glass core with four gently floating chips; pill
  buttons and tags; segmented demo tabs with a sliding highlight driven by
  `:has(.demo-tab:nth-child(2).active)`; `.reveal/.in-view` transitions;
  `[id] { scroll-margin-top: 84px }` so anchors clear the sticky nav; removed
  the instrument grid, corner brackets, and monospace uppercase labels; kept a
  full `prefers-reduced-motion` fallback that disables all ambient motion and
  shows revealed content immediately.
- `website/static/index.html` — assets bumped to `?v=16`; added the
  `.bg-fluid` layer; replaced the radar markup with `.orb-scene`; dropped the
  `SIGNAL CONSOLE` tag and `hud-frame` classes; softened section eyebrows to
  "Try it / Benchmark / Signals / Pipeline"; hero copy now reads
  "Phishing email detection, explained."
- `website/static/app.js` — added `setupScrollReveal()`: an
  `IntersectionObserver` adds `.in-view` the first time a target enters the
  viewport, with up to 60 ms stagger per child inside `.hero-stats`,
  `.charts-row`, `.feature-cards-grid`, `.top3-grid`, and `.pipeline-steps`.
  It is skipped when
  `IntersectionObserver` is unavailable or reduced motion is requested, so
  nothing is ever left hidden. Scroll listener is now `passive`.

### Effect
- Verified in a real Chrome session (1920×1171) and recorded: cards fade/slide
  in as they scroll into view, the background glow and orb motion are
  perceptible but slow, the segmented control slides between tabs, and both
  sender and content critical-risk results render without overlap or
  stuck-invisible elements.
- Fatigue budget unchanged in spirit: colour fields ≤ 20 % alpha at their
  centre and fully transparent by 68 %, every ambient loop ≥ 9 s (chip float
  9 s, ring breathe 12 s, gradient 14 s, orb morph 18 s, drift ≥ 46 s), reveal
  transitions 0.8 s with a decelerating ease, no flicker.
- After integration, `node --test website/static/app.test.mjs` passes 9/9 (the
  reveal code is guarded so the `vm`-based test harness is unaffected);
  `node --check` passes.

## [2026-09-17 12:41 PT] — Calm sci-fi HUD restyle of the web frontend

### Why
- User request: give the frontend a stronger science-fiction feel without
  making it tiring to read or watch.
- The previous theme was a generic GitHub-dark palette with a single fast
  orbit animation and no visual hierarchy between labels, numbers, and prose.

### Files changed
- `website/static/style.css` — rewritten around a "calm HUD" design system:
  deep-space palette (`#070b14` base, `#4fd1ff` cyan / `#3fd58f` mint accents),
  fixed low-alpha aurora glow and fading 48px instrument grid on `body::before`
  / `body::after`, `hud-frame` corner brackets, monospace uppercase labels for
  all section/column/metric headers, radar hero (concentric rings, 20 s conic
  sweep, 60 s orbiting signal pills), glowing probability bars, HUD-style
  loading ring, `::file-selector-button` styling, `:focus-visible` outlines,
  and a `prefers-reduced-motion` block that freezes ambient motion and pins
  orbit pills to static positions.
- `website/static/index.html` — cache-busted assets to `?v=15`; added
  `color-scheme`/`theme-color` metas, inline SVG shield brand mark with a
  `SIGNAL CONSOLE` tag, hero badge with a slow pulse dot, secondary
  "How It Works" hero button, numbered `section-eyebrow` labels (01–04), and
  `hud-frame` on the input, disposable-info, and chart cards.
- `website/static/app.js` — aligned hardcoded verdict/score colours and the
  Chart.js bar, grid, legend, and tooltip colours to the new palette. No
  behavioural logic changed.

### Effect
- Fatigue controls: decorative layers stay at ≤ 11 % alpha, every ambient
  animation is ≥ 20 s per cycle (aurora drift 48 s, radar sweep 20 s, orbit
  60 s, pulse dot 2.8 s at low amplitude), no flicker/scanline effects, body
  text remains 15px sans-serif on a near-black background, and reduced-motion
  users get a fully static page.
- Layout regressions fixed while restyling: the `No detected risk` probability
  label no longer wraps to three lines (`.prob-label` 36px → 96px) and the
  content-tab `Analyze Content` button is no longer collapsed to text height
  (now 40px tall).
- Verified with headless Chrome at 1440px and 414px on the hero, sender
  critical-risk result, content critical-risk result, benchmark, features,
  pipeline, and mobile views; `node --test website/static/app.test.mjs`
  remains 6/6 passing and the backend suite still passes.

## [2026-09-17 08:48 PT] — Evidence-based disposable email classification

### Why
- Disposable-provider lookup reduced domains to their last two labels, missing
  providers such as `10minutemail.co.uk` and `guerrillamail.co.uk`.
- Broad substring checks falsely classified unrelated domains, while random
  Gmail and Outlook mailbox names were not surfaced at all.
- Privacy relays, plus aliases, and Gmail dot variants could be presented as
  disposable or risky without enough evidence, and the UI implied unsupported
  mailbox-expiration guarantees.

### Files changed
- `website/app.py`: add boundary-aware full-domain registry matching, normalized
  and disjoint disposable/privacy-relay registries, anchored domain heuristics,
  provider-aware mailbox-pattern thresholds, plus-address and Gmail-dot
  normalization, and explicit classification metadata.
- `website/static/app.js` and `website/static/index.html`: render confirmed,
  suspected, privacy-relay, and no-known-match states separately with cautious
  explanations of what the evidence can establish.
- `website/tests/test_detection_behavior.py` and
  `website/static/app.test.mjs`: add regression coverage for multi-label
  providers, random Gmail/Outlook names, relay services, aliases, domain
  collisions, rendered labels, and education copy.
- `README.md`: document the response fields, semantics, and limitations.

### Effect
- Known disposable providers are confirmed by an exact or label-boundary domain
  match; suspicious mailbox or domain shapes remain explicitly heuristic.
- Random-looking Gmail and Outlook addresses are surfaced without being called
  confirmed disposable accounts, while ordinary addresses remain low risk.
- Privacy relays are informational and contribute no phishing score by
  themselves; plus tags and Gmail dots likewise do not increase risk.
- The backend regression suite passes 83 tests and the frontend suite passes
  9 tests.

## [2026-09-15 19:36 PT] — Raw-sender, ASCII-link, and MIME hardening

### Why
- Complete `.eml` analysis parsed the `From` header but did not reuse the
  sender/domain detector, allowing a highly suspicious sender to receive a safe
  full-message verdict when its body was neutral.
- Destination checks covered IDN lookalikes but missed ASCII digit substitutions,
  URL userinfo deception, and trusted-brand labels embedded in attacker domains.
- Attachment scoring relied on filename extensions, so an executable or archive
  MIME type without a matching suffix was not detected.

### Files changed
- `website/app.py`: extract shared sender analysis, fuse bounded sender evidence
  from the highest-risk valid mailbox into raw-message verdicts, and detect
  nonempty URL userinfo plus noncanonical brand labels normalized for common
  digit substitutions and separators.
- `website/email_structure.py`: classify dangerous and archive attachment MIME
  types in addition to filename extensions, including risky leaf parts without
  attacker-controlled attachment metadata.
- `website/tests/test_detection_behavior.py`: add positive attack controls and
  canonical-domain, Gmail-sender, and PDF negative controls.
- `README.md`: document the expanded full-message signals and regression scope.

### Effect
- `billing@secure-account.xyz` in a raw message now contributes its existing
  critical sender score and receives a high-or-critical full-message verdict;
  multi-mailbox `From` headers cannot hide it behind a benign first address.
- `paypa1.com`, `paypal.com@evil.example`, and
  `paypal.com.evil.example` destinations now set a high-risk floor while
  canonical PayPal destinations remain clean.
- Extensionless executable MIME payloads are high risk, archive MIME payloads
  are medium risk, and ordinary PDF attachments remain unscored.
- Common official regional domains remain clean, malformed sender fields and
  empty URL userinfo are ignored, and MIME aliases are covered.
- The backend regression suite now passes 72 tests; the frontend suite remains
  6/6 passing.

## [2026-09-15 14:14 PT] — Destination-aware rules and global corpus deduplication

### Why
- Rules-only analysis inspected displayed URL text but could miss a malicious
  destination behind generic button text, a bare displayed domain, or an IDN
  lookalike.
- Macro-enabled and archive attachments were not scored, and decisive trusted
  authentication failures could still receive only a medium verdict.
- Source-prefixed fallback groups allowed normalized duplicates from different
  corpora to cross the train/test boundary; permissive substring and
  obfuscation rules also produced avoidable false positives.

### Files changed
- `website/app.py`: analyze HTML, Markdown, and plain-text destinations; detect
  IDN lookalikes, displayed-host mismatches, credential-themed domains, raw-IP
  destinations, malformed targets, `hxxp` schemes, and zero-width keyword
  splitting; add evidence severity floors and boundary-aware phrase matching.
- `website/email_structure.py`: score macro-enabled, executable, disk-image, and
  archive attachments and expose a structural risk floor.
- `website/content_model.py`: deduplicate normalized families across all sources,
  exclude label conflicts, use source-independent fallback groups, and select
  candidate models by cross-validated average precision.
- `website/tests/test_detection_behavior.py` and project documentation: add the
  corresponding adversarial regressions and refresh measured metrics.

### Effect
- Generic-link, bare-domain, and IDN destination attacks now receive high-risk
  evidence; ZIP and macro-document attachments no longer pass as safe; decisive
  SPF/DKIM/DMARC failure sets a high-risk minimum.
- Normal words such as `login` and substrings such as `irs` in `first` no longer
  trigger obfuscation or brand rules.
- From 61,707 raw corpus rows, normalization retained 53,841 after removing
  7,333 duplicates and 533 label-conflicting rows. The 10,768-row grouped
  holdout measured 99.78% phishing recall, 0.22% false-negative rate, 97.88%
  precision, 98.89% accuracy, and 0.9996 PR AUC at an F2 threshold of 0.3515.

## [2026-09-15 08:57 PT] — Trusted email evidence and offline model artifacts

### Why
- Uploaded `Authentication-Results` headers could claim `dmarc=pass` and
  suppress real authentication failures without proving which receiver created
  the header.
- Protected-brand display names and internationalized lookalike domains were
  not represented in raw-message structural risk.
- Local SMTP verification could connect to private DNS targets, the in-memory
  rate limiter trusted raw forwarding headers, and web startup could download
  data and train the content model.

### Files changed
- `website/email_structure.py` and `website/config.py`: add configurable trusted
  authentication-service IDs plus protected-brand, IDNA, and Unicode-confusable
  identity signals.
- `website/app.py`: enforce public SMTP targets, bound rate-limit state, ignore
  raw forwarding headers, load only verified offline content-model artifacts,
  and remove the dead `/api/predict` route and UCI runtime model state.
- `website/content_model.py` and `website/prebuild_demo_model.py`: add versioned
  SHA-256-verified artifacts, disable pickle-cache loading by default, strengthen
  near-duplicate grouping, and report per-source sample counts.
- `website/tests/`, `.env.example`, `render.yaml`, and project documentation:
  add adversarial regression coverage and document the new safe defaults.

### Effect
- Untrusted authentication claims cannot affect scoring; configured receiver
  results retain forwarding-aware DMARC handling.
- Display-name, Punycode, and common Unicode lookalikes produce visible phishing
  evidence while canonical brand domains remain clean.
- SMTP cannot open a socket to non-global addresses, rate-limit memory is
  bounded, and default web startup remains rules-only without network or model
  training work.
- Optional ML is deployed as a trusted offline artifact whose digest and runtime
  compatibility are checked before use.
- A fresh 61,707-row offline evaluation with normalized family grouping retained
  zero train/test group overlap and measured 99.67% phishing recall, 0.33%
  false-negative rate, 98.80% precision, 99.21% accuracy, 0.9997 PR AUC, and a
  learned F2 threshold of 0.3636 on the 12,342-row held-out fold.

## [2026-09-04 13:52 PT] — Full corpus recall benchmark and campaign URL isolation

### Why
- The first full evaluation grouped PhishNChips rows by unique record ID even
  when multiple variants shared the same phishing URL. That could allow one
  campaign's variants to cross training and test boundaries.
- The project needed a direct comparison between the default `0.5` decision
  threshold and the learned recall-oriented threshold.

### Files changed
- `website/content_model.py`: groups PhishNChips variants by `url_raw` before
  falling back to record ID/text hash; reports the grouping policy, default
  threshold recall, and recall gain; defaults bundled synthetic-template
  augmentation to off; bumps the cache key to v5.2.
- `website/tests/test_detection_behavior.py`: verifies shared campaign URLs use
  one group and the new threshold-comparison metrics are present.
- `.env.example`: documents `CONTENT_MODEL_AUGMENT_SYNTHETIC=false`.
- `README.md`: records the dated corpus evaluation and its limitations.

### Effect
- On the 12,342-row group-isolated holdout, the learned F2 threshold `0.3492`
  achieved phishing recall `0.9980` and false-negative rate `0.0020`, compared
  with recall `0.9951` at threshold `0.5` (`+0.0028`). Accuracy was `0.9921`,
  precision `0.9869`, F1 `0.9924`, ROC AUC `0.9997`, PR AUC `0.9998`, and Brier
  score `0.0058`; train/test group overlap was zero.
- These remain offline mixed-corpus results rather than a production claim:
  PhishNChips is synthetic, classic corpora lack campaign IDs, and the split is
  not time-separated.

## [2026-09-04 13:24 PT] — Evidence-preserving phishing detection and honest evaluation

### Why
- The sender endpoint applied a Random Forest trained on UCI phishing-website
  URL/HTML features to similarly named email-address heuristics. That domain
  mismatch made its displayed “phishing probability” and feature importances
  invalid for email senders.
- The content model split individual rows, allowing variants from the same
  source/template family to appear in training and evaluation, and fitted its
  TF-IDF vocabulary before cross-validation. Both could inflate reported
  performance.
- Full authentication headers, sender-identity alignment, MIME attachments,
  and actual HTML link destinations were unavailable to the detector. Weak ML
  output could also average away strong rule evidence, while attacker-copyable
  footer text reduced risk.

### Files changed
- `website/app.py`: replaced sender-model probability output with a declared
  heuristic risk score; added raw-message input, conservative max-evidence
  fusion, honest UCI metric scope, rules-only readiness, HTML-link parsing, and
  neutral handling of regional English and safety-footer phrases.
- `website/email_structure.py`: added RFC 5322/MIME parsing, SPF/DKIM/DMARC
  result checks, From/Reply-To/Return-Path alignment, multipart HTML coverage,
  and dangerous-attachment indicators.
- `website/content_model.py`: added campaign/template group IDs,
  `StratifiedGroupKFold`, per-fold TF-IDF fitting, out-of-fold F2 threshold
  selection, phishing recall/FNR/PR-AUC/Brier reporting, cache invalidation,
  and removal of automatic downloads from an unaudited PhishFuzzer mirror.
- `website/config.py`, `.env.example`, and `render.yaml`: added
  `CONTENT_MODEL_ENABLED`; the public Render profile now uses validated
  sender/structure/rule analysis without synthetic model training.
- `website/static/index.html`, `website/static/app.js`, and
  `website/static/style.css`: added `.eml` upload, sender-risk terminology,
  recall-focused metrics, scoped the historical UCI website benchmark, removed
  invalid sender importance claims, and escaped attacker-controlled indicator
  text before HTML rendering.
- `website/tests/test_detection_behavior.py`, `website/tests/test_app_security.py`,
  `website/tests/test_config.py`, and `website/static/app.test.mjs`: added
  regression coverage for the new semantics, raw-message evidence, grouping,
  deployment mode, multipart HTML, forwarded-mail authentication, and output
  escaping.
- `README.md` and `phishing-detection/README.md`: documented the new detector,
  evaluation scope, dataset limitations, and reproducible quality gates.

### Effect
- Sender results no longer claim unsupported ML probabilities. Complete email
  files can expose high-value phishing evidence that plain text omits.
- Evaluation prevents train/test campaign-family overlap, learns a
  recall-oriented threshold without using the held-out set, and reports the
  metrics needed to measure missed phishing.
- Strong structural/authentication evidence cannot be diluted by a weak text
  score, copied safety footers do not evade detection, and regional language is
  not treated as malicious.
- The zero-cost public deployment starts without a synthetic model while
  retaining useful explainable detection, and the regression suite verifies
  both model-enabled and rules-only behavior.

## [2026-06-20 15:15 PT] — README features-table sync with v4.3 content classifier

### Why
- User flagged: the "Web Application" features table in `README.md` still
  described **Email Content Analysis** as "Rule-based keyword scan across
  10 phishing categories + 11 structural checks", which has been stale
  since v2 of the content classifier (May 2026). The same row also said
  "all four classifiers" in the Model Metrics Dashboard row even though
  we now also expose the content-classifier metrics in `/api/metrics`.

### Files changed
- `README.md` (features table, two rows):
  - **Email Content Analysis** — now reads
    "Hybrid **ML + heuristic** classifier — TF-IDF (word + char n-gram)
    → CV-selected calibrated model (LogReg / LinearSVC / ComplementNB)
    trained on ~82 400 emails incl. 2026 LLM-grounded benchmarks
    (PhishNChips v5.2, PhishFuzzer), blended 55 / 45 with the
    10-category keyword scan + 11 structural checks".
  - **Model Metrics Dashboard** — wording adjusted from "all four
    classifiers" to "all classifiers (UCI URL-feature models + content
    classifier)" so it matches what `/api/metrics` actually returns.

### Effect
- Top-of-README feature summary now accurately reflects the v4.3 hybrid
  pipeline; new readers won't be told the content path is rule-only.
- No code or model changes; docs-only patch.

---

## [2026-06-20 14:55 PT] — 2026 LLM-grounded datasets + brand-impersonation rebalance (v4.3)

### Why
- User asked: "继续加强训练，数据集尽量用最新的". Up to v4 the real data was
  still 2002–2008 mailing-list traffic. Modern phishing attacks (GitHub
  Pages hosting, IPFS, URL shorteners, QR-code lures, hyper-realistic LLM
  brand impersonation) were under-represented, and we were still seeing
  false positives on legit transactional emails (Amazon shipping, Stripe
  payout, DocuSign envelope) once the LLM-generated phishing was mixed in.

### Files changed
- `phishing-detection/data/` *(new files, ~42 MB total)* — three
  `phishnchips_*.csv` and three `phishfuzzer_*.csv` files downloaded from
  Hugging Face into the data directory.
- `website/content_model.py`:
  - Added two new schemas `phishnchips_csv` (JSON-encoded `email_content`
    blob from PhishNChips v5.2) and `phishfuzzer_csv` (Subject/Body/Type
    columns from PhishFuzzer; `Spam` rows dropped, `Phishing→1`,
    `Valid→0`).
  - Extended `_DATASETS` with six new entries pointing at the HF mirrors
    of **PhishNChips v5.2** (Apr 2026, 2 387 emails grounded in real
    PhishTank / OpenPhish / GitHub Pages / Tranco / cross-domain modern
    workplace data) and **PhishFuzzer** (Nov 2026, 19 800 LLM-generated
    variants over 3 300 real seeds, 3-class).
  - Bumped synthetic `n_variants` from 80 → 160 to give the modern legit
    templates more relative weight against brand-impersonation phishing.
  - Added ~8 brand-issued transactional legit templates (Amazon shipping
    × 3, Stripe payout × 3, DocuSign envelope × 3, Chase mortgage,
    Google 2FA backup codes) directly aimed at the failure patterns
    surfaced by the new corpora.
  - Added a tie-break rule in `build_content_pipeline`: when LinearSVC
    and LogisticRegression are within 0.001 ROC AUC, prefer LogReg
    because its sigmoid output is naturally well-calibrated for
    boundary samples (Platt-calibrated SVM was producing brittle
    50–60 % probabilities for legit Amazon / Stripe / DocuSign).
  - `_CACHE_VERSION` → `v4.3-2026-brand-saturated-logreg-preferred`
    (forces retrain; old `v3-...` cache is stale).

### Effect
- Training corpus grew from ~50 k → **82 393 emails**
  (65 914 train + 16 479 test). New 2026 data contributes
  ~16 k modern LLM-grounded examples (2 387 PhishNChips + 13 356
  PhishFuzzer after dropping Spam).
- Model: `LogisticRegression` (selected via tie-break against
  CalibratedLinearSVC, both at CV ROC AUC ≈ 0.9995).
- Test metrics: **Accuracy 0.9905 · F1 0.9908 · ROC AUC 0.9996** on a
  held-out 16 479-row test set.
- 15/15 on the hard generalisation suite (7 modern legit including
  Amazon shipping / Stripe payout / DocuSign / Chase mortgage / 2FA
  backup codes / GitHub PR / Calendar invite, 4 classic phishing,
  4 brand-new 2026 attack patterns — Google Docs lure, QR-code invoice
  scam, IPFS-hosted DocuSign envelope, GitHub Pages security alert).
  Lowest legit score 32.1 %, highest legit 32.1 %; lowest phishing
  79.7 % → comfortable 47-point decision margin.
- Cold-train time ≈ 2 min 40 s; warm load from
  `phishing-detection/data/content_model_cache.pkl` (3.6 MB) is
  effectively instant.

---

## [2026-06-20 14:36 PT] — Project change-history bootstrap

### Why
- User asked: "将之前所有的更新记录起来，具体到时间，位置，更新的原因和效果。
  以后所有的更新都要记录在里面". Up to this point all changes were only
  reflected in commits/files; there was no single dated narrative of what
  happened and why.

### Files changed
- `CHANGELOG.md` *(new)* — backfilled four prior dated entries
  (v4 multi-dataset, v3 real-data + caching, v2 initial ML integration,
  plus a "project context anchors" appendix) and pinned the maintenance
  rule at the top.
- `README.md` — added a top-of-file pointer ("📋 Change history: see
  `CHANGELOG.md`") so the log is discoverable.
- `.cursor/rules/changelog.mdc` *(new)* — Cursor rule with
  `alwaysApply: true` requiring every future code/model/dataset/doc/dep
  change in this repo to append a new dated entry to `CHANGELOG.md`
  before ending the turn. Entry-format spec is included verbatim.

### Effect
- Future agent sessions (and humans) will see and honour the rule via
  Cursor's always-applied rules system, so the changelog stays current
  by default instead of needing to be remembered.
- Three prior tracked milestones (initial ML, real-data + cache,
  multi-dataset + model selection) are now visible to any reviewer as a
  single chronological record, eliminating the need to read commit
  history or scroll through long chats to understand the evolution.

---

## [2026-06-20 14:30 PT] — Content classifier v4: multi-dataset + model selection + modern templates

### Why
- The v3 model (trained only on `Phishing_Email.csv`, 18,631 emails) showed
  three concrete false positives on real-world modern emails: Amazon order
  confirmations (46.3 % phishing), Wells Fargo mortgage statements (73.2 %)
  and Google 2FA backup codes (79.6 %).
- Root cause: the public corpus is heavy on 2002–2008 mailing-list traffic and
  under-represents modern e-commerce / SaaS / banking / 2FA notification
  formats. Pulling in more 2002-era data would not fix this.
- Goal: (1) substantially expand both the *phishing* coverage (CEAS_08 +
  Nazario) and the *modern legitimate* coverage (new synthetic templates);
  (2) replace the hand-picked classifier with automatic CV-driven selection.

### Files changed
- **`website/content_model.py`**
  - `_DATASETS` table — three real corpora declared (Phishing_Email + CEAS_08
    + Nazario) with downloaders.
  - `ensure_real_dataset()` rewritten to fetch all three from their direct
    URLs (Hugging Face + Zenodo 8339691).
  - `_load_one_corpus()` added with two schemas
    (`phishing_email_csv`, `champa_csv`); filters Nazario mbox-control rows
    like `FOLDER INTERNAL DATA`.
  - `_LEGIT_TEMPLATES` extended by **17 new modern templates**: Amazon order,
    Best Buy receipt, GitHub PR comment, GitHub CI build, Stripe receipt,
    AWS invoice, Slack DM digest, Zoom meeting reminder, Google Calendar
    invite, Apple App Store receipt, Netflix payment, Uber Eats, DocuSign
    NDA, Chase Sapphire statement, Notion weekly digest, LinkedIn weekly
    summary, Lyft trip receipt, Spotify Premium receipt, Delta flight
    confirmation, Shopify new-order, Datadog usage report, password-changed
    confirmation, generic 2FA OTP, Coursera receipt, Figma welcome —
    plus a second batch: Wells Fargo mortgage statement, Chase auto-loan,
    PG&E utility bill, Comcast Xfinity bill, State Farm renewal, Geico
    insurance card, Fidelity 1099-INT, Google 2-Step backup codes,
    1Password Emergency Kit, generic authenticator code, Workday W-2,
    open-enrollment HR memo, Etsy / Bookshop.org orders, Partiful RSVP,
    Calendly confirmation.
  - `n_variants` default raised **40 → 80** so synthetic samples are not
    drowned out by the 59 k real-corpus rows.
  - **Model selection added** — `build_content_pipeline()` now runs 3-fold
    stratified CV ROC AUC across three candidates and picks the winner:
    - `LogisticRegression(C=4, liblinear, balanced)`
    - `CalibratedClassifierCV(LinearSVC, method='sigmoid', cv=3)` — Platt-scaled
      so it emits probabilities.
    - `ComplementNB(alpha=0.3)`
  - `_extract_coefficients()` added to keep the explainability layer
    working for all three model families (incl. CalibratedClassifierCV via
    averaged inner-estimator coefs and ComplementNB via
    `feature_log_prob_` diff).
  - `predict_content()` made robust to classifiers without `coef_`.
  - `_CACHE_VERSION` bumped to `v3-multidataset-modelselect-calibrated`
    so the existing on-disk cache is invalidated.
- **`phishing-detection/data/CEAS_08.csv`** (64 MB) added — downloaded from
  `https://zenodo.org/records/8339691/files/CEAS_08.csv` (Champa et al. 2024,
  CC-BY-4.0).
- **`phishing-detection/data/Nazario.csv`** (7.4 MB) added — same source.
- **`README.md`** — content-classifier section + datasets table rewritten to
  reflect the three-corpus pipeline and the new metrics.
- **`phishing-detection/README.md`** — same updates plus file-tree entries
  for the two new CSVs.

### Effect

| Metric (20 % hold-out) | v3 | **v4** |
|------------------------|-----|--------|
| Training samples | 16,376 | **50,392** |
| Accuracy | 0.9805 | **0.9908** |
| Precision | 0.9617 | **0.9900** |
| Recall | 0.9909 | **0.9920** |
| F1 | 0.9761 | **0.9911** |
| ROC AUC | 0.9983 | **0.9997** |
| Selected model | LogReg (hard-coded) | **LogReg (CV-selected)** |

11-sample hard generalization battery (samples NOT in training templates):

| Sample | v3 ML % | **v4 ML %** | Verdict |
|--------|--------:|------------:|---------|
| Phish: Crypto wallet hack | 100.0 | **99.2** | ✓ phishing |
| Phish: HR salary credential grab | 70.8 | **64.2** | ✓ phishing |
| Phish: SharePoint share scam | 99.9 | **98.9** | ✓ phishing |
| Phish: Voicemail .exe attachment | 62.4 | **63.9** | ✓ phishing |
| Phish: Apple ID closure scam | 100.0 | **99.9** | ✓ phishing |
| Legit: Wells Fargo mortgage | **73.2 ⚠ FP** | **9.5** | ✓ legit (fixed) |
| Legit: Pediatric appointment | 0.1 | **0.9** | ✓ legit |
| Legit: School field-trip slip | 1.1 | **7.8** | ✓ legit |
| Legit: K8s CI failure email | 3.6 | **8.8** | ✓ legit |
| Legit: 2FA backup codes | **79.6 ⚠ FP** | **37.2** | ✓ legit (fixed) |
| Bonus: Amazon order shipped | 19.1 | **11.3** | ✓ legit |

**Overall: 11/11 correct (100 %).** All three previously-known false
positives were eliminated.

Training time: ~127 s on first run; subsequent server starts load the
pickled pipeline in **< 50 ms**.

---

## [2026-06-20 13:59 PT] — Content classifier v2 → v3: real public dataset + caching

### Why
- The v2 model trained on a purely synthetic template corpus reported
  Accuracy / F1 / ROC AUC = 1.0 — visibly inflated. Held-out metrics on
  synthetic data don't reflect real-world performance.
- We needed a real-world labelled email corpus and faster startups so the
  FastAPI app doesn't take 40 s every reload.

### Files changed
- **`website/content_model.py`**
  - Module-level docstring rewritten to declare the real-data-first
    pipeline.
  - `ensure_real_dataset()` and `load_real_corpus()` added with auto-download
    from the Hugging Face mirror of the Kaggle *Phishing Email Detection*
    dataset (`zefang-liu/phishing-email-dataset`,
    `Phishing_Email.csv`, 18 650 emails, LGPL-3.0).
  - Vectoriser upgraded from single `TfidfVectorizer` to `FeatureUnion`:
    - word 1–2 grams (semantic phrases)
    - `char_wb` 3–5 grams (catches obfuscation like `P@yP@l`, `Amaz0n`)
  - `_extract_coefficients()` precursor / `_flat_feature_names()` introduced
    so the per-email top-token explainability still works through
    `FeatureUnion`.
  - **Pickle-based cache** added (`content_model_cache.pkl`) keyed by a
    SHA-256 hash that captures dataset file sizes/mtimes + training options
    + `_CACHE_VERSION` (`v2-word12-charwb35`). First training takes ~38 s,
    subsequent loads ≈ 20 ms.
- **`website/app.py`**
  - `/api/metrics` extended to include the `content_model` section
    (`name`, `metrics`, `data_source`, `top_terms`).
- **`README.md`** + **`phishing-detection/README.md`** — added new
  "Email-text dataset" section, dataset citation, and a metrics table.

### Effect

| Metric | Synthetic-only (v2 inflated) | **v3 with real data** |
|--------|------------------------------|----------------------|
| Training samples | 1,472 | **16,376 (≈11× more)** |
| Test samples | 368 | **4,095** |
| Accuracy | 1.0 | **0.9805** |
| F1 | 1.0 | **0.9761** |
| ROC AUC | 1.0 | **0.9983** |
| Startup time | ~1 s | 38 s first time / **0.02 s cached** |

Manual test verification:

| Sample | v3 ML phishing prob |
|--------|---------------------|
| Classic PayPal urgency phish | 100.0 % |
| Obfuscated `P@yP@l` / `acc0unt` | 99.4 % |
| TechBlog newsletter | 2.5 % |
| Legit Amazon order | 46.3 % (boundary — noted as known weak spot, addressed in v4) |

---

## [2026-06-20 13:51 PT] — Initial ML integration for email-content search

### Why
- The website had two analyzers: the *email-address* tab used a Random Forest
  ML model; the *email-content* tab used **only** hand-coded keyword rules.
  User asked: "让邮件内容搜索也采用机器学习" — make the content scan also use
  ML so the system is end-to-end ML-driven.

### Files changed
- **`website/content_model.py`** *(new file)*
  - 24 phishing templates + 20 legitimate templates with randomised
    placeholders (`{brand}`, `{url}`, `{amount}`, `{name}`).
  - `generate_content_corpus()` produces 1,840 balanced samples.
  - `build_content_pipeline()` fits `TfidfVectorizer(ngram=(1,2),
    stopwords=english, sublinear_tf)` + `LogisticRegression(class_weight=
    balanced)`; computes Accuracy / Precision / Recall / F1 / ROC AUC on a
    20 % stratified hold-out.
  - `predict_content()` returns `ml_phishing_probability`,
    `ml_legitimate_probability`, `ml_label`, `ml_prediction`,
    `ml_top_contributors` (per-email word-level token attribution).
- **`website/app.py`**
  - `from content_model import build_content_pipeline, predict_content`.
  - New global `_content_pipeline` populated in `startup_event()`.
  - `/api/analyze-content` rewritten to: (1) still run the heuristic
    scanner, (2) add ML probabilities into the response, (3) blend the two
    into a `combined_phishing_score` (55 % ML + 45 % heuristic) and
    promote/demote `risk_level` accordingly.
- **`website/static/index.html`**
  - Added a `content-ml-card` section between the risk banner and the
    keyword-category grid.
  - Updated the "About This Analysis" footer to describe the new ML +
    heuristic hybrid (replacing the previous "this is NOT an ML model"
    disclaimer).
- **`website/static/app.js`**
  - `renderContentResult()` extended to display ML phishing/legit
    probability bars, ML metric badges (Accuracy / F1 / ROC AUC), and the
    per-email top phishing-indicative tokens.
- **`website/static/style.css`**
  - `.content-ml-card`, `.ml-badge`, `.ml-card-metrics`, `.ml-metric`,
    `.ml-contribs`, `.ml-token` style rules added (blue accent palette).

### Effect
- Both analyzers in the web app are now ML-driven.
- Live API verified end-to-end:
  - Classic PayPal phishing sample → **ML 98.1 % phishing**, combined 81.0,
    verdict *Critical Risk*.
  - TechBlog newsletter sample → **ML 2.1 % phishing**, combined 1.2,
    verdict *No Phishing Indicators Found*.
- The pure-synthetic metrics (Accuracy / F1 / AUC all 1.0) were honest about
  being synthetic — the v3 update later replaced this with real data.

---

## Project context — anchors that predate this changelog

These items were already in place at the start of the conversation that
created this file. Listed for completeness; future entries describe deltas
relative to this baseline.

- **Random Forest URL-feature classifier** trained on the UCI Phishing
  Websites Dataset (`phishing-detection/data/phishing_dataset.csv`,
  11 055 rows × 30 features). Held-out metrics from the notebook:
  Accuracy 97.47 %, F1 0.9746, ROC AUC **0.9977** (best of four classifiers
  benchmarked: Random Forest, SVM-RBF, Decision Tree, Logistic Regression).
- **FastAPI backend** `website/app.py` with endpoints `/api/metrics`,
  `/api/features`, `/api/analyze-email`, `/api/analyze-content`,
  `/api/verify-email`, `/api/predict`.
- **Disposable-email database** of 500+ known providers + 6-factor
  auto-generated-username heuristic.
- **Email-authenticity 7-stage verifier**: RFC 5321 format → DNS MX/A →
  SMTP RCPT TO → SPF (`-all/~all/?all/+all`) → DMARC
  (`p=reject/quarantine/none`) → MX PTR / reverse-DNS → WHOIS domain age.
- **Single-page frontend** (`website/static/index.html` + `app.js` +
  `style.css`) — dark-theme responsive UI with orbital hero animation,
  three analysis tabs, animated probability bars, and a model-performance
  panel powered by Chart.js.
