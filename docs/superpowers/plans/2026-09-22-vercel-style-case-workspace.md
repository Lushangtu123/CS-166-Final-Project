# Vercel-inspired Case Workspace Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Rebuild the authenticated case workspace as a compact, responsive operations dashboard while preserving every existing security and case-management behavior.

**Architecture:** Keep the current server-rendered HTML, CSS, and plain JavaScript. The HTML provides a native create-case dialog and table-like queue structure; `cases.js` remains the only UI state owner and gains small dialog and row-rendering helpers; `cases.css` supplies the Vercel-inspired shell, themes, responsive behavior, and motion handling.

**Tech Stack:** HTML5, CSS custom properties, plain JavaScript, Node's built-in test runner, FastAPI static serving.

**Spec:** `docs/superpowers/specs/2026-09-22-vercel-style-case-workspace-design.md`

## Global Constraints

- Add no runtime or build dependency.
- Keep token values memory-only and only in the Authorization header.
- Keep saved email content text-only; never render untrusted HTML.
- Preserve case API, Upstash schema, risk engine, Jev contract, OCR, idempotency, feedback records, pagination, and review conflict handling.
- Preserve system, light, and dark themes.

---

### Task 1: Lock the new interaction contract with focused tests

**Files:**
- Modify: `website/static/cases.test.mjs`

**Interfaces:**
- Consumes: current synthetic DOM harness and existing `setup()` helper.
- Produces: assertions for `open-compose`, `close-compose`, `compose-dialog`, structured queue columns, and successful-creation dialog closure.

- [x] **Step 1: Extend the synthetic element harness for dialog behavior**

Add `open`, `showModal()`, and `close()` state to the test `Element` class:

```js
showModal() { this.open = true; }
close() { this.open = false; this.dispatchEvent({type: 'close'}); }
```

- [x] **Step 2: Add failing interaction tests**

Add these concrete cases using the existing `setup`, `login`, `fire`, and `caseValue` helpers:

```js
test('authenticated analysts can open and close the create-case drawer', async () => {
  const ui = setup(standard); await ui.login();
  await ui.fire('open-compose');
  assert.equal(ui.el('compose-dialog').open, true);
  await ui.fire('close-compose');
  assert.equal(ui.el('compose-dialog').open, false);
});

test('queue rows expose dashboard columns without rendering untrusted HTML', async () => {
  const ui = setup(standard); await ui.login();
  assert.deepEqual(ui.el('case-list').children[0].children.map(child => child.className),
    ['case-cell risk-cell', 'case-cell title-cell', 'case-cell status-cell',
     'case-cell verdict-cell', 'case-cell date-cell']);
});
```

Extend the existing creation and sign-out tests to assert `compose-dialog.open === false` after the operation.

- [x] **Step 3: Run the focused test and confirm the intended failure**

Run:

```bash
node --test website/static/cases.test.mjs
```

Expected: new assertions fail because the dialog controls and structured row columns do not exist yet.

### Task 2: Recompose the workspace HTML

**Files:**
- Modify: `website/static/cases.html`

**Interfaces:**
- Consumes: all existing element IDs used by `cases.js`, `vision.js`, and `file-intake.js`.
- Produces: `open-compose`, `close-compose`, `compose-dialog`, queue toolbar, `queue-columns`, and the same existing form/detail IDs.

- [x] **Step 1: Replace the authenticated page heading with a compact dashboard header**

Keep `notice`, `workspace`, and all authentication IDs unchanged. Add the primary `open-compose` button beside the page title.

- [x] **Step 2: Move the existing create form into a native dialog drawer**

Wrap the complete current `compose-content` markup in `<dialog id="compose-dialog" class="compose-dialog" aria-labelledby="compose-title">` and `<div class="drawer-shell">`. Add a drawer header containing `<h2 id="compose-title">Create an investigation</h2>` and `<button id="close-compose" type="button" aria-label="Close new case form">×</button>`. Retain every existing form field, warning, progress region, file control, and submit/cancel button ID exactly once.

- [x] **Step 3: Add table-like queue headings and compact filter toolbar**

Add a presentation-only heading row for Risk, Investigation, Status, Verdict, and Created. Keep the record list itself as keyboard-accessible buttons.

- [x] **Step 4: Bump static asset query versions**

Increment the `cases.css` and `cases.js` query versions so Vercel clients do not reuse stale assets.

### Task 3: Implement structured rows and dialog lifecycle

**Files:**
- Modify: `website/static/cases.js`
- Test: `website/static/cases.test.mjs`

**Interfaces:**
- Consumes: `HTMLDialogElement.showModal()`, `HTMLDialogElement.close()`, `open-compose`, and `close-compose`.
- Produces: `openComposer()`, `closeComposer()`, and case rows with `.case-cell` children.

- [x] **Step 1: Add safe dialog helpers**

Implement helpers that open only when authenticated and close only when open:

```js
function openComposer() {
  if (!token || $('workspace').hidden || $('compose-dialog').open) return;
  $('compose-dialog').showModal();
}
function closeComposer({reset = false} = {}) {
  if (reset) {
    $('create-form').reset();
    $('subject').disabled = $('body').disabled = false;
    $('case-file-status').textContent = '';
    $('vision-progress').textContent = '';
  }
  if ($('compose-dialog').open) $('compose-dialog').close();
}
```

- [x] **Step 2: Render each queue item into semantic visual columns**

Continue using `textContent` through `node()`. Build risk, title/type, status, verdict, and created-time spans; keep `aria-pressed` and `data-case-id` for selection.

- [x] **Step 3: Connect open, close, cancel, sign-out, and successful creation**

Explicit close and Escape preserve entered draft content. Sign-out clears the draft. A successful create resets and closes the dialog after rendering the returned case.

- [x] **Step 4: Run the focused tests to green**

Run:

```bash
node --test website/static/cases.test.mjs
```

Expected: all case UI tests pass.

### Task 4: Build the dashboard visual system

**Files:**
- Modify: `website/static/cases.css`
- Modify: `website/static/cases-theme.js`
- Test: `website/static/cases-theme.test.mjs`

**Interfaces:**
- Consumes: existing `data-theme` and `data-theme-mode` attributes.
- Produces: neutral theme tokens, compact shell, queue table, sticky detail pane, right drawer, and responsive layouts.

- [x] **Step 1: Define dark and light neutral design tokens**

Use CSS custom properties for canvas, panels, raised controls, text, borders, focus, and risk colors. Update only the theme-color metadata values in `cases-theme.js` and its assertions.

- [x] **Step 2: Implement the compact shell and controls**

Use a 232-pixel desktop sidebar, 48-pixel top bar, 32-pixel controls, thin borders, restrained radii, and no decorative gradient.

- [x] **Step 3: Implement queue and detail layouts**

Render desktop queue rows with the same five-column CSS grid as the heading. Make the detail panel sticky with a viewport-bound maximum height and internal overflow.

- [x] **Step 4: Implement the create drawer and responsive breakpoints**

Animate the drawer from the right on desktop, use a full-height sheet on mobile, collapse secondary row columns below the title, and stack queue/detail below tablet widths.

- [x] **Step 5: Add accessibility and motion safeguards**

Maintain visible focus, text labels for risk, high-contrast active rows, `color-scheme`, and a `prefers-reduced-motion` rule that removes transitions and animations.

- [x] **Step 6: Run case and theme tests**

Run:

```bash
node --test website/static/cases.test.mjs website/static/cases-theme.test.mjs
```

Expected: all tests pass.

### Task 5: Verify neighboring behavior and real rendering

**Files:**
- Verify: `website/static/cases.html`
- Verify: `website/static/cases.css`
- Verify: `website/static/cases.js`

**Interfaces:**
- Consumes: completed UI and unchanged case API.
- Produces: final test and browser evidence for the accepted design.

- [x] **Step 1: Run the full frontend suite**

Run:

```bash
node --test website/static/*.test.mjs
```

Expected: every frontend test passes.

- [x] **Step 2: Run relevant backend regression tests**

Run the repository Python environment against case API, feedback API, application security, and Vercel runtime smoke tests.

- [x] **Step 3: Serve and inspect in a real browser**

Exercise login, filtering, selection, creation drawer, Escape/close behavior, theme switching, review controls, sign-out, desktop layout, and a mobile viewport. Confirm untrusted content remains text-only.

- [x] **Step 4: Inspect final scope and static references**

Run `git diff --check`, inspect the complete diff, confirm asset version references resolve, and verify no dependency or backend contract changed.

- [x] **Step 5: Request commit/push authorization**

Report exact verification evidence and ask before creating the implementation commit, pushing, or deploying.
