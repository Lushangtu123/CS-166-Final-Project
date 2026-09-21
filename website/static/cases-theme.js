'use strict';
// Loaded before the stylesheet so the saved theme applies before first paint.
(() => {
  const key = 'phishguard-theme';
  const root = document.documentElement;
  const media = typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-color-scheme: light)') : null;
  const normalize = value => value === 'light' || value === 'dark' ? value : 'auto';
  let mode = 'auto', control = null;
  try { mode = normalize(localStorage.getItem(key)); } catch (_) { /* Storage is optional. */ }
  function apply(value) {
    mode = normalize(value);
    const theme = mode === 'auto' ? (media?.matches ? 'light' : 'dark') : mode;
    root.dataset.theme = theme;
    root.dataset.themeMode = mode;
    document.querySelector('meta[name="theme-color"]')?.setAttribute('content', theme === 'light' ? '#f3f6f3' : '#101413');
    if (control) control.value = mode;
  }
  apply(mode);
  media?.addEventListener('change', () => { if (mode === 'auto') apply('auto'); });
  window.addEventListener('storage', event => {
    if (event.key === key || event.key === null) apply(event.newValue);
  });
  document.addEventListener('DOMContentLoaded', () => {
    control = document.getElementById('case-theme');
    if (!control) return;
    control.value = mode;
    control.addEventListener('change', () => {
      apply(control.value);
      try {
        if (mode === 'auto') localStorage.removeItem(key);
        else localStorage.setItem(key, mode);
      } catch (_) { /* Still works for this page when storage is unavailable. */ }
    });
  });
})();
