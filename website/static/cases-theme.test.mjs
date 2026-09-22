import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

function setup({stored = null, light = false, blocked = false} = {}) {
  const root = {dataset: {}}, listeners = {}, control = {value: '', addEventListener(type, fn) { listeners['control:' + type] = fn; }};
  const meta = {setAttribute(key, value) { this[key] = value; }};
  const storage = new Map(stored === null ? [] : [['phishguard-theme', stored]]);
  const media = {matches: light, addEventListener(type, fn) { listeners['media:' + type] = fn; }};
  const sourceFile = new URL('./cases-theme.js', import.meta.url);
  vm.runInNewContext(readFileSync(sourceFile, 'utf8'), {
    document: {documentElement: root, querySelector: () => meta, getElementById: () => control,
      addEventListener(type, fn) { listeners[type] = fn; }},
    window: {matchMedia: () => media, addEventListener(type, fn) { listeners['window:' + type] = fn; }},
    localStorage: {
      getItem(key) { if (blocked) throw new Error('Blocked'); return storage.get(key) ?? null; },
      setItem(key, value) { if (blocked) throw new Error('Blocked'); storage.set(key, value); },
      removeItem(key) { if (blocked) throw new Error('Blocked'); storage.delete(key); }
    }
  });
  return {root, meta, control, storage,
    ready() { listeners.DOMContentLoaded?.(); },
    choose(mode) { control.value = mode; listeners['control:change']?.(); },
    system(value) { media.matches = value; listeners['media:change']?.(); },
    storageEvent(key, value) { listeners['window:storage']?.({key, newValue: value}); }
  };
}

test('system preference is resolved before DOM ready', () => {
  const ui = setup({light: true});
  assert.equal(ui.root.dataset.theme, 'light');
  assert.equal(ui.root.dataset.themeMode, 'auto');
  assert.equal(ui.meta.content, '#fafafa');
});

test('saved homepage preference wins over the system', () => {
  const ui = setup({stored: 'dark', light: true}); ui.ready();
  assert.equal(ui.root.dataset.theme, 'dark');
  assert.equal(ui.meta.content, '#0a0a0a');
  assert.equal(ui.control.value, 'dark');
  ui.system(false); ui.system(true);
  assert.equal(ui.root.dataset.theme, 'dark');
});

test('manual choice persists only the theme and survives a page load', () => {
  const ui = setup(); ui.ready(); ui.choose('light');
  assert.equal(ui.root.dataset.theme, 'light');
  assert.deepEqual([...ui.storage], [['phishguard-theme', 'light']]);
  const reload = setup({stored: ui.storage.get('phishguard-theme')});
  assert.equal(reload.root.dataset.theme, 'light');
});

test('returning to system clears the override and follows subsequent changes', () => {
  const ui = setup({stored: 'light'}); ui.ready(); ui.choose('auto');
  assert.equal(ui.storage.has('phishguard-theme'), false);
  assert.equal(ui.root.dataset.theme, 'dark');
  ui.system(true); assert.equal(ui.root.dataset.theme, 'light');
});

test('blocked local storage does not prevent switching', () => {
  const ui = setup({blocked: true}); ui.ready(); ui.choose('light');
  assert.equal(ui.root.dataset.theme, 'light');
  ui.choose('auto'); assert.equal(ui.root.dataset.themeMode, 'auto');
});

test('invalid saved values use the system default', () => {
  const ui = setup({stored: 'invalid', light: true}); ui.ready();
  assert.equal(ui.control.value, 'auto');
  assert.equal(ui.root.dataset.theme, 'light');
});

test('changes made in another homepage tab synchronize without unrelated storage effects', () => {
  const ui = setup(); ui.ready();
  ui.storageEvent('phishguard-theme', 'light');
  assert.equal(ui.root.dataset.theme, 'light');
  assert.equal(ui.control.value, 'light');
  ui.storageEvent('unrelated', 'dark');
  assert.equal(ui.root.dataset.theme, 'light');
  ui.storageEvent('phishguard-theme', null);
  assert.equal(ui.root.dataset.theme, 'dark');
});
