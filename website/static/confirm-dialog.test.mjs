import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import vm from 'node:vm';

const source = readFileSync(new URL('./confirm-dialog.js', import.meta.url), 'utf8');

class Node {
  constructor(tag) { this.tag = tag; this.children = []; this.attrs = {}; this.listeners = {}; this.returnValue = ''; }
  append(...nodes) { this.children.push(...nodes); }
  setAttribute(key, value) { this.attrs[key] = value; }
  addEventListener(name, listener) { this.listeners[name] = listener; }
  showModal() { this.open = true; }
  focus() { this.focused = true; }
  remove() { this.removed = true; }
  close(value) { this.open = false; this.returnValue = value; this.listeners.close?.(); }
}

function load({ dialogSupported }) {
  const body = new Node('body');
  const document = { body, createElement: tag => new Node(tag) };
  const window = { confirm: () => 'native' };
  const context = vm.createContext({ document, window, setTimeout: fn => fn(),
    ...(dialogSupported ? { HTMLDialogElement: function HTMLDialogElement() {} } : {}) });
  vm.runInContext(source, context);
  return { window, body };
}

test('falls back to the native confirm when <dialog> is unavailable', async () => {
  const { window } = load({ dialogSupported: false });
  assert.equal(await window.PhishGuardConfirm('Proceed?'), 'native');
});

test('themed confirm resolves from the chosen button and focuses cancel', async () => {
  const { window, body } = load({ dialogSupported: true });
  const confirmed = window.PhishGuardConfirm('Sign out?', { confirmLabel: 'Sign out' });
  const dialog = body.children.at(-1);
  const [text, actions] = dialog.children[0].children;
  const [cancel, ok] = actions.children;
  assert.equal(text.textContent, 'Sign out?');
  assert.equal(ok.textContent, 'Sign out');
  assert.equal(cancel.focused, true);
  dialog.close('confirm');
  assert.equal(await confirmed, true);
  assert.equal(dialog.removed, true);

  const dismissed = window.PhishGuardConfirm('Discard?');
  body.children.at(-1).close('');
  assert.equal(await dismissed, false);
});
