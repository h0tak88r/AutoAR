const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

// uiConfirm replaces native confirm(), which embedded browsers suppress
// (returns false without a dialog) — every guarded action used to do nothing.

const repoRoot = path.resolve(__dirname, '../..');

function setup() {
  const listeners = {};
  let overlay = null;
  const mkBtn = (val) => ({ dataset: { uiConfirm: val }, focus() { doc.activeElement = this; }, closest(sel) { return sel === '[data-ui-confirm]' ? this : null; } });
  const yes = mkBtn('yes');
  const no = mkBtn('no');
  const doc = {
    activeElement: null,
    contains: () => true,
    body: { appendChild(el) { overlay = el; } },
    addEventListener(t, f) { listeners[t] = f; },
    removeEventListener(t) { delete listeners[t]; },
    getElementById: () => null,
    createElement: () => {
      const el = {
        className: '', innerHTML: '', handlers: {},
        addEventListener(t, f) { this.handlers[t] = f; },
        querySelector: (sel) => (sel.includes('"yes"') ? yes : no),
        querySelectorAll: () => [no, yes],
        remove() { overlay = null; },
      };
      return el;
    },
  };
  const context = { console, document: doc, window: { esc: (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])) } };
  vm.createContext(context);
  const rel = 'internal/api/ui/pages/ui-helpers.js';
  vm.runInContext(fs.readFileSync(path.join(repoRoot, rel), 'utf8'), context, { filename: rel });
  return { win: context.window, doc, listeners, getOverlay: () => overlay, yes, no };
}

test('confirm button resolves true, cancel and Escape resolve false', async () => {
  let s = setup();
  let p = s.win.uiConfirm('Run the AI review on 3 findings?\n\nEach uses one unit of the daily AI budget.');
  const ov = s.getOverlay();
  assert.ok(ov.innerHTML.includes('Run the AI review on 3 findings?'));
  assert.ok(ov.innerHTML.includes('Each uses one unit'));
  assert.ok(ov.innerHTML.includes('btn-primary'), 'non-destructive → primary button');
  assert.equal(s.doc.activeElement, s.yes, 'non-destructive focuses Confirm');
  ov.handlers.click({ target: s.yes });
  assert.equal(await p, true);
  assert.equal(s.getOverlay(), null, 'dialog removed');

  s = setup();
  p = s.win.uiConfirm('Delete 4 findings?\n\nScan results stay untouched.');
  assert.ok(s.getOverlay().innerHTML.includes('btn-danger') && s.getOverlay().innerHTML.includes('>Delete<'));
  assert.equal(s.doc.activeElement, s.no, 'destructive focuses Cancel');
  s.getOverlay().handlers.click({ target: s.no });
  assert.equal(await p, false);

  s = setup();
  p = s.win.uiConfirm('Delete this chat?');
  s.listeners.keydown({ key: 'Escape', preventDefault() {}, stopPropagation() {} });
  assert.equal(await p, false);
});

test('the message is escaped', async () => {
  const s = setup();
  s.win.uiConfirm('Delete "<img src=x onerror=alert(1)>"?');
  assert.doesNotMatch(s.getOverlay().innerHTML, /<img/);
});

// uiPrompt replaces native prompt(), which the app browser pane also
// suppresses (null at once — "Submitted" with a report link cancelled).
function setupPrompt() {
  const listeners = {};
  let overlay = null;
  const input = { value: '', focus() { doc.activeElement = this; }, select() {} };
  const form = { handlers: {}, addEventListener(t, f) { this.handlers[t] = f; } };
  const doc = {
    activeElement: null,
    contains: () => true,
    body: { appendChild(el) { overlay = el; } },
    addEventListener(t, f) { listeners[t] = f; },
    removeEventListener(t) { delete listeners[t]; },
    getElementById: () => null,
    createElement: () => ({
      className: '', innerHTML: '', handlers: {},
      addEventListener(t, f) { this.handlers[t] = f; },
      querySelector: (sel) => (sel === 'input' ? input : sel === 'form' ? form : null),
      querySelectorAll: () => [input],
      remove() { overlay = null; },
    }),
  };
  const context = { console, document: doc, window: { esc: (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])) } };
  vm.createContext(context);
  const rel = 'internal/api/ui/pages/ui-helpers.js';
  vm.runInContext(fs.readFileSync(path.join(repoRoot, rel), 'utf8'), context, { filename: rel });
  return { win: context.window, doc, listeners, getOverlay: () => overlay, input, form };
}

test('uiPrompt: submit resolves the text, Escape and Cancel resolve null, values are escaped', async () => {
  let s = setupPrompt();
  let p = s.win.uiPrompt('Report link', { value: 'H1#1', placeholder: '<b>x</b>', help: 'Leave empty to remove it.', type: 'url' });
  const ov = s.getOverlay();
  assert.ok(ov.innerHTML.includes('Report link') && ov.innerHTML.includes('Leave empty to remove it.'));
  assert.ok(ov.innerHTML.includes('type="url"') && ov.innerHTML.includes('&lt;b&gt;x&lt;/b&gt;'));
  assert.equal(s.input.value, 'H1#1', 'prefilled');
  assert.equal(s.doc.activeElement, s.input, 'input focused');
  s.input.value = 'https://hackerone.com/reports/1';
  s.form.handlers.submit({ preventDefault() {} });
  assert.equal(await p, 'https://hackerone.com/reports/1');
  assert.equal(s.getOverlay(), null);

  s = setupPrompt();
  p = s.win.uiPrompt('Scan name (optional)');
  s.listeners.keydown({ key: 'Escape', preventDefault() {}, stopPropagation() {} });
  assert.equal(await p, null);

  s = setupPrompt();
  p = s.win.uiPrompt('x');
  s.getOverlay().handlers.click({ target: { closest: (sel) => (sel === '[data-ui-prompt="no"]' ? {} : null) } });
  assert.equal(await p, null);

  s = setupPrompt();
  s.win.uiPrompt('New password', { type: 'password' });
  assert.ok(s.getOverlay().innerHTML.includes('type="password"') && s.getOverlay().innerHTML.includes('autocomplete="new-password"'));
  s = setupPrompt();
  s.win.uiPrompt('y', { type: 'javascript' });
  assert.ok(s.getOverlay().innerHTML.includes('type="text"'), 'unknown types fall back to text');
});
