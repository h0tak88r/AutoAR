const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const repoRoot = path.resolve(__dirname, '../..');

// Agent replies are model output that routinely quotes what a scanned target
// returned, so the chat formatter is an XSS boundary: everything is escaped,
// and the only markup it may emit is <pre class="agent-code">, <code> and <b>.

function loadAgent() {
  const store = {};
  const context = {
    console,
    Date,
    Math,
    localStorage: {
      getItem: (k) => (k in store ? store[k] : null),
      setItem: (k, v) => { store[k] = String(v); },
    },
    document: { getElementById: () => null },
    window: {},
  };
  context.window.esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  vm.createContext(context);
  const rel = 'internal/api/ui/pages/ai-agent.js';
  vm.runInContext(fs.readFileSync(path.join(repoRoot, rel), 'utf8'), context, { filename: rel });
  return { win: context.window, store };
}

const ALLOWED_TAG = /^<\/?(pre|code|b)( class="agent-code")?>$/;
function assertOnlyAllowedTags(html) {
  for (const tag of html.match(/<[^>]*>/g) || []) assert.match(tag, ALLOWED_TAG, `unexpected markup: ${tag}`);
}

test('hostile reply text is escaped, never rendered', () => {
  const { win } = loadAgent();
  const out = win.AgentPage.fmt('<img src=x onerror=alert(1)> and <script>alert(2)</script> [x](javascript:alert(3))');
  assertOnlyAllowedTags(out);
  assert.ok(out.includes('&lt;img src=x onerror=alert(1)&gt;'));
});

test('payloads inside code fences, inline code and bold stay inert', () => {
  const { win } = loadAgent();
  const out = win.AgentPage.fmt('**<b onmouseover=alert(1)>x</b>** `"><svg onload=alert(2)>`\n```html\n</code></pre><img src=x onerror=alert(3)>\n```\ntail');
  assertOnlyAllowedTags(out);
  assert.ok(out.includes('<pre class="agent-code"><code>&lt;/code&gt;&lt;/pre&gt;&lt;img src=x onerror=alert(3)&gt;</code></pre>'), 'fence body escaped, language tag dropped');
  assert.ok(out.includes('<code>&quot;&gt;&lt;svg onload=alert(2)&gt;</code>'));
});

test('an unclosed fence still renders as escaped code', () => {
  const { win } = loadAgent();
  const out = win.AgentPage.fmt('run this:\n```\n<script>x</script>');
  assertOnlyAllowedTags(out);
  assert.ok(out.endsWith('<pre class="agent-code"><code>&lt;script&gt;x&lt;/script&gt;</code></pre>'));
});

test('newlines hugging a code block are trimmed (no stacked blank lines)', () => {
  const { win } = loadAgent();
  assert.equal(win.AgentPage.fmt('a\n\n```\nb\n```\n\nc'), 'a<pre class="agent-code"><code>b</code></pre>c');
});

test('the open chat id is remembered across reloads', () => {
  const { store } = loadAgent();
  assert.match(store.autoar_agent_session, /^s[a-z0-9]+$/, 'server accepts it: <=64 chars, no spaces or slashes');
});
