(() => {
  const esc = (v) =>
    window.esc ? window.esc(v) : String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const $ = (id) => document.getElementById(id);

  // The open chat survives refreshes (localStorage); every turn is persisted
  // server-side, so history is always re-fetched rather than cached here.
  const LS_KEY = 'autoar_agent_session';
  const newId = () => 's' + Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  let sessionId = null;
  try { sessionId = localStorage.getItem(LS_KEY) || null; } catch (e) { /* ignore */ }
  if (!sessionId) sessionId = newId();
  const remember = () => { try { localStorage.setItem(LS_KEY, sessionId); } catch (e) { /* ignore */ } };
  remember();

  let busy = false;
  let renderedFor = null; // session whose history is in #agent-messages
  let turns = 0; // messages rendered for that session
  let sessions = []; // last /sessions response
  let prefill = ''; // text handed over by openAgentWith()

  const SUGGESTIONS = [
    'Which findings are waiting on me, and what does each one still need before I can submit it?',
    'List the scans that finished in the last 24 hours and call out anything worth a closer look.',
    'Show this week\'s actionable CVEs from the radar that match hosts in our corpus.',
  ];

  // Agent replies are model text that may quote target data: escape it all
  // first, then add back only fenced code, inline code and bold. No links,
  // images or raw HTML ever reach the DOM.
  function fmt(text) {
    const parts = String(text ?? '').split('```');
    return parts.map((part, i) => {
      if (i % 2 === 1) {
        const body = part.replace(/^[\w+-]*\n/, '').replace(/\n$/, '');
        return `<pre class="agent-code"><code>${esc(body)}</code></pre>`;
      }
      // The body is pre-wrap: newlines hugging a code block would stack on
      // top of its margin as blank lines.
      let t = part;
      if (i > 0) t = t.replace(/^\n+/, '');
      if (i < parts.length - 1) t = t.replace(/\n+$/, '');
      return esc(t)
        .replace(/`([^`\n]+)`/g, '<code>$1</code>')
        .replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>');
    }).join('');
  }

  function relTime(unix) {
    const s = Math.max(0, Math.floor(Date.now() / 1000 - unix));
    if (s < 60) return 'just now';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    if (s < 86400) return Math.floor(s / 3600) + 'h ago';
    return Math.floor(s / 86400) + 'd ago';
  }

  function scrollDown() {
    const box = $('agent-messages');
    if (box) box.scrollTop = box.scrollHeight;
  }

  function appendMsg(role, text, toolLog) {
    const box = $('agent-messages');
    if (!box) return null;
    box.querySelector('.agent-empty')?.remove();
    const kind = role === 'owner' ? 'owner' : role === 'error' ? 'error' : 'agent';
    const el = document.createElement('div');
    el.className = 'agent-msg';
    el.dataset.role = kind;
    let html = `<div class="agent-msg-who">${kind === 'owner' ? 'You' : 'Agent'}</div>` +
      `<div class="agent-msg-body">${kind === 'owner' ? esc(text) : fmt(text)}</div>`;
    if (toolLog && toolLog.length) {
      html += `<details class="agent-tools"><summary>${toolLog.length} tool call${toolLog.length === 1 ? '' : 's'}</summary>` +
        toolLog.map((l) => `<div class="agent-tool"><div class="agent-tool-head"><b>${esc(l.tool)}</b><span>${esc(l.summary)}</span></div>${l.output ? `<pre>${esc(l.output)}</pre>` : ''}</div>`).join('') +
        '</details>';
    }
    el.innerHTML = html;
    box.appendChild(el);
    turns++;
    scrollDown();
    return el;
  }

  // A turn can run for minutes (scans, shell commands), so show elapsed time.
  function appendThinking() {
    const box = $('agent-messages');
    if (!box) return () => {};
    box.querySelector('.agent-empty')?.remove();
    const el = document.createElement('div');
    el.className = 'agent-msg';
    el.dataset.role = 'agent';
    el.innerHTML = '<div class="agent-msg-who">Agent</div><div class="agent-msg-body agent-thinking"><span class="agent-dots" aria-hidden="true"><i></i><i></i><i></i></span>Working <span class="agent-elapsed">0s</span></div>';
    box.appendChild(el);
    scrollDown();
    const t0 = Date.now();
    const out = el.querySelector('.agent-elapsed');
    const timer = setInterval(() => {
      const s = Math.round((Date.now() - t0) / 1000);
      out.textContent = s < 60 ? s + 's' : Math.floor(s / 60) + 'm ' + (s % 60) + 's';
    }, 1000);
    return () => { clearInterval(timer); el.remove(); };
  }

  function renderEmpty() {
    const box = $('agent-messages');
    if (!box) return;
    turns = 0;
    box.innerHTML = `<div class="agent-empty">
      <div class="agent-empty-title">What are we hunting?</div>
      <div class="agent-empty-sub">Ask in plain words. The agent picks the tools itself and shows every call it made under its reply.</div>
      <div class="agent-suggest">${SUGGESTIONS.map((s, i) => `<button type="button" class="agent-chip" data-agent-suggest="${i}">${esc(s)}</button>`).join('')}</div>
    </div>`;
  }

  function setTitle() {
    const el = $('agent-chat-title');
    if (!el) return;
    const cur = sessions.find((x) => x.session_id === sessionId);
    el.textContent = (cur && cur.preview) || 'New chat';
  }

  function setBusy(b) {
    const btn = $('agent-send-btn');
    if (btn) { btn.disabled = b; btn.textContent = b ? 'Working…' : 'Send'; }
  }

  function grow(ta) {
    if (!ta) return;
    ta.style.height = 'auto';
    ta.style.height = Math.min(ta.scrollHeight, 220) + 'px';
  }

  async function showSession(id) {
    sessionId = id;
    remember();
    renderedFor = id;
    const box = $('agent-messages');
    if (!box) return;
    box.innerHTML = '';
    turns = 0;
    let msgs;
    try {
      msgs = (await window.apiFetch('/api/ai/agent/session/' + encodeURIComponent(id))).messages || [];
    } catch (e) {
      if (renderedFor === id) appendMsg('error', 'Could not load this chat: ' + (e.message || e));
      return;
    }
    if (renderedFor !== id) return; // switched again while loading
    // Tool results are stored as user turns for the model's context; they are
    // noise here (the agent's reply already summarises them).
    const shown = msgs.filter((m) => !(m.role === 'user' && String(m.content || '').startsWith('TOOL RESULT:')));
    if (!shown.length) renderEmpty();
    for (const m of shown) appendMsg(m.role === 'user' ? 'owner' : 'agent', m.content);
    setTitle();
  }

  function startFresh() {
    sessionId = newId();
    remember();
    renderedFor = sessionId;
    renderEmpty();
    setTitle();
  }

  async function loadSessionList() {
    const list = $('agent-session-list');
    if (!list) return;
    try { sessions = (await window.apiFetch('/api/ai/agent/sessions')).sessions || []; } catch (e) { /* best-effort */ }
    const items = sessions.slice(0, 50);
    if (!items.some((x) => x.session_id === sessionId)) items.unshift({ session_id: sessionId, preview: '', messages: 0, updated_at: 0 });
    list.innerHTML = items.map((x) => {
      const active = x.session_id === sessionId;
      const meta = x.messages ? `${x.messages} message${x.messages === 1 ? '' : 's'} · ${relTime(x.updated_at)}` : 'not started';
      return `<div class="agent-sess${active ? ' active' : ''}">
        <button type="button" class="agent-sess-open" data-agent-open="${esc(x.session_id)}"${active ? ' aria-current="true"' : ''}>
          <span class="agent-sess-title">${esc(x.preview || 'New chat')}</span>
          <span class="agent-sess-meta">${esc(meta)}</span>
        </button>
        ${x.messages ? `<button type="button" class="agent-sess-del" data-agent-del="${esc(x.session_id)}" aria-label="Delete chat" title="Delete chat">×</button>` : ''}
      </div>`;
    }).join('');
    setTitle();
  }

  async function deleteSession(id) {
    if (!await window.uiConfirm('Delete this chat?\n\nIts history and the agent\'s scratch workspace are removed. This cannot be undone.')) return;
    try {
      await window.apiDelete('/api/ai/agent/session/' + encodeURIComponent(id));
    } catch (e) {
      window.showToast('error', 'Delete failed', e.message || String(e));
      return;
    }
    if (id === sessionId) startFresh();
    loadSessionList();
  }

  // New chat keeps the previous one in History (it used to wipe it).
  function newChat() {
    if (turns > 0) startFresh();
    loadSessionList();
    $('agent-input')?.focus();
  }

  async function send(text) {
    const input = $('agent-input');
    const fromInput = text === undefined;
    const msg = String(fromInput ? input?.value || '' : text).trim();
    if (!msg || busy) return;
    if (fromInput && input) { input.value = ''; grow(input); }
    busy = true;
    setBusy(true);
    const sid = sessionId;
    appendMsg('owner', msg);
    const done = appendThinking();
    try {
      const res = await fetch(window.API + '/api/ai/agent/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...(await window.buildAuthHeaders()) },
        body: JSON.stringify({ session_id: sid, message: msg }),
      });
      if (!res.ok) {
        let e = res.statusText || 'HTTP ' + res.status;
        try { e = (await res.json()).error || e; } catch (_) { /* keep status text */ }
        throw new Error(e);
      }
      const data = await res.json();
      done();
      if (sid === sessionId) appendMsg('agent', data.reply || '(empty reply)', data.tool_log);
      else window.showToast('success', 'Agent replied', 'The reply was saved to the chat you left.');
    } catch (e) {
      done();
      if (sid === sessionId) appendMsg('error', 'Error: ' + (e.message || e));
      else window.showToast('error', 'Agent error', e.message || String(e));
    } finally {
      busy = false;
      setBusy(false);
      loadSessionList();
    }
  }

  function wireOnce() {
    const root = $('view-ai-agent');
    if (!root || root.dataset.wired) return;
    root.dataset.wired = '1';
    $('agent-send-btn')?.addEventListener('click', () => send());
    $('agent-new-session-btn')?.addEventListener('click', newChat);
    const input = $('agent-input');
    input?.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); send(); }
    });
    input?.addEventListener('input', () => grow(input));
    $('agent-messages')?.addEventListener('click', (e) => {
      const chip = e.target.closest('[data-agent-suggest]');
      if (chip) send(SUGGESTIONS[Number(chip.dataset.agentSuggest)]);
    });
    $('agent-session-list')?.addEventListener('click', (e) => {
      const del = e.target.closest('[data-agent-del]');
      if (del) { deleteSession(del.dataset.agentDel); return; }
      const open = e.target.closest('[data-agent-open]');
      if (open && open.dataset.agentOpen !== sessionId) {
        showSession(open.dataset.agentOpen);
        loadSessionList();
      }
    });
  }

  async function loadAgentPage() {
    wireOnce();
    if (renderedFor !== sessionId) await showSession(sessionId);
    loadSessionList();
    if (prefill) {
      const input = $('agent-input');
      if (input) {
        input.value = prefill;
        grow(input);
        input.focus();
        input.setSelectionRange(input.value.length, input.value.length);
      }
      prefill = '';
    }
  }

  // Open the agent on a fresh chat with a drafted question (not sent): the
  // owner reads and edits it first.
  function openAgentWith(text) {
    prefill = String(text || '');
    sessionId = newId();
    remember();
    renderedFor = null;
    window.navigateTo('ai-agent');
  }

  window.loadAgentPage = loadAgentPage;
  window.openAgentWith = openAgentWith;
  window.AgentPage = { loadAgentPage, openAgentWith, fmt };
})();
