/* AIPenScan frontend: new-scan form, live SSE console, tabs, answer/refocus. */
(function () {
  'use strict';

  async function post(action, data) {
    const r = await fetch('api.php?action=' + encodeURIComponent(action), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.error || ('request failed (' + r.status + ')'));
    return j;
  }

  // ---- new scan form (index) ----
  const form = document.getElementById('new-scan-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const err = document.getElementById('form-err');
      const btn = document.getElementById('start-btn');
      err.textContent = '';
      btn.disabled = true;
      const data = Object.fromEntries(new FormData(form).entries());
      try {
        const j = await post('create', data);
        window.location.href = 'scan.php?id=' + j.id;
      } catch (ex) {
        err.textContent = ex.message;
        btn.disabled = false;
      }
    });
  }

  // ---- scan page ----
  const page = document.getElementById('scan-page');
  if (!page) return;
  const scanId = page.dataset.scanId;
  const consoleEl = document.getElementById('console');
  const findingsEl = document.getElementById('findings');
  const auditEl = document.getElementById('audit');
  const statusEl = document.getElementById('scan-status');
  const summaryEl = document.getElementById('scan-summary');
  const qbox = document.getElementById('question-box');
  const qtext = document.getElementById('question-text');
  let lastId = 0;
  let finished = false;

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function addLine(ev) {
    if (consoleEl.querySelector('.muted') && consoleEl.querySelector('.muted').textContent.startsWith('Connecting')) {
      consoleEl.innerHTML = '';
    }
    const div = document.createElement('div');
    div.className = 'line t-' + ev.type;
    const when = (ev.created_at || '').slice(11, 19);
    div.innerHTML = '<span class="ts">' + esc(when) + '</span> '
      + '<span class="agent">[' + esc(ev.agent || 'sys') + ']</span> '
      + '<span class="msg">' + esc(ev.message || '') + '</span>';
    consoleEl.appendChild(div);
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  async function refresh(full) {
    try {
      const r = await fetch('api.php?action=get&scan_id=' + encodeURIComponent(scanId));
      const j = await r.json();
      if (!r.ok) return;
      const s = j.scan;
      statusEl.textContent = s.status;
      statusEl.className = 'status ' + s.status;
      if (s.summary) summaryEl.textContent = s.summary;
      if (s.status === 'awaiting_input' && s.clarifying_question) {
        qbox.classList.remove('hidden');
        qtext.textContent = s.clarifying_question;
      } else {
        qbox.classList.add('hidden');
      }
      if (full) {
        const planPre = document.getElementById('plan-pre');
        if (planPre && s.plan_json) planPre.textContent = s.plan_json;
        const report = document.getElementById('custom-report');
        if (report && s.custom_html) report.innerHTML = s.custom_html;
      }
      renderFindings(j.findings || []);
      renderAudit(j.audit || []);
      if (['complete', 'error', 'cancelled'].includes(s.status)) {
        finished = true;
        const cancelBtn = document.getElementById('cancel-btn');
        if (cancelBtn) cancelBtn.remove();
      }
    } catch (e) { /* transient; SSE/poll will retry */ }
  }

  function renderFindings(list) {
    document.getElementById('finding-count').textContent = list.length ? '(' + list.length + ')' : '';
    if (!list.length) {
      findingsEl.innerHTML = '<p class="muted">No findings yet.</p>';
      return;
    }
    findingsEl.innerHTML = list.map((f) =>
      '<article class="finding sev-' + esc(f.severity) + '">' +
      '<header><span class="sev">' + esc(f.severity) + '</span> <strong>' + esc(f.title) + '</strong> ' +
      '<span class="muted">[' + esc(f.agent) + ']</span></header>' +
      (f.detail ? '<p>' + esc(f.detail) + '</p>' : '') +
      (f.evidence ? '<pre>' + esc(f.evidence) + '</pre>' : '') +
      '</article>'
    ).join('');
  }

  function renderAudit(list) {
    if (!list.length) {
      auditEl.innerHTML = '<p class="muted">No audit entries yet.</p>';
      return;
    }
    auditEl.innerHTML = '<table><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr></thead><tbody>' +
      list.map((a) =>
        '<tr><td class="muted">' + esc((a.created_at || '').slice(11, 19)) + '</td>' +
        '<td>' + esc(a.actor) + '</td><td>' + esc(a.action) + '</td>' +
        '<td class="detail">' + esc((a.detail || '').slice(0, 400)) + '</td></tr>'
      ).join('') + '</tbody></table>';
  }

  function connect() {
    const es = new EventSource('api.php?action=events&scan_id=' + encodeURIComponent(scanId) + '&last_id=' + lastId);
    es.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data);
        lastId = Math.max(lastId, ev.id || 0);
        addLine(ev);
        if (['finding', 'done', 'question', 'error'].includes(ev.type)) refresh(true);
      } catch (err) { /* ignore malformed */ }
    };
    es.onerror = () => {
      es.close();
      // Fall back to polling while the stream is unavailable.
      setTimeout(() => { if (!finished) { refresh(true); poll(); } }, 3000);
    };
  }

  async function poll() {
    if (finished) return;
    await refresh(true);
    // catch up on any events missed between last SSE message and now
    try {
      const r = await fetch('api.php?action=get&scan_id=' + encodeURIComponent(scanId));
      void r;
    } catch (e) { /* ignore */ }
    setTimeout(poll, 5000);
  }

  // Tabs
  document.getElementById('tabs').addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-tab]');
    if (!btn) return;
    document.querySelectorAll('#tabs button').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    document.querySelectorAll('.tabpane').forEach((p) => p.classList.add('hidden'));
    document.getElementById('tab-' + btn.dataset.tab).classList.remove('hidden');
  });

  // Answer form
  document.getElementById('answer-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ta = e.target.querySelector('textarea');
    try {
      await post('answer', { scan_id: Number(scanId), answer: ta.value });
      ta.value = '';
      finished = false;
      refresh(true);
      connect();
    } catch (ex) {
      alert(ex.message);
    }
  });

  // Refocus form
  document.getElementById('refocus-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const ta = e.target.querySelector('textarea');
    const msg = document.getElementById('refocus-msg');
    try {
      const j = await post('refocus', { scan_id: Number(scanId), instructions: ta.value });
      window.location.href = 'scan.php?id=' + j.id;
    } catch (ex) {
      msg.textContent = ex.message;
    }
  });

  // Cancel
  const cancelBtn = document.getElementById('cancel-btn');
  if (cancelBtn) {
    cancelBtn.addEventListener('click', async () => {
      if (!confirm('Cancel this scan?')) return;
      try {
        await post('cancel', { scan_id: Number(scanId) });
        refresh(true);
      } catch (ex) {
        alert(ex.message);
      }
    });
  }

  refresh(true);
  connect();
})();
