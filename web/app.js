/* Agent Firewall — clearance board.
 *
 * Two sources, one board:
 *   live   — an engine is reachable, so strips file in as real decisions land
 *            and Clear/Refuse resolve genuinely parked calls.
 *   replay — no engine (the deployed page's normal state), so a recorded run
 *            files in on the same timings. Every score and every annotation in
 *            replay.json is real engine output, captured from a live run.
 *
 * Live mode is opt-in via ?engine=<url> (or ENGINE below) because the engine
 * runs on the developer's own machine; the deployed board has nothing to poll.
 */

const ENGINE = new URLSearchParams(location.search).get('engine') || '';
const POLL_MS = 1000;

const el = {
  strips:    document.getElementById('strips'),
  empty:     document.getElementById('bayEmpty'),
  brief:     document.getElementById('clearanceBrief'),
  session:   document.getElementById('metaSession'),
  agent:     document.getElementById('metaAgent'),
  cleared:   document.getElementById('metaCleared'),
  held:      document.getElementById('metaHeld'),
  refused:   document.getElementById('metaRefused'),
  linkDot:   document.getElementById('linkDot'),
  linkText:  document.getElementById('linkText'),
  runDemo:   document.getElementById('runDemo'),
  reset:     document.getElementById('resetBoard'),
  footNote:  document.getElementById('footNote'),
};

const STAMP = { allow: 'Cleared', hold: 'Held', block: 'Refused' };

/** Strips currently on the board, oldest first. */
let filed = [];
let lastSeq = 0;
let live = false;
let replay = null;
let playing = false;

/* ------------------------------------------------------------------ render */

function esc(value) {
  return String(value ?? '').replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function clockOf(ts) {
  const d = new Date((ts || Date.now() / 1000) * 1000);
  return d.toLocaleTimeString([], { hour12: false });
}

/** Compact one-line reading of the arguments — the strip's route field. */
function routeOf(strip) {
  const args = strip.args || {};
  const parts = Object.entries(args).map(([k, v]) => {
    const text = typeof v === 'string' ? v : JSON.stringify(v);
    return `${k} ${text.length > 64 ? text.slice(0, 64) + '…' : text}`;
  });
  return parts.join('  ·  ');
}

function stripMarkup(strip, index) {
  const state = strip.decision;
  const held = state === 'hold';
  const annotated = state !== 'allow' && (strip.annotation || strip.provenance);

  const actions = held && strip.hold_id ? `
      <div class="annot-actions">
        <button class="ctl ctl-clear" type="button" data-clear="${esc(strip.hold_id)}">Clear it</button>
        <button class="ctl ctl-refuse" type="button" data-refuse="${esc(strip.hold_id)}">Refuse it</button>
      </div>` : '';

  const annotation = annotated ? `
    <div class="annot">
      <p class="annot-label">Controller's note</p>
      <p class="annot-body">${esc(strip.annotation || '')}</p>
      ${strip.provenance ? `<p class="annot-source">Raised on: <b>${esc(strip.provenance)}</b></p>` : ''}
      ${actions}
    </div>` : '';

  return `
    <article class="strip" data-state="${esc(state)}" aria-label="${esc(strip.tool)} — ${STAMP[state]}">
      <div class="cell cell-seq">
        <span class="seq">${String(index + 1).padStart(2, '0')}</span>
        <span class="time">${clockOf(strip.ts)}</span>
      </div>
      <div class="cell cell-action">
        <span class="tool">${esc(strip.tool)}</span>
        <span class="args">${esc(routeOf(strip))}</span>
      </div>
      <div class="cell cell-score">
        <span class="score">${Math.round(strip.risk)}</span>
        <span class="score-label">risk</span>
      </div>
      <div class="cell cell-stamp">
        <span class="stamp">${STAMP[state]}</span>
      </div>
      ${annotation}
    </article>`;
}

function render() {
  el.empty.hidden = filed.length > 0;
  el.strips.querySelectorAll('.strip').forEach((n) => n.remove());
  const html = filed.map((s, i) => stripMarkup(s, i)).reverse().join('');
  el.strips.insertAdjacentHTML('beforeend', html);

  const count = (state) => filed.filter((s) => s.decision === state).length;
  el.cleared.textContent = count('allow');
  el.held.textContent = count('hold');
  el.refused.textContent = count('block');
}

function setClearance({ intent, session, agent }) {
  if (intent) {
    el.brief.textContent = intent;
    el.brief.dataset.empty = 'false';
  }
  if (session) el.session.textContent = session;
  if (agent) el.agent.textContent = agent;
}

function setLink(state, text) {
  el.linkDot.dataset.state = state;
  el.linkText.textContent = text;
}

/* --------------------------------------------------------------- filing */

function file(strip) {
  const existing = filed.findIndex((s) => s.hold_id && s.hold_id === strip.hold_id);
  if (existing >= 0) filed[existing] = { ...filed[existing], ...strip };
  else filed.push(strip);
  render();
}

/* ----------------------------------------------------------------- live */

async function engineGet(path) {
  const res = await fetch(`${ENGINE}${path}`, { cache: 'no-store' });
  if (!res.ok) throw new Error(String(res.status));
  return res.json();
}

/** Engine feed records use the pipeline's field names; map them onto a strip. */
function fromFeed(record) {
  return {
    seq: record.seq,
    ts: record.ts,
    tool: record.tool,
    args: {},
    risk: record.risk_score,
    decision: record.decision,
    hold_id: record.hold_id,
    annotation: record.counterfactual,
    provenance: record.provenance,
  };
}

async function pollLive() {
  try {
    const feed = await engineGet(`/events?since=${lastSeq}`);
    (feed.records || []).forEach((r) => {
      lastSeq = Math.max(lastSeq, r.seq);
      file(fromFeed(r));
    });
    const sessions = await engineGet('/sessions');
    const armed = (sessions.sessions || []).find((s) => s.armed && s.intent);
    if (armed) setClearance({ intent: armed.intent, session: armed.session_id, agent: armed.agent });
    setLink('live', 'Live engine');
  } catch {
    setLink('replay', 'Engine unreachable');
  }
}

async function resolveHold(holdId, action) {
  if (!live) {
    // Replay: the recording already carries the outcome the reviewer chose.
    const strip = filed.find((s) => s.hold_id === holdId);
    if (strip) {
      strip.decision = action === 'approve' ? 'allow' : 'block';
      strip.annotation = action === 'approve'
        ? 'Cleared by the reviewer. The call was released to the server and ran.'
        : 'Refused by the reviewer. The call never reached the server.';
      strip.provenance = 'reviewer decision';
      render();
    }
    return;
  }
  try {
    await fetch(`${ENGINE}/holds/${encodeURIComponent(holdId)}/${action}`, { method: 'POST' });
  } catch { /* the next poll reconciles */ }
}

/* --------------------------------------------------------------- replay */

async function loadReplay() {
  if (replay) return replay;
  const res = await fetch('./replay.json', { cache: 'no-store' });
  replay = await res.json();
  return replay;
}

const wait = (ms) => new Promise((r) => setTimeout(r, ms));

async function playReplay() {
  if (playing) return;
  playing = true;
  el.runDemo.disabled = true;
  el.runDemo.textContent = 'Session running…';

  try {
    const data = await loadReplay();
    filed = [];
    render();
    setClearance({ intent: data.intent, session: data.session_id, agent: data.agent });

    for (const strip of data.strips) {
      await wait(strip.delay_ms ?? 900);
      file({ ...strip, ts: Date.now() / 1000 });
    }
  } catch {
    el.footNote.textContent = 'Could not load the recorded session.';
  } finally {
    playing = false;
    el.runDemo.disabled = false;
    el.runDemo.textContent = 'Run the recorded session';
  }
}

/* ------------------------------------------------------------------ boot */

el.strips.addEventListener('click', (event) => {
  const clear = event.target.closest('[data-clear]');
  const refuse = event.target.closest('[data-refuse]');
  if (clear) resolveHold(clear.dataset.clear, 'approve');
  if (refuse) resolveHold(refuse.dataset.refuse, 'deny');
});

el.runDemo.addEventListener('click', playReplay);
el.reset.addEventListener('click', () => {
  filed = [];
  render();
  el.brief.textContent = 'No clearance filed';
  el.brief.dataset.empty = 'true';
  el.session.textContent = '—';
  el.agent.textContent = '—';
});

async function boot() {
  if (ENGINE) {
    try {
      await engineGet('/health');
      live = true;
      setLink('live', 'Live engine');
      el.footNote.textContent = 'Connected to a live engine. Held actions on this board are real and clearing one releases it.';
      el.runDemo.hidden = true;
      await pollLive();
      setInterval(pollLive, POLL_MS);
      return;
    } catch {
      el.footNote.textContent = `No engine answered at ${ENGINE}. Showing the recorded session instead.`;
    }
  }
  setLink('replay', 'Recorded session');
  await playReplay();
}

boot();
