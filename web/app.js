/* Agent Firewall — clearance board.
 *
 * Two sources, one board:
 *   live   — an engine is reachable, so strips file in as real decisions land
 *            and Clear/Refuse resolve genuinely parked calls.
 *   replay — no engine (the deployed page's normal state), so a recorded run
 *            files in on the same timings. Every score and every annotation in
 *            replay.json is real engine output, captured from a live run.
 *
 * Live mode is opt-in — via the Connect control, a remembered engine URL, or
 * ?engine=<url> — because the engine runs on the operator's own machine and the
 * deployed board has nothing to poll until it is pointed at one.
 */

const STORE_KEY = 'agentfirewall.engine';
const POLL_MS = 1000;

/** Current engine origin; '' means replay. Mutable — Connect/Disconnect set it. */
let engineUrl =
  new URLSearchParams(location.search).get('engine') ||
  (() => { try { return localStorage.getItem(STORE_KEY) || ''; } catch { return ''; } })();

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
  reset:      document.getElementById('resetBoard'),
  footNote:   document.getElementById('footNote'),
  form:       document.getElementById('connectForm'),
  engineIn:   document.getElementById('engineUrl'),
  connect:    document.getElementById('connectBtn'),
  disconnect: document.getElementById('disconnectBtn'),
};

const STAMP = { allow: 'Cleared', hold: 'Held', block: 'Refused' };

/** Strips currently on the board, oldest first. */
let filed = [];
let lastSeq = 0;
let live = false;
let replay = null;
let playing = false;
let pollTimer = null;

/* ------------------------------------------------------------------ render */

function esc(value) {
  return String(value ?? '').replace(/[&<>"]/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function clockOf(ts) {
  const d = new Date((ts || Date.now() / 1000) * 1000);
  return d.toLocaleTimeString([], { hour12: false });
}

function truncate(text, n) {
  return text.length > n ? text.slice(0, n) + '…' : text;
}

/** https://host/path -> host/path — the protocol is noise on a printed strip. */
function prettyDest(value) {
  const text = String(value);
  try {
    const u = new URL(text);
    return u.host + u.pathname + u.search;
  } catch {
    return text; // not a URL — a plain file path, channel name, etc.
  }
}

/**
 * A tool call's arguments read as a route, not a key/value dump: where the
 * call is going, then what it's carrying. Recognizes the destination-shaped
 * and content-shaped keys these demo tools use; anything else still shows,
 * just without pretending to be more structured than it is.
 */
const DEST_KEYS = ['url', 'path', 'channel'];
const CONTENT_KEYS = ['body', 'text', 'data'];

/**
 * A payload that is itself KEY=value pairs (env-style secrets) reads as a
 * variable dump no matter how it's wrapped. Detected, it's shown as redacted
 * name chips instead — which is also the more honest picture: the point of
 * this call being refused is that these names almost left, not their values.
 */
const SECRET_LINE = /\b([A-Z][A-Z0-9_]{2,})=(\S+)/g;

function secretChipsOf(text) {
  const names = [...text.matchAll(SECRET_LINE)].map((m) => m[1]);
  return names.length >= 2 ? names : null; // one match is likelier a stray "A=B", not a secrets block
}

/**
 * The controller's note is prose, but it is prose *about* machine things: URLs,
 * environment variable names, file paths, key literals. Left as running text
 * those read as debris dropped into the middle of a sentence — the eye can
 * neither skim past them nor land on them cleanly. Set in the strip's figure
 * face they become specimens: skippable when you're reading for the argument,
 * findable when you're reading for the evidence.
 *
 * Order matters in the alternation. A full URL has to win before the bare
 * host/path pattern gets a chance at its tail.
 */
const NOTE_TOKEN = new RegExp([
  '(https?:\\/\\/[^\\s,;)\\]]+)',                                    // 1 full URL
  '(\\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\\b)',                           // 2 ENV_VAR_NAME
  '(\\.env(?:\\.[a-z]+)?\\b|\\b[\\w/-]+\\.(?:env|pem|key|json|ya?ml|py|ts|js)\\b)', // 3 file
  '(\\b(?:sk_live|sk_test|sk_ant|xoxb|xoxp|ghp|AKIA)[A-Za-z0-9_-]*)', // 4 key literal
  '(\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)*\\.(?:io|com|net|org|sh|ru|co|dev|app)\\b(?:\\/[^\\s,;)\\]]*)?)', // 5 bare host
].join('|'), 'g');

/**
 * Render note prose with its machine tokens typeset.
 *
 * Deliberately NOT anchors: every URL in a refused note is somewhere an attacker
 * wanted data sent. Making that clickable on a security console would be a way
 * to get a reviewer to visit it by reflex.
 */
function noteMarkup(text) {
  // Em/en dashes arrive from the model set tight against the words on either
  // side, which reads as a typo at this size. Space them as a plain hyphen.
  const src = String(text || '').replace(/\s*[—–]\s*/g, ' - ');

  let out = '';
  let last = 0;
  for (const m of src.matchAll(NOTE_TOKEN)) {
    const raw = m[0];
    out += esc(src.slice(last, m.index));
    if (m[1] || m[5]) {
      out += `<span class="tok tok-dest" title="${esc(raw)}">${esc(prettyDest(raw))}</span>`;
    } else if (m[2]) {
      out += `<span class="tok tok-var">${esc(raw)}</span>`;
    } else if (m[3]) {
      out += `<span class="tok tok-file">${esc(raw)}</span>`;
    } else {
      out += `<span class="tok tok-key">${esc(raw)}</span>`;
    }
    last = m.index + raw.length;
  }
  return out + esc(src.slice(last));
}

/**
 * "Raised on" splits into a reason and, when the reason is quoted attacker text,
 * the quote itself. Running them together in one bold line makes the payload
 * look like the board's own words; setting the quote apart keeps the attribution
 * unambiguous.
 */
function evidenceMarkup(provenance) {
  const text = String(provenance || '');
  const quoted = /^injected text:\s*([\s\S]+)$/.exec(text);
  if (!quoted) {
    return `<p class="annot-source">Raised on <b>${esc(text)}</b></p>`;
  }
  return `
      <p class="annot-source">Raised on <span class="evidence-kind">injected text</span></p>
      <blockquote class="evidence">${noteMarkup(quoted[1])}</blockquote>`;
}

function routeFields(strip) {
  const args = strip.args || {};
  const destKey = DEST_KEYS.find((k) => k in args);
  const contentKey = CONTENT_KEYS.find((k) => k in args);
  const rest = Object.keys(args).filter((k) => k !== destKey && k !== contentKey);
  const asText = (v) => (typeof v === 'string' ? v : JSON.stringify(v));
  const content = contentKey ? asText(args[contentKey]) : null;
  return {
    dest: destKey ? prettyDest(args[destKey]) : null,
    content,
    secretNames: content ? secretChipsOf(content) : null,
    rest: rest.map((k) => `${k} ${truncate(asText(args[k]), 40)}`),
  };
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
      <p class="annot-body">${noteMarkup(strip.annotation || '')}</p>
      ${strip.provenance ? evidenceMarkup(strip.provenance) : ''}
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
        ${(() => {
          const { dest, content, secretNames, rest } = routeFields(strip);
          if (!dest && !content && !rest.length) return '';
          const payload = secretNames
            ? `<span class="route-secrets" title="${esc(secretNames.length)} value(s) redacted — names shown, not the values">
                ${secretNames.map((n) => `<span class="secret-chip">${esc(n)} <i>redacted</i></span>`).join('')}
              </span>`
            : content
              ? `<span class="route-payload">${esc(truncate(content, 100))}</span>`
              : '';
          return `
          <span class="route">
            ${dest ? `<span class="route-dest">→ ${esc(truncate(dest, 72))}</span>` : ''}
            ${payload}
            ${rest.length ? `<span class="route-rest">${esc(rest.join('  ·  '))}</span>` : ''}
          </span>`;
        })()}
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
  const res = await fetch(`${engineUrl}${path}`, { cache: 'no-store' });
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
    await fetch(`${engineUrl}/holds/${encodeURIComponent(holdId)}/${action}`, { method: 'POST' });
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

/* ------------------------------------------------------- source switching */

function showConnected(connected) {
  el.connect.hidden = connected;
  el.disconnect.hidden = !connected;
  el.runDemo.hidden = connected;
  el.engineIn.value = connected ? engineUrl : el.engineIn.value;
  el.engineIn.readOnly = connected;
}

/** Attach to an engine. Returns false (and stays on replay) if none answers. */
async function connectTo(url) {
  const candidate = url.trim().replace(/\/+$/, '');
  if (!candidate) return false;

  const previous = engineUrl;
  engineUrl = candidate;
  el.connect.disabled = true;
  el.connect.textContent = 'Connecting…';
  try {
    await engineGet('/health');
  } catch {
    engineUrl = previous;
    el.footNote.textContent =
      `No engine answered at ${candidate}. Is it running, and does it allow this origin?`;
    setLink('replay', 'Not connected');
    return false;
  } finally {
    el.connect.disabled = false;
    el.connect.textContent = 'Connect';
  }

  try { localStorage.setItem(STORE_KEY, engineUrl); } catch { /* private mode */ }
  live = true;
  filed = [];
  lastSeq = 0;
  render();
  showConnected(true);
  setLink('live', 'Live engine');
  el.footNote.textContent =
    'Connected. Every strip below is a real call this firewall intercepted, and clearing a held one releases it to the server.';
  await pollLive();
  clearInterval(pollTimer);
  pollTimer = setInterval(pollLive, POLL_MS);
  return true;
}

function disconnect() {
  clearInterval(pollTimer);
  pollTimer = null;
  live = false;
  engineUrl = '';
  try { localStorage.removeItem(STORE_KEY); } catch { /* private mode */ }
  showConnected(false);
  setLink('replay', 'Recorded session');
  el.footNote.textContent =
    'Replaying a recorded run. Start the engine locally and connect above to review a real agent\'s calls.';
  filed = [];
  render();
}

el.form.addEventListener('submit', (event) => {
  event.preventDefault();
  connectTo(el.engineIn.value);
});
el.disconnect.addEventListener('click', disconnect);

/* ------------------------------------------------------------------ boot */

async function boot() {
  showConnected(false);
  if (engineUrl) {
    el.engineIn.value = engineUrl;
    if (await connectTo(engineUrl)) return;
  }
  setLink('replay', 'Recorded session');
  await playReplay();
}

boot();
