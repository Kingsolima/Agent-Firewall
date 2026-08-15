# Agent Firewall — Status & Command Cheatsheet

_Snapshot for the CUTC Transform build. Branch: `feat/mcp-proxy` (all work pushed to origin)._

## Where the project is

| Day | Phase | State |
|---|---|---|
| Sun | MCP stdio proxy — transparent passthrough | ✅ done, tested, pushed |
| Mon | Intercept `tools/call`, block the exfil attack, `tools/list` scan | ✅ done, tested, pushed |
| Tue | Hold engine + audit wiring + multi-turn escalation evals | ✅ done, tested, pushed |
| Wed | Live security-console dashboard + intent-store backend seam | ✅ done, verified live, pushed |
| Thu | Backboard durable-memory backend + durability/privacy demo beats | ⏳ next |
| Fri | Eval + baseline + ablation table · then start video + README | ⏳ |
| Sat | Finish video + Devpost story, submit with buffer (deadline 12 PM) | ⏳ |

**Working end-to-end today:** benign call ALLOWED · single-turn exfil BLOCKED with a plain-English counterfactual · multi-turn drift escalates ALLOW→HOLD · dashboard shows it live · approve/deny releases a parked call. **40/40 offline tests pass.**

**Open items:**
- Supabase project is **paused** → the historical audit panel is empty until you un-pause it. The live console does **not** need it (runs on the in-memory backend).
- Taint **rehydrate-on-restart** (for the kill-and-restart durability demo) lands with the Backboard backend Thursday.

---

## Remaining plan (Thu → Sat)

_Guiding rule: Backboard is additive, not load-bearing. The eval table and the story/video are what decide placement — protect them. Don't let Backboard or a deploy eat into them._

### Thursday — Backboard backend + hardening
- **2:00 PM** — attend the Backboard.io workshop (Moe). Confirm exact SDK signatures (`POST /threads/messages`, thread creation, manual-memory CRUD, `X-API-Key`) **before** writing against field names.
- **`FIREWALL_MEMORY_BACKEND=backboard`** in `src/pipeline/intent_store.py`, behind the existing seam:
  - create-or-reuse one thread per `session_id`; write the **armed intent** as the opening entry.
  - append **derived taint summaries only** (never raw tool content / secrets) as **fire-and-forget** calls after each decision — off the hot path. Reasoning stays local; Backboard never gates a decision.
  - **taint rehydrate-on-restart**: on proxy/engine restart, reload the session's intent + taint from Backboard so `SessionState` isn't empty. This is what makes the durability demo actually block.
- **Two demo beats:**
  - **Durability** — arm a session, run poison→exfil partway, kill the proxy, restart, re-run the exfil → still BLOCKED (state came back from Backboard).
  - **Privacy** — open the Backboard dashboard, show stored content = intent + derived facts, **zero secret values**.
- **`config_helper.py`** (one-command onboarding) — only if it's free.
- **Hard checkpoint (EOD):** if Backboard is fighting you, drop to `FIREWALL_MEMORY_BACKEND=memory` and move on. Freeze non-eval feature work.

### Friday — eval rigor (AM) → start packaging (PM)
_This is the heaviest-weighted judging criterion (Technical Execution 35–45%). It gets the day._
- **AM — the numbers:**
  - signature/regex **baseline scorer** (~30–40 patterns: instruction-override, exfil-instruction, prompt markers, secret-key DLP).
  - expand `evals/cases.py` to **~50 cases across 6 categories**: benign, benign-but-scary (the false-positive test), single-call injection, cross-turn taint (largest bucket, routed through real sequences), tool-poisoning, ambiguous.
  - **ablation flag** (taint/drift disabled). Run all three — firewall / baseline / ablation — through the runner → **confusion matrix + precision/recall/FPR/F1/latency** table to JSON + Markdown for the README.
- **PM — start the story while the demo is fresh:** begin the **demo video** recording and the **README rewrite** (MCP-first, kill remaining Slack framing). **Railway deploy is stretch** — only if the AM eval work finished clean; a live "Try it out" URL is nice, not required.

### Saturday AM — finish & submit (deadline 12:00 PM EDT)
_Nothing first-drafted here — only finishing._
- Finish the **demo video** — one arc: arm intent → benign read (green) → exfil attempt (red, counterfactual + provenance visible) → same attack through the baseline waved through → flash the eval table → approve a held call, watch it resume. One-liner in the first 10 seconds.
- Finish the **Devpost story** (victim-first hook → what it does → how it works → eval table → privacy/trust boundary → "doesn't cry wolf" → war stories → what's next → Built With: name Claude + Backboard). Cross-check README and Devpost say the same thing.
- **Submit with buffer (~10 AM).** Confirm Luma deadline/timezone. If deployed, confirm the URL still works.

**Cut order if Thursday slips:** per-agent baseline (Backboard Option B) → durability beat (keep privacy beat if manual-memory writes work) → fall back to `memory` backend entirely. None of that touches Friday's eval or Saturday's story — the two things that decide placement.

---

## Commands (PowerShell — your default shell)

> The reasoning engine needs `ANTHROPIC_API_KEY` in `.env`. Run everything from the repo root:
> `cd C:\Users\King_SO\Agent-Firewall-1`

### 1. Where am I? (git)
```powershell
git log --oneline -6            # recent commits
git status --short              # uncommitted changes
git branch --show-current       # should be feat/mcp-proxy
git log origin/feat/mcp-proxy..HEAD --oneline   # unpushed commits (empty = in sync)
```

### 2. Run the tests (no API keys needed — all offline)
```powershell
python -m pytest tests/ -q                       # full suite (expect 40 passed)
python -m pytest tests/test_holds.py -v          # hold engine only
python -m pytest tests/test_proxy_passthrough.py -v   # proxy protocol integrity
```

### 3. Start the reasoning engine (needed for the demo + dashboard)
```powershell
$env:FIREWALL_MEMORY_BACKEND = "memory"          # runs without Supabase
python -m uvicorn src.pipeline.app:pipeline_api --port 8001
```
Leave this running in its own terminal. Health check (new terminal):
```powershell
curl.exe -s http://localhost:8001/health
```

### 4. Open the dashboard
With the engine running, open in a browser:
```
http://localhost:8001/
```
Then click **▶ Run demo** (bottom-right) to light up the feed — or run the demo manually (below).

### 5. Run the attack demo (benign ALLOW + exfil BLOCK)
Engine must be running. New terminal:
```powershell
python demo/run_demo.py
```
Expect: `read_file` ALLOWED, `http_post` BLOCKED with a counterfactual, `RESULT: both PASS`.

### 6. Run the eval suites (live — uses Claude, costs a little)
```powershell
python -m evals.run          # 30-case single-turn suite (clean/attack/ambiguous)
python -m evals.multiturn    # multi-turn Crescendo escalation (ALLOW -> HOLD)
```

### 6b. Backboard durable memory (Thursday)
Needs `BACKBOARD_API_KEY` in `.env`. Run the engine on the backboard backend:
```powershell
$env:FIREWALL_MEMORY_BACKEND = "backboard"
python -m uvicorn src.pipeline.app:pipeline_api --port 8001
```
**Durability beat** — kill the proxy mid-session; the firewall still remembers:
```powershell
python demo/run_demo.py --durability
```
It self-verifies: it checks that taint was actually rehydrated and reports
**INCONCLUSIVE** (not PASS) if the block could have come from engine-side state
or the fail-safe path. For a *true* test, restart the **engine** between phases too.

**Privacy beat** — show what is persisted, and that no secrets are:
```powershell
python demo/show_memory.py                 # all firewall memories + secret scan
python demo/show_memory.py <session_id>    # one session
```

### 7. Poke the engine directly (curl)
```powershell
# Score a clean call (expect allow, low risk)
curl.exe -s -X POST http://localhost:8001/intercept -H "content-type: application/json" -d "{\"tool_name\":\"database_read\",\"tool_input\":{\"customer_id\":\"1234\"},\"session_id\":\"s1\",\"agent_id\":\"a1\",\"workspace_id\":\"w1\",\"trigger_source\":\"internal\",\"message_context\":\"look up customer 1234\"}"

# Arm a session with an intent, then everything on that session is judged against it
curl.exe -s -X POST http://localhost:8001/session/register -H "content-type: application/json" -d "{\"session_id\":\"s_demo\",\"agent\":\"filesystem\"}"
curl.exe -s -X POST http://localhost:8001/session/arm -H "content-type: application/json" -d "{\"session_id\":\"s_demo\",\"intent\":\"review the PR for formatting only\"}"

curl.exe -s http://localhost:8001/sessions    # registered/armed sessions
curl.exe -s http://localhost:8001/feed        # full decision feed
curl.exe -s http://localhost:8001/holds       # calls parked awaiting approval
```

### 8. Stop the engine
`Ctrl+C` in the engine terminal.

---

## Bash equivalents (Git Bash tool)
Same commands; only the env var and `curl` differ:
```bash
FIREWALL_MEMORY_BACKEND=memory python -m uvicorn src.pipeline.app:pipeline_api --port 8001
curl -s http://localhost:8001/health           # plain 'curl', not curl.exe
```

## Key files
- Proxy: `src/proxy/mcp_proxy.py` · engine: `src/pipeline/app.py` · dashboard: `src/dashboard/`
- Intent backend seam: `src/pipeline/intent_store.py` (`FIREWALL_MEMORY_BACKEND=memory|supabase|backboard`)
- Demo: `demo/run_demo.py` · plan: `~/.claude/plans/backboard-has-free-credits-delightful-bonbon.md`
