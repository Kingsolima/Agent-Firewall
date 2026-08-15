<!-- impeccable:product-schema v1 -->

# Product

Agent Firewall — an in-line security proxy for the Model Context Protocol that
judges every tool call an AI agent attempts against what the user actually asked
for.

## Platform

web

## Stack

Python 3.11 (CI) / 3.13 (dev) · FastAPI + Uvicorn · Pydantic v2 · asyncio ·
Anthropic Claude (`claude-haiku-4-5`) for all reasoning · Supabase/Postgres for
the audit log · Backboard for durable session memory · httpx. The MCP proxy is a
stdio JSON-RPC man-in-the-middle spawned by the host. The dashboard is currently
a single vanilla-JS HTML file served same-origin by the engine; it is being
rebuilt and deployed separately to Vercel.

## Users

- **Developers running AI agents** through an MCP host (Claude Desktop, Kiro)
  who have given the agent access to real tools — files, databases, messaging.
- **Engineers evaluating the tool**, who care how it works, what it costs them
  in latency, and whether it false-positives on their real work.
- **Hackathon judges**, arriving cold with no setup and roughly a minute.

## Product Purpose

An agent reads text from many sources — a file, a web page, a pull-request
comment — and cannot tell instructions it was given from data it was asked to
look at. An attacker never talks to the agent: they plant text where it will be
read. Agent Firewall intercepts each tool call before it executes and asks
whether the action still follows from the user's original request.

## Positioning

Not a blocklist. Conventional guardrails ask "is this action on a list of
forbidden things?"; Agent Firewall asks "is this action consistent with what the
user actually wanted?" Posting a message to a channel is not inherently an
attack — it is the wrong thing to do if what you asked for was a formatting review.

## Operating Context

Runs inline between an MCP host and MCP servers, at the infrastructure layer: no
agent code changes, no modified prompts, no SDK to adopt. Two services so the
slow LLM-bound reasoning path can never stall the proxy's fast path. The
reasoning engine is unreachable → the proxy **blocks**; a security layer that
fails open is decoration.

## Capabilities and Constraints

Capabilities: transparent JSON-RPC passthrough · `tools/call` interception with
allow / hold / block · injection detection (regex + semantic + source trust) ·
intent extraction and drift scoring · plain-English counterfactuals · cross-turn
taint (poison read on an earlier turn is in view for the action it induces) ·
`tools/list` tool-poisoning scan · human hold with approve/deny · durable
session memory that survives a restart.

Constraints: ~8.4 s to score one call — real agent loops make dozens. The
anomaly detector and PII tokenizer are **not built** and are reported as such.
Vercel is serverless, so the in-process decision feed and hold registry cannot
run there; the deployed page therefore replays a recorded run by default and
switches to live when an engine is reachable.

## Brand Commitments

The decision vocabulary is fixed product language: **allow / hold / block**, and
a 0–100 risk score. Live approve/deny against a running engine must keep
working. Everything visual is replaceable.

## Evidence on Hand

A 42-case evaluation across six categories, run against a 39-pattern signature
baseline and an ablation with intent-drift disabled (`evals/results.md`).
Headline: recall 0.83 vs 0.61 for the baseline; on the `ambiguous` category the
firewall scores 4/7 while both the baseline and the ablation score **0/7**.
False-positive rate is honestly *worse* than the baseline (0.21 vs 0.16). 47
offline tests. Sample is small and self-authored; single-case deltas are noise.

## Product Principles

- Fail closed. An unavailable analyzer is a red flag, never tacit approval.
- Explain, don't error. A block returns a counterfactual a developer can
  adjudicate, not `Error 403: policy_v2`.
- Derived facts only. Durable memory stores intent and findings, never raw tool
  output or secret values.
- Report honestly. Unbuilt components and unflattering numbers are stated, not
  filtered.

## Accessibility & Inclusion

Decision state must never be carried by color alone — allow / hold / block need
a non-color signal. The console is read for long sessions on a desk display;
contrast and legibility at screen-record zoom are requirements, not polish.
