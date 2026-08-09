"""
Agent Firewall — AI Security Reasoning Engine (Omar).

The "brain" the proxy calls over HTTP. Replaces the Day-1 mock pipeline with
real Claude-powered analysis. Exposes POST /analyze (see src/pipeline/app.py).

Phase 1 (SPINE) components:
  - injection detection   (regex signatures + Claude semantic + source trust)
  - intent extraction     (Claude, persisted in Supabase intent_store)
  - drift scoring         (Claude semantic comparison)
  - risk combination      (weighted, with cold-signal reweighting + overrides)
  - counterfactual        (Claude, plain-English admin explanation)

Phase 2 (DEPTH, not built yet): anomaly detector, eval harness.
Phase 3 (GARNISH): tokenization vault, threat intel, embedding drift.
"""
