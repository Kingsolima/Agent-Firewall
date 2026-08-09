"""
Anomaly Detection System — Phase 2 (docs.md §5 Anomaly Detection System).

>>> HANDED OFF: this whole file is yours to implement. <<<
Omar owns the interface (the two function signatures below) and the wiring into
the orchestrator/combiner. You own everything else in this file.

WHAT IT DOES
  Catches attacks that look semantically legitimate but are behaviorally
  abnormal for THIS agent — a tool it has never used, or a normal action at
  100x its usual data volume. This is a third, independent signal on top of
  injection + drift.

SAFETY / LOW PRESSURE
  The risk combiner already reweights when anomaly is absent, so your component
  is *corroborating evidence*, not the block trigger. If it's late, cold, or
  rough, the demo still blocks the attack on injection + drift alone. Build it
  well, but nothing breaks if it isn't perfect.

THE FIVE SIGNALS (per-agent behavioral baseline)
  1. call_frequency   — calls per hour (mean + std dev)
  2. tool_distribution— % of calls per tool type
  3. data_volume      — bytes read/written per call (mean + std dev)
  4. trigger_source   — % internal vs external
  5. call_sequence    — most common tool ordering

Z-SCORE
  z = abs((observed - baseline_mean) / baseline_std_dev)

COMPOSITE ANOMALY SCORE (normalized to 0-100)
  data_volume 35% + call_frequency 35% + tool_distribution 20% + trigger_source 10%
  (call_sequence is tracked but not in the composite weights, per docs.)

BASELINE UPDATES
  Welford's online algorithm, applied ONLY after an ALLOWED call — never after a
  blocked call (prevents an attacker from poisoning the baseline).

COLD START PHASES
  learning  0–50    calls : no detection, log only  (return 0.0)
  warming   50–200  calls : detection on, relaxed threshold z = 5
  active    200+    calls : full detection, threshold z = 3

STORAGE
  Table `agent_baselines` ALREADY EXISTS (Ahmed's migration —
  supabase/migrations/001_initial_schema.sql). Read/write it; do NOT recreate
  it. Reuse the shared client: `from src.db.client import get_client`.
  Mirror the pattern in src/pipeline/intent_store.py.

DONE WHEN
  - The demo agent has a seeded ~300-call baseline (see docs Side Notes,
    Problem 2 — run synthetic calls through update_baseline so the stats are
    REAL, not faked).
  - The demo http_post attack produces a high z-score (unseen tool + huge
    volume) -> composite anomaly ~90+.
  - Unit tests pass (see tests/ for the pattern).
"""
from src.models import AnomalySignals, ToolCallRequest

# --- Cold-start thresholds (docs §Cold start phases) ---
LEARNING_MAX_CALLS = 50
WARMING_MAX_CALLS = 200
WARMING_Z_THRESHOLD = 5.0
ACTIVE_Z_THRESHOLD = 3.0

# --- Composite weights (docs §Composite anomaly score). Sum = 1.0 ---
COMPOSITE_WEIGHTS = {
    "data_volume": 0.35,
    "call_frequency": 0.35,
    "tool_distribution": 0.20,
    "trigger_source": 0.10,
}


def z_score(observed: float, mean: float, std_dev: float) -> float:
    """z = |observed - mean| / std_dev. Guard std_dev == 0 (no variance yet)."""
    if std_dev == 0:
        return 0.0
    return abs((observed - mean) / std_dev)


async def compute_anomaly(request: ToolCallRequest) -> tuple[float, AnomalySignals]:
    """
    Return (anomaly_score 0-100, per-signal z-scores).

    TODO (yours):
      1. Load this agent's baseline row from `agent_baselines` (by agent_id).
      2. Cold start: if call_count < LEARNING_MAX_CALLS -> return (0.0, AnomalySignals()).
      3. Compute the observed value for each of the 5 signals from `request`
         (+ recent history for frequency/sequence).
      4. z-score each signal vs the baseline mean/std (use z_score()).
      5. Blend into a composite using COMPOSITE_WEIGHTS, normalize to 0-100.
      6. Return the composite + the per-signal z-scores in AnomalySignals.

    Until implemented, returns a safe neutral default so wiring it in early is
    harmless.
    """
    # TODO: implement. Safe placeholder for now:
    return 0.0, AnomalySignals()


def update_baseline(request: ToolCallRequest) -> None:
    """
    Welford online update of this agent's baseline. Call ONLY after an ALLOWED
    call — never on a blocked one (baseline-poisoning defense).

    TODO (yours):
      1. Load the agent_baselines row (create it if this is the first call).
      2. Welford-update running mean + M2 (std dev) for data_volume and
         call_frequency; update tool_distribution / trigger_source rates and
         call_sequence.
      3. Increment call_count and roll the baseline_phase
         (learning -> warming -> active) at the thresholds above.
      4. Persist back to agent_baselines.
    """
    # TODO: implement.
    return None
