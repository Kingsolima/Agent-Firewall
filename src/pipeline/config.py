"""
Tunable constants for the reasoning engine. One place to adjust scoring so the
demo numbers and thresholds aren't scattered across modules.
"""
import os

# Claude model for all reasoning calls. These are structured classification /
# extraction tasks (injection, intent, drift) where haiku-4-5 is fast AND
# accurate — critical for the <4s proxy budget. Live testing: haiku scored the
# demo attack 99/100 and a clean call 3/100, faster than sonnet. Override via
# env (e.g. claude-sonnet-4-6) if a component needs more reasoning depth.
MODEL = os.getenv("PIPELINE_MODEL", "claude-haiku-4-5")

# Timeouts. The TOTAL budget is enforced by the proxy (src/proxy/omar_client.py),
# which fail-safe BLOCKs if the pipeline doesn't answer in time — we don't
# duplicate a total cap here. This is the per-component safety net for a hung
# call: a healthy warm Claude call is ~1s; 6s catches a genuinely stuck one
# without killing a slow-but-fine one.
STAGE_TIMEOUT_SECONDS = float(os.getenv("STAGE_TIMEOUT_SECONDS", "6.0"))

# Risk weights (docs.md §Risk Combiner). Anomaly + threat are Phase 2/3 and are
# absent in Phase 1 — the combiner reweights across whatever signals are present,
# so a missing signal never silently drags the score down.
WEIGHTS = {
    "injection": 0.35,
    "drift": 0.30,
    "anomaly": 0.25,
    "threat": 0.10,
}

# Decision thresholds.
#
# History, because the reasoning matters more than the number:
#
# This was briefly lowered 30 -> 20 on a DOMINANCE argument from
# `python -m evals.threshold_sweep`: on the 42-case set, a cut at 18-20 caught
# three more attacks for exactly the same false-positive count, so 30 was giving
# up recall and buying nothing.
#
# That argument did NOT survive the dataset growing to 504 cases. It was an
# artifact of 19 negatives, where a single case moves FPR by five points. On the
# larger set the two settings are close to indistinguishable:
#
#     dev      t=20  recall 0.89  FPR 0.15  acc 0.86
#     dev      t=30  recall 0.82  FPR 0.13  acc 0.86
#     heldout  t=20  recall 0.86  FPR 0.10  acc 0.88
#     heldout  t=30  recall 0.86  FPR 0.08  acc 0.89
#
# On dev, the split we are entitled to tune against, they tie on accuracy and
# simply trade recall for FPR: the data does not choose. So this is a POLICY
# choice, not a measured one, and 30 is chosen because holding a plainly benign
# first-turn file read is the failure mode that costs a user's trust fastest.
#
# Stated plainly so nobody mistakes it for evidence: 30 also happens to be the
# value the recorded demo reads best at. That is not why it is defensible; it is
# defensible because no measurement separates it from 20. Revisit when real
# traffic replaces the synthetic negatives (see evals/README.md).
ALLOW_MAX = float(os.getenv("ALLOW_MAX", "30.0"))   # 0-30  -> allow
HOLD_MAX = 70.0    # 31-70 -> hold ; 71-100 -> block

# Override: an unambiguous injection always BLOCKs regardless of the blended score.
INJECTION_OVERRIDE_THRESHOLD = 90.0

# Raw (pre-source-trust) injection likelihood at/above which we call it "detected".
INJECTION_DETECTION_THRESHOLD = 50.0

# How long a session's extracted intent stays valid (docs.md: 24h TTL).
INTENT_TTL_HOURS = 24

# Source trust (docs.md §Prompt Injection Detector, Layer 3). Lower trust ->
# we discount the injection signal less (external/unknown senders are the real
# attack surface); a trusted internal sender dampens it. confidence is divided
# by (trust + offset): internal /1.6, external_dm /1.0, unknown /0.8.
SOURCE_TRUST = {"internal": 0.9, "external_dm": 0.3, "unknown": 0.1}
TRUST_OFFSET = 0.7

# A regex signature hit is strong evidence on its own — floor the injection
# confidence so a known attack from an untrusted source clears the override.
REGEX_CONFIDENCE_FLOOR = 95.0

# Conservative defaults when a component fails or times out (graceful degradation).
DEFAULT_DRIFT_NO_INTENT = 50.0   # docs.md: missing intent object -> drift 50
