"""Risk combiner — pure logic, no API calls."""
from src.pipeline.combiner import combine_risk


def test_clean_call_allows():
    risk, decision = combine_risk(injection_score=3.0, drift_score=8.0)
    assert decision == "allow"
    assert risk < 31


def test_high_injection_overrides_to_block():
    # Even if drift were modest, injection > 90 always blocks.
    risk, decision = combine_risk(injection_score=94.0, drift_score=40.0)
    assert decision == "block"


def test_high_drift_and_injection_blocks():
    risk, decision = combine_risk(injection_score=88.0, drift_score=96.7)
    assert decision == "block"
    assert risk > 71


def test_ambiguous_holds():
    risk, decision = combine_risk(injection_score=20.0, drift_score=75.0)
    assert decision == "hold"
    assert 31 <= risk <= 70


def test_reweight_excludes_missing_signals():
    # With only injection+drift present, the score is their renormalized blend,
    # NOT dragged down by absent anomaly/threat weights.
    risk, _ = combine_risk(injection_score=100.0, drift_score=100.0)
    assert risk == 100.0  # would be 65.0 if anomaly+threat counted as 0


def test_adding_cold_anomaly_changes_weighting():
    with_anomaly, _ = combine_risk(80.0, 80.0, anomaly_score=0.0)
    without_anomaly, _ = combine_risk(80.0, 80.0)
    assert with_anomaly < without_anomaly  # a 0 anomaly pulls the blend down
