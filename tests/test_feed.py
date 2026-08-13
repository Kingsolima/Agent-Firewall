"""
Offline tests for the decision-feed ring buffer.

The eviction contract is the tricky part: seq is monotonic and independent of
buffer position, so a client polling with a stale `since` that predates the
oldest buffered record must receive the whole current buffer, never nothing.
"""
from src.dashboard.events import DecisionFeed


def test_seq_is_monotonic_and_since_is_incremental():
    f = DecisionFeed(maxlen=100)
    a = f.publish({"tool": "x"})
    b = f.publish({"tool": "y"})
    assert a["seq"] == 1 and b["seq"] == 2
    assert [r["tool"] for r in f.since(0)] == ["x", "y"]
    assert [r["tool"] for r in f.since(1)] == ["y"]
    assert f.since(2) == []


def test_publish_stamps_timestamp():
    f = DecisionFeed()
    r = f.publish({"tool": "x"})
    assert isinstance(r["ts"], float) and r["ts"] > 0


def test_eviction_still_returns_current_buffer_for_stale_since():
    f = DecisionFeed(maxlen=3)
    for i in range(5):                 # seqs 1..5; buffer holds seqs 3,4,5
        f.publish({"i": i})
    # A client last saw seq 1, which has been evicted. It must get everything
    # still buffered (3,4,5), not an empty list.
    got = f.since(1)
    assert [r["seq"] for r in got] == [3, 4, 5]
    assert f.latest_seq() == 5
