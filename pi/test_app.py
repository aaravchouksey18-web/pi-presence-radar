"""Minimal tests for the aggregator's dedup rule and liveness windows.

Run from pi/:  python -m pytest test_app.py
The module now only starts its MQTT thread under `__main__`, so importing
it here is side-effect free.
"""

import app as aggregator


def reset():
    aggregator.devices.clear()
    aggregator.boards.clear()


def test_sighting_creates_and_dedups(monkeypatch):
    reset()
    t0 = 1_000_000.0
    monkeypatch.setattr(aggregator, "_now", lambda: t0)
    aggregator.record_sighting("a", "aa:bb:cc:00:00:01", "home-ssid")
    assert len(aggregator.devices) == 1

    # re-report 60 s later: same device, refreshed last_seen, not a dupe
    monkeypatch.setattr(aggregator, "_now", lambda: t0 + 60)
    aggregator.record_sighting("a", "aa:bb:cc:00:00:01", "")
    assert len(aggregator.devices) == 1
    d = aggregator.devices["aa:bb:cc:00:00:01"]
    assert d["last_seen"] == t0 + 60
    assert d["ssid"] == "home-ssid"      # first-seen ssid sticks


def test_heard_by_counts_distinct_boards(monkeypatch):
    reset()
    monkeypatch.setattr(aggregator, "_now", lambda: 2_000_000.0)
    aggregator.record_sighting("a", "aa:bb:cc:00:00:02", "")
    aggregator.record_sighting("b", "aa:bb:cc:00:00:02", "")
    d = aggregator.devices["aa:bb:cc:00:00:02"]
    assert sorted(d["boards"]) == ["a", "b"]

    # the same board re-reporting does not add a second entry
    aggregator.record_sighting("b", "aa:bb:cc:00:00:02", "")
    assert sorted(d["boards"]) == ["a", "b"]

    # and the API reports it as heard by both sniffers
    client = aggregator.app.test_client()
    dev = client.get("/api/who").get_json()["devices"][0]
    assert dev["heard_by"] == 2
    assert dev["boards"] == ["a", "b"]


def test_board_alive_window(monkeypatch):
    reset()
    clock = {"t": 0.0}
    monkeypatch.setattr(aggregator, "_now", lambda: clock["t"])
    aggregator.record_online("a", True)          # proof at t=0
    clock["t"] = aggregator.ONLINE_S - 1
    assert aggregator.board_alive("a")
    clock["t"] = aggregator.ONLINE_S + 1
    assert not aggregator.board_alive("a")


def test_api_who_respects_home_window(monkeypatch):
    reset()
    clock = {"t": 1_000_000.0}
    monkeypatch.setattr(aggregator, "_now", lambda: clock["t"])
    aggregator.record_sighting("a", "aa:bb:cc:00:00:03", "")

    client = aggregator.app.test_client()
    clock["t"] += aggregator.HOME_S - 10
    r = client.get("/api/who")
    assert r.status_code == 200
    assert len(r.get_json()["devices"]) == 1

    clock["t"] += 30                            # beyond HOME_S now
    r = client.get("/api/who")
    assert len(r.get_json()["devices"]) == 0