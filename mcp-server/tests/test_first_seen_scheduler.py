"""Tests for the in-process scheduler that runs first-seen scans."""
from unittest.mock import MagicMock

from src.first_seen_scheduler import FirstSeenScheduler


def test_run_one_cycle_emits_one_event_per_device():
    service = MagicMock()
    service.scan_first_seen_for_all_devices.return_value = [
        {"device": "a", "new_domain_count": 0, "new_domains": []},
        {"device": "b", "new_domain_count": 3, "new_domains": ["x.com", "y.com", "z.com"]},
    ]
    heartbeat = MagicMock()

    sched = FirstSeenScheduler(
        service=service, heartbeat=heartbeat,
        interval_sec=3600, warmup_sec=0,
        recent_window="last_7d", baseline_days=90,
    )
    sched._run_one_cycle()

    service.scan_first_seen_for_all_devices.assert_called_once_with(
        recent_window="last_7d", baseline_days=90
    )
    assert heartbeat.record_first_seen.call_count == 2
    emitted_devices = [
        c.args[0]["device"] for c in heartbeat.record_first_seen.call_args_list
    ]
    assert emitted_devices == ["a", "b"]


def test_run_one_cycle_forwards_error_report():
    """Per-device errors propagate through to the heartbeat writer, which
    emits them as error-status events (so they show up in the dashboard
    like any sidecar failure)."""
    service = MagicMock()
    service.scan_first_seen_for_all_devices.return_value = [
        {"device": "good", "new_domain_count": 0, "new_domains": []},
        {"device": "broken", "error": "ValueError: boom"},
    ]
    heartbeat = MagicMock()

    sched = FirstSeenScheduler(
        service=service, heartbeat=heartbeat,
        interval_sec=3600, warmup_sec=0,
    )
    sched._run_one_cycle()

    assert heartbeat.record_first_seen.call_count == 2
    last = heartbeat.record_first_seen.call_args_list[1].args[0]
    assert last == {"device": "broken", "error": "ValueError: boom"}
