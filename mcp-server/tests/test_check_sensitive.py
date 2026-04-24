"""Self-test for scripts/check_sensitive.py — ensures the regex deny-list
actually catches every identifier class it claims to block."""
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import check_sensitive  # noqa: E402


# One representative sample per rule — if any class regresses, this fails.
SAMPLES = {
    "home-lan-24":                  "agent ip 192.168.168.17 joined",
    "device-name:theblacksilence":  "scan theblacksilence for new domains",
    "device-name:The-Pinky":        "The-Pinky saw a new connection",
    "device-name:Ne7csg":           "bucket Ne7csg had 10 alarms",
    "device-name:StunningBanana":   "StunningBanana is an iPad",
    "first-name:Yassir":            "Yassir's iPad just joined",
    "windows-user-path":            r'"C:\Users\yasir\AppData\Local\app.exe":',
    "linux-home-path":              "cd /home/yasir/firewalla-wazuh",
    "user-ref":                     '"agent": {"user": "yasir"}',
    "email":                        "ping yasirhamza@gmail.com",
    "investigation-domain:rapidshare":  "contact klk.rapidshare.cc",
    "investigation-domain:4pjoxehw":    "weird domain 4pjoxehw.com",
}


def test_every_rule_matches_at_least_one_sample():
    """Every rule must fire on its canonical example."""
    for label, _ in check_sensitive.RULES:
        assert label in SAMPLES, f"no sample for rule {label!r}"

    hit_labels = {label for label, pat in check_sensitive.RULES
                  for sample_label, sample_text in SAMPLES.items()
                  if sample_label == label and pat.search(sample_text)}
    missing = {label for label, _ in check_sensitive.RULES} - hit_labels
    assert not missing, f"rules that don't match their canonical sample: {missing}"


def test_generic_placeholders_do_not_match():
    """Generic tokens used in sanitized tests/docs must stay allowed."""
    safe_strings = [
        "demo-device scanned successfully",
        "kids-laptop is in the baseline",
        "host-a, host-b, host-c, host-d are all online",
        "10.0.0.5 is a test-net address",
        "192.0.2.50 is TEST-NET-1",
        "cd /path/to/firewalla-wazuh",
        r'"C:\Users\alice\AppData\Local\app.exe":',
        "contact foo.example.com and bar.example.com",
        '"user": "alice"',
    ]
    for s in safe_strings:
        hits = [label for label, pat in check_sensitive.RULES if pat.search(s)]
        assert not hits, f"false positive — {hits!r} matched {s!r}"


def test_scanner_returns_nonzero_on_real_repo_when_seeded(tmp_path, monkeypatch):
    """End-to-end: plant a bad string and verify scan() catches it."""
    bad = tmp_path / "leak.txt"
    bad.write_text("device theblacksilence contacted 192.168.168.17\n")
    monkeypatch.setattr(check_sensitive, "REPO_ROOT", tmp_path)
    findings = check_sensitive.scan([Path("leak.txt")])
    assert len(findings) == 2
    labels = {f[2] for f in findings}
    assert "device-name:theblacksilence" in labels
    assert "home-lan-24" in labels
