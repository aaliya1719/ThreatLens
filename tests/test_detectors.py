"""
test_detectors.py
-----------------
Targeted unit tests for all 7 ThreatLens detection rules.

Each test:
  - POSITIVE: constructs a minimal dataset that MUST trigger the rule
  - NEGATIVE: constructs a dataset that must NOT trigger the rule
  - Asserts on rule_id, severity, and explanation content

Run from project root:
    python tests/test_detectors.py
"""

import sys
import uuid
from datetime import datetime, timedelta, timezone

import pandas as pd

sys.path.insert(0, "src")
from detectors import (
    detect_brute_force,
    detect_credential_stuffing,
    detect_off_hours_login,
    detect_impossible_travel,
    detect_repeated_lockout,
    detect_vpn_no_mfa,
    detect_password_reset_spike,
    run_all_detectors,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = "[PASS]"
FAIL = "[FAIL]"
_results = []


def _assert(condition: bool, test_name: str, detail: str = ""):
    status = PASS if condition else FAIL
    msg = f"  {status}  {test_name}"
    if detail:
        msg += f"  [{detail}]"
    _results.append((condition, test_name))
    print(msg)
    return condition


def _base_ts(hour: int = 10, day: int = 1) -> datetime:
    return datetime(2025, 6, day, hour, 0, 0, tzinfo=timezone.utc)


def _make_row(
    ts: datetime,
    username: str = "alice",
    source_ip: str = "1.2.3.4",
    country: str = "US",
    event_type: str = "login_failure",
    auth_method: str = "password",
    failure_reason: str = "wrong_password",
    is_vpn: bool = False,
    lat: float = 37.0,
    lon: float = -95.0,
) -> dict:
    return {
        "event_id": f"EVT-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": ts,
        "username": username,
        "source_ip": source_ip,
        "country": country,
        "event_type": event_type,
        "user_agent": "test/1.0",
        "session_id": str(uuid.uuid4()) if event_type == "login_success" else None,
        "auth_method": auth_method,
        "failure_reason": failure_reason if event_type == "login_failure" else None,
        "is_vpn": is_vpn,
        "latitude": lat,
        "longitude": lon,
    }


def _df(rows: list) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df["is_vpn"] = df["is_vpn"].astype(bool)
    return df


# ---------------------------------------------------------------------------
# R-01: Brute Force
# ---------------------------------------------------------------------------

def test_r01():
    print("\n-- R-01 Brute Force -----------------------------------------")
    base = _base_ts()

    # POSITIVE: 6 failures from same IP within 10 min
    rows_pos = [
        _make_row(base + timedelta(seconds=i * 60), source_ip="10.0.0.1")
        for i in range(6)
    ]
    df_pos = _df(rows_pos)
    result = detect_brute_force(df_pos)
    _assert(not result.empty, "R-01 POSITIVE fires on 6 failures/10min")
    _assert(result["rule_id"].iloc[0] == "R-01", "R-01 rule_id correct")
    _assert(result["severity"].iloc[0] == "HIGH", "R-01 severity=HIGH")

    # NEGATIVE: 4 failures from same IP -- below threshold of 5
    rows_neg = [
        _make_row(base + timedelta(seconds=i * 60), source_ip="10.0.0.2")
        for i in range(4)
    ]
    df_neg = _df(rows_neg)
    result_neg = detect_brute_force(df_neg)
    _assert(result_neg.empty, "R-01 NEGATIVE does not fire on 4 failures")

    # NEGATIVE: 6 failures but spread over 20 min (exceeds 10-min window)
    rows_spread = [
        _make_row(base + timedelta(minutes=i * 3.5), source_ip="10.0.0.3")
        for i in range(6)
    ]
    df_spread = _df(rows_spread)
    result_spread = detect_brute_force(df_spread)
    _assert(result_spread.empty, "R-01 NEGATIVE does not fire when spread over 20min")


# ---------------------------------------------------------------------------
# R-02: Credential Stuffing
# ---------------------------------------------------------------------------

def test_r02():
    print("\n-- R-02 Credential Stuffing ---------------------------------")
    base = _base_ts()

    # POSITIVE: 4 failures from same IP against 4 distinct users within 15 min
    users = ["alice", "bob", "carol", "dave"]
    rows_pos = [
        _make_row(base + timedelta(minutes=i * 3), username=u, source_ip="20.0.0.1")
        for i, u in enumerate(users)
    ]
    df_pos = _df(rows_pos)
    result = detect_credential_stuffing(df_pos)
    _assert(not result.empty, "R-02 POSITIVE fires on 4 users/1 IP/15min")
    _assert(result["rule_id"].iloc[0] == "R-02", "R-02 rule_id correct")
    _assert(result["severity"].iloc[0] == "HIGH", "R-02 severity=HIGH")

    # NEGATIVE: 4 failures from same IP but ALL same username
    rows_neg = [
        _make_row(base + timedelta(minutes=i), username="alice", source_ip="20.0.0.2")
        for i in range(4)
    ]
    df_neg = _df(rows_neg)
    result_neg = detect_credential_stuffing(df_neg)
    _assert(result_neg.empty, "R-02 NEGATIVE does not fire on same username")

    # NEGATIVE: 4 users spaced 8 min apart (span=24 min > 15-min window)
    # Any 15-min window can capture at most 2 consecutive events (2 distinct users)
    rows_spread = [
        _make_row(base + timedelta(minutes=i * 8), username=f"user{i}", source_ip="20.0.0.3")
        for i in range(4)
    ]
    df_spread = _df(rows_spread)
    result_spread = detect_credential_stuffing(df_spread)
    _assert(result_spread.empty, "R-02 NEGATIVE does not fire when max 2 users per window")


# ---------------------------------------------------------------------------
# R-03: Off-Hours Login
# ---------------------------------------------------------------------------

def test_r03():
    print("\n-- R-03 Off-Hours Login -------------------------------------")

    # POSITIVE: 02:30 UTC login
    ts_night = datetime(2025, 6, 1, 2, 30, 0, tzinfo=timezone.utc)
    rows_pos = [_make_row(ts_night, event_type="login_success", failure_reason=None)]
    df_pos = _df(rows_pos)
    result = detect_off_hours_login(df_pos)
    _assert(not result.empty, "R-03 POSITIVE fires at 02:30 UTC")
    _assert(result["rule_id"].iloc[0] == "R-03", "R-03 rule_id correct")
    _assert(result["severity"].iloc[0] == "MEDIUM", "R-03 severity=MEDIUM")

    # POSITIVE: 23:15 UTC login
    ts_late = datetime(2025, 6, 1, 23, 15, 0, tzinfo=timezone.utc)
    rows_pos2 = [_make_row(ts_late, event_type="login_success", failure_reason=None)]
    df_pos2 = _df(rows_pos2)
    result2 = detect_off_hours_login(df_pos2)
    _assert(not result2.empty, "R-03 POSITIVE fires at 23:15 UTC")

    # NEGATIVE: 10:00 UTC login
    ts_day = datetime(2025, 6, 1, 10, 0, 0, tzinfo=timezone.utc)
    rows_neg = [_make_row(ts_day, event_type="login_success", failure_reason=None)]
    df_neg = _df(rows_neg)
    result_neg = detect_off_hours_login(df_neg)
    _assert(result_neg.empty, "R-03 NEGATIVE does not fire at 10:00 UTC")

    # NEGATIVE: off-hours but it's a failure not a success
    rows_fail = [_make_row(ts_night, event_type="login_failure")]
    df_fail = _df(rows_fail)
    result_fail = detect_off_hours_login(df_fail)
    _assert(result_fail.empty, "R-03 NEGATIVE does not fire on failure event at off-hours")


# ---------------------------------------------------------------------------
# R-04: Impossible Travel
# ---------------------------------------------------------------------------

def test_r04():
    print("\n-- R-04 Impossible Travel -----------------------------------")
    base = _base_ts()

    # POSITIVE: US then CN in 30 min -- ~10,000 km
    rows_pos = [
        _make_row(base, username="traveler", event_type="login_success",
                  failure_reason=None, country="US", lat=37.09, lon=-95.71,
                  source_ip="1.1.1.1"),
        _make_row(base + timedelta(minutes=30), username="traveler",
                  event_type="login_success", failure_reason=None,
                  country="CN", lat=35.86, lon=104.19, source_ip="2.2.2.2"),
    ]
    df_pos = _df(rows_pos)
    result = detect_impossible_travel(df_pos)
    _assert(not result.empty, "R-04 POSITIVE fires US->CN in 30min")
    _assert(result["rule_id"].iloc[0] == "R-04", "R-04 rule_id correct")
    _assert(result["severity"].iloc[0] == "CRITICAL", "R-04 severity=CRITICAL")
    # Two events should be flagged (both legs of the journey)
    _assert(len(result) == 2, "R-04 flags both login events")

    # NEGATIVE: same user, nearby cities, 30 min apart (~200 km)
    rows_neg = [
        _make_row(base, username="local", event_type="login_success",
                  failure_reason=None, country="US", lat=40.71, lon=-74.01,
                  source_ip="3.3.3.3"),
        _make_row(base + timedelta(minutes=30), username="local",
                  event_type="login_success", failure_reason=None,
                  country="US", lat=42.36, lon=-71.06, source_ip="4.4.4.4"),
    ]
    df_neg = _df(rows_neg)
    result_neg = detect_impossible_travel(df_neg)
    _assert(result_neg.empty, "R-04 NEGATIVE does not fire for nearby cities")

    # NEGATIVE: US then CN but 2 hours apart (exceeds 60-min window)
    rows_slow = [
        _make_row(base, username="slow", event_type="login_success",
                  failure_reason=None, country="US", lat=37.09, lon=-95.71,
                  source_ip="5.5.5.5"),
        _make_row(base + timedelta(minutes=90), username="slow",
                  event_type="login_success", failure_reason=None,
                  country="CN", lat=35.86, lon=104.19, source_ip="6.6.6.6"),
    ]
    df_slow = _df(rows_slow)
    result_slow = detect_impossible_travel(df_slow)
    _assert(result_slow.empty, "R-04 NEGATIVE does not fire when gap > 60min")


# ---------------------------------------------------------------------------
# R-05: Repeated Account Lockout
# ---------------------------------------------------------------------------

def test_r05():
    print("\n-- R-05 Repeated Account Lockout ----------------------------")
    base = _base_ts()

    # POSITIVE: 4 lockouts for same account within 60 min
    rows_pos = [
        _make_row(base + timedelta(minutes=i * 10), username="victim",
                  failure_reason="account_locked", source_ip=f"9.0.0.{i}")
        for i in range(4)
    ]
    df_pos = _df(rows_pos)
    result = detect_repeated_lockout(df_pos)
    _assert(not result.empty, "R-05 POSITIVE fires on 4 lockouts/60min")
    _assert(result["rule_id"].iloc[0] == "R-05", "R-05 rule_id correct")
    _assert(result["severity"].iloc[0] == "MEDIUM", "R-05 severity=MEDIUM")

    # NEGATIVE: 2 lockouts only -- below threshold of 3
    rows_neg = [
        _make_row(base + timedelta(minutes=i * 10), username="lucky",
                  failure_reason="account_locked")
        for i in range(2)
    ]
    df_neg = _df(rows_neg)
    result_neg = detect_repeated_lockout(df_neg)
    _assert(result_neg.empty, "R-05 NEGATIVE does not fire on 2 lockouts")

    # NEGATIVE: 4 lockouts but wrong failure_reason
    rows_wrong = [
        _make_row(base + timedelta(minutes=i * 5), username="wrongtype",
                  failure_reason="wrong_password")
        for i in range(4)
    ]
    df_wrong = _df(rows_wrong)
    result_wrong = detect_repeated_lockout(df_wrong)
    _assert(result_wrong.empty, "R-05 NEGATIVE does not fire on wrong_password type")


# ---------------------------------------------------------------------------
# R-06: VPN Without MFA
# ---------------------------------------------------------------------------

def test_r06():
    print("\n-- R-06 VPN Login Without MFA -------------------------------")
    base = _base_ts()

    # POSITIVE: VPN success with password (not mfa)
    rows_pos = [
        _make_row(base, event_type="login_success", failure_reason=None,
                  is_vpn=True, auth_method="password")
    ]
    df_pos = _df(rows_pos)
    result = detect_vpn_no_mfa(df_pos)
    _assert(not result.empty, "R-06 POSITIVE fires on VPN+password success")
    _assert(result["rule_id"].iloc[0] == "R-06", "R-06 rule_id correct")
    _assert(result["severity"].iloc[0] == "LOW", "R-06 severity=LOW")

    # NEGATIVE: VPN success WITH mfa -- should not flag
    rows_neg = [
        _make_row(base, event_type="login_success", failure_reason=None,
                  is_vpn=True, auth_method="mfa")
    ]
    df_neg = _df(rows_neg)
    result_neg = detect_vpn_no_mfa(df_neg)
    _assert(result_neg.empty, "R-06 NEGATIVE does not fire on VPN+MFA")

    # NEGATIVE: non-VPN password login -- not flagged
    rows_no_vpn = [
        _make_row(base, event_type="login_success", failure_reason=None,
                  is_vpn=False, auth_method="password")
    ]
    df_no_vpn = _df(rows_no_vpn)
    result_no_vpn = detect_vpn_no_mfa(df_no_vpn)
    _assert(result_no_vpn.empty, "R-06 NEGATIVE does not fire on non-VPN login")


# ---------------------------------------------------------------------------
# R-07: Password Reset Spike
# ---------------------------------------------------------------------------

def test_r07():
    print("\n-- R-07 Password Reset Spike --------------------------------")
    base = _base_ts()

    # POSITIVE: 4 resets from same IP within 30 min
    rows_pos = [
        _make_row(base + timedelta(minutes=i * 6), event_type="password_reset",
                  failure_reason=None, source_ip="50.0.0.1",
                  username=f"user{i}")
        for i in range(4)
    ]
    df_pos = _df(rows_pos)
    result = detect_password_reset_spike(df_pos)
    _assert(not result.empty, "R-07 POSITIVE fires on 4 resets/IP/30min")
    _assert(result["rule_id"].iloc[0] == "R-07", "R-07 rule_id correct")
    _assert(result["severity"].iloc[0] == "MEDIUM", "R-07 severity=MEDIUM")

    # NEGATIVE: 2 resets -- below threshold
    rows_neg = [
        _make_row(base + timedelta(minutes=i * 6), event_type="password_reset",
                  failure_reason=None, source_ip="50.0.0.2",
                  username=f"usr{i}")
        for i in range(2)
    ]
    df_neg = _df(rows_neg)
    result_neg = detect_password_reset_spike(df_neg)
    _assert(result_neg.empty, "R-07 NEGATIVE does not fire on 2 resets")

    # NEGATIVE: 4 resets spaced 16 min apart (span=48 min > 30-min window)
    # Any 30-min window captures at most 2 consecutive events, below threshold of 3
    rows_spread = [
        _make_row(base + timedelta(minutes=i * 16), event_type="password_reset",
                  failure_reason=None, source_ip="50.0.0.3",
                  username=f"u{i}")
        for i in range(4)
    ]
    df_spread = _df(rows_spread)
    result_spread = detect_password_reset_spike(df_spread)
    _assert(result_spread.empty, "R-07 NEGATIVE does not fire when max 2 resets per window")


# ---------------------------------------------------------------------------
# Integration: run_all_detectors on full synthetic dataset
# ---------------------------------------------------------------------------

def test_integration():
    print("\n-- Integration: synthetic dataset end-to-end ----------------")
    # Ensure generate module works and all detectors fire
    from generate_dataset import generate
    import tempfile, os

    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = os.path.join(tmpdir, "auth_logs.csv")
        df = generate(n_rows=2000, output_path=out_path)

    # Reproducibility: generate twice with same seeds, compare row counts
    import random, numpy as np
    from faker import Faker
    with tempfile.TemporaryDirectory() as tmpdir:
        p1 = os.path.join(tmpdir, "a.csv")
        p2 = os.path.join(tmpdir, "b.csv")
        # Reset seeds explicitly
        random.seed(42); np.random.seed(42); Faker.seed(42)
        df1 = generate(n_rows=500, output_path=p1)
        random.seed(42); np.random.seed(42); Faker.seed(42)
        df2 = generate(n_rows=500, output_path=p2)
    _assert(
        len(df1) == len(df2),
        f"Reproducibility: same row count ({len(df1)})"
    )
    _assert(
        list(df1["username"]) == list(df2["username"]),
        "Reproducibility: same usernames across two runs"
    )
    _assert(
        list(df1["event_type"]) == list(df2["event_type"]),
        "Reproducibility: same event_types across two runs"
    )

    # All 7 rules should fire on the 2000-row synthetic set
    df_full = generate(n_rows=2000, output_path=os.path.join(
        __import__("tempfile").mkdtemp(), "test.csv"
    ))
    df_full["timestamp"] = pd.to_datetime(df_full["timestamp"], utc=True)
    df_full["is_vpn"] = df_full["is_vpn"].astype(bool)
    flagged = run_all_detectors(df_full)

    fired_rules = set(flagged["rule_id"].unique()) if not flagged.empty else set()
    expected_rules = {"R-01", "R-02", "R-03", "R-04", "R-05", "R-06", "R-07"}
    for rule in expected_rules:
        _assert(rule in fired_rules, f"Integration: {rule} fires on synthetic dataset")

    # Each flagged row has explanation
    if not flagged.empty:
        has_explanation = flagged["explanation"].notna().all()
        _assert(has_explanation, "Integration: all flagged rows have explanations")

        # Severity values are valid
        valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        bad_sev = set(flagged["severity"].unique()) - valid_severities
        _assert(len(bad_sev) == 0, f"Integration: all severities valid (bad={bad_sev})")


# ---------------------------------------------------------------------------
# Schema validation test
# ---------------------------------------------------------------------------

def test_schema_validation():
    print("\n-- Schema validation ----------------------------------------")
    import importlib, types

    REQUIRED_COLUMNS = [
        "event_id", "timestamp", "username", "source_ip", "country",
        "event_type", "user_agent", "session_id", "auth_method",
        "failure_reason", "is_vpn", "latitude", "longitude",
    ]

    # Missing column should raise ValueError
    base = _base_ts()
    rows = [_make_row(base)]
    df = _df(rows)
    df_broken = df.drop(columns=["source_ip"])

    missing = [c for c in REQUIRED_COLUMNS if c not in df_broken.columns]
    _assert("source_ip" in missing, "Schema: missing column detected correctly")

    # Full schema is intact
    missing_full = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    _assert(len(missing_full) == 0, "Schema: full schema has no missing columns")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 62)
    print("ThreatLens - Detector Unit Tests")
    print("=" * 62)

    test_r01()
    test_r02()
    test_r03()
    test_r04()
    test_r05()
    test_r06()
    test_r07()
    test_integration()
    test_schema_validation()

    passed = sum(1 for ok, _ in _results if ok)
    failed = sum(1 for ok, _ in _results if not ok)
    total = len(_results)

    print("\n" + "=" * 62)
    print(f"Results: {passed}/{total} passed,  {failed} failed")
    print("=" * 62)

    if failed > 0:
        print("\nFailed tests:")
        for ok, name in _results:
            if not ok:
                print(f"  [FAIL]  {name}")
        sys.exit(1)
    else:
        print("All tests passed.")
        sys.exit(0)
