"""
detectors.py
------------
Rule-based threat detection functions for ThreatLens.

Each function receives the full DataFrame and returns a DataFrame of
flagged events with added columns:
    rule_id    : e.g. "R-01"
    rule_name  : human-readable rule label
    severity   : CRITICAL | HIGH | MEDIUM | LOW
    explanation: one-sentence plain-English reason

All rules operate on a sorted, UTC-parsed DataFrame.
No ML, no external APIs, no network calls.
"""

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BRUTE_FORCE_THRESHOLD = 5        # failures from same IP
_BRUTE_FORCE_WINDOW_MIN = 10      # within N minutes

_STUFFING_IP_THRESHOLD = 3        # minimum distinct usernames
_STUFFING_FAIL_THRESHOLD = 3      # minimum failures
_STUFFING_WINDOW_MIN = 15

_OFF_HOURS_START = 22             # 22:00 UTC
_OFF_HOURS_END = 5                # 05:00 UTC

_IMPOSSIBLE_TRAVEL_KM = 500       # km threshold
_IMPOSSIBLE_TRAVEL_MIN = 60       # within N minutes

_LOCKOUT_THRESHOLD = 3            # lockout events per account
_LOCKOUT_WINDOW_MIN = 60

_RESET_SPIKE_THRESHOLD = 3        # reset requests from same IP
_RESET_SPIKE_WINDOW_MIN = 30

EARTH_RADIUS_KM = 6371.0


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _haversine(lat1, lon1, lat2, lon2) -> float:
    """Return great-circle distance in km between two lat/lon points."""
    lat1, lon1, lat2, lon2 = map(np.radians, [lat1, lon1, lat2, lon2])
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = np.sin(dlat / 2) ** 2 + np.cos(lat1) * np.cos(lat2) * np.sin(dlon / 2) ** 2
    return 2 * EARTH_RADIUS_KM * np.arcsin(np.sqrt(a))


def _rolling_window_flags(df: pd.DataFrame,
                           group_col: str,
                           event_types: list,
                           window_minutes: int,
                           threshold: int,
                           rule_id: str,
                           rule_name: str,
                           severity: str,
                           explanation_template: str) -> pd.DataFrame:
    """
    Generic sliding-window detector.
    Groups df by group_col, filters to event_types, then for each event
    counts how many same-group events fall within the preceding window_minutes.
    Returns rows where that count >= threshold.
    """
    subset = df[df["event_type"].isin(event_types)].copy()
    if subset.empty:
        return pd.DataFrame()

    flagged_rows = []
    for group_val, group_df in subset.groupby(group_col):
        group_df = group_df.sort_values("timestamp")
        # Convert to UTC-naive int64 (nanoseconds) for safe numpy comparison.
        # pd.Timestamp.values on tz-aware Series is datetime64[ns] without tz
        # info when accessed via .values; using view(np.int64) avoids the
        # UserWarning raised by np.datetime64(tz_aware_timestamp) on numpy>=1.24.
        ts_ns = group_df["timestamp"].values.view(np.int64)
        for i, row in enumerate(group_df.itertuples()):
            window_start_ns = int(
                (row.timestamp - pd.Timedelta(minutes=window_minutes))
                .value
            )
            row_ts_ns = int(row.timestamp.value)
            count = int(np.sum(
                (ts_ns >= window_start_ns) &
                (ts_ns <= row_ts_ns)
            ))
            if count >= threshold:
                r = group_df.iloc[i].copy()
                r["rule_id"] = rule_id
                r["rule_name"] = rule_name
                r["severity"] = severity
                r["explanation"] = explanation_template.format(
                    group_val=group_val, count=count,
                    window=window_minutes, threshold=threshold
                )
                flagged_rows.append(r)

    if not flagged_rows:
        return pd.DataFrame()
    return pd.DataFrame(flagged_rows).drop_duplicates(subset=["event_id"])


# ---------------------------------------------------------------------------
# Detection Rules
# ---------------------------------------------------------------------------

def detect_brute_force(df: pd.DataFrame) -> pd.DataFrame:
    """
    R-01 Brute Force
    ≥ 5 login failures from the same IP within 10 minutes.
    """
    return _rolling_window_flags(
        df,
        group_col="source_ip",
        event_types=["login_failure"],
        window_minutes=_BRUTE_FORCE_WINDOW_MIN,
        threshold=_BRUTE_FORCE_THRESHOLD,
        rule_id="R-01",
        rule_name="Brute Force",
        severity="HIGH",
        explanation_template=(
            "IP {group_val} made {count} failed login attempts "
            "within {window} minutes — likely automated password guessing."
        ),
    )


def detect_credential_stuffing(df: pd.DataFrame) -> pd.DataFrame:
    """
    R-02 Credential Stuffing
    One IP attempts ≥ 3 distinct usernames with ≥ 3 failures within 15 min.
    """
    subset = df[df["event_type"] == "login_failure"].copy()
    if subset.empty:
        return pd.DataFrame()

    flagged_rows = []
    for ip, ip_df in subset.groupby("source_ip"):
        ip_df = ip_df.sort_values("timestamp")
        for i, row in enumerate(ip_df.itertuples()):
            window_start = row.timestamp - pd.Timedelta(minutes=_STUFFING_WINDOW_MIN)
            window_df = ip_df[
                (ip_df["timestamp"] >= window_start) &
                (ip_df["timestamp"] <= row.timestamp)
            ]
            distinct_users = window_df["username"].nunique()
            if (len(window_df) >= _STUFFING_FAIL_THRESHOLD and
                    distinct_users >= _STUFFING_IP_THRESHOLD):
                r = ip_df.iloc[i].copy()
                r["rule_id"] = "R-02"
                r["rule_name"] = "Credential Stuffing"
                r["severity"] = "HIGH"
                r["explanation"] = (
                    f"IP {ip} attempted {distinct_users} distinct usernames "
                    f"({len(window_df)} failures) within {_STUFFING_WINDOW_MIN} min — "
                    "pattern consistent with credential stuffing."
                )
                flagged_rows.append(r)

    if not flagged_rows:
        return pd.DataFrame()
    return pd.DataFrame(flagged_rows).drop_duplicates(subset=["event_id"])


def detect_off_hours_login(df: pd.DataFrame) -> pd.DataFrame:
    """
    R-03 Off-Hours Login
    Successful login between 22:00–05:00 UTC.
    """
    subset = df[df["event_type"] == "login_success"].copy()
    if subset.empty:
        return pd.DataFrame()

    hour = subset["timestamp"].dt.hour
    mask = (hour >= _OFF_HOURS_START) | (hour < _OFF_HOURS_END)
    flagged = subset[mask].copy()
    flagged["rule_id"] = "R-03"
    flagged["rule_name"] = "Off-Hours Login"
    flagged["severity"] = "MEDIUM"
    flagged["explanation"] = (
        "Successful login at " +
        flagged["timestamp"].dt.strftime("%H:%M UTC") +
        " — outside normal business hours (22:00–05:00 UTC)."
    )
    return flagged


def detect_impossible_travel(df: pd.DataFrame) -> pd.DataFrame:
    """
    R-04 Impossible Travel
    Same user logs in from two locations > 500 km apart within 60 minutes.
    """
    subset = df[df["event_type"] == "login_success"].copy()
    if subset.empty:
        return pd.DataFrame()

    flagged_rows = []
    for user, user_df in subset.groupby("username"):
        user_df = user_df.sort_values("timestamp")
        rows = list(user_df.itertuples())
        for i in range(len(rows) - 1):
            a = rows[i]
            b = rows[i + 1]
            delta_min = (b.timestamp - a.timestamp).total_seconds() / 60
            if delta_min > _IMPOSSIBLE_TRAVEL_MIN:
                continue
            dist_km = _haversine(a.latitude, a.longitude, b.latitude, b.longitude)
            if dist_km > _IMPOSSIBLE_TRAVEL_KM:
                for row_obj, label in [(a, "first"), (b, "second")]:
                    r = user_df[user_df["event_id"] == row_obj.event_id].iloc[0].copy()
                    r["rule_id"] = "R-04"
                    r["rule_name"] = "Impossible Travel"
                    r["severity"] = "CRITICAL"
                    r["explanation"] = (
                        f"User '{user}' logged in from {a.country} then {b.country} "
                        f"({dist_km:,.0f} km) in {delta_min:.0f} min — "
                        "physically impossible without compromised credentials."
                    )
                    flagged_rows.append(r)

    if not flagged_rows:
        return pd.DataFrame()
    return pd.DataFrame(flagged_rows).drop_duplicates(subset=["event_id"])


def detect_repeated_lockout(df: pd.DataFrame) -> pd.DataFrame:
    """
    R-05 Repeated Account Lockout
    Same account locked ≥ 3 times within 60 minutes.
    """
    subset = df[
        (df["event_type"] == "login_failure") &
        (df["failure_reason"] == "account_locked")
    ].copy()
    if subset.empty:
        return pd.DataFrame()

    return _rolling_window_flags(
        subset,
        group_col="username",
        event_types=["login_failure"],
        window_minutes=_LOCKOUT_WINDOW_MIN,
        threshold=_LOCKOUT_THRESHOLD,
        rule_id="R-05",
        rule_name="Repeated Account Lockout",
        severity="MEDIUM",
        explanation_template=(
            "Account '{group_val}' was locked out {count} times "
            "within {window} minutes — may indicate targeted attack."
        ),
    )


def detect_vpn_no_mfa(df: pd.DataFrame) -> pd.DataFrame:
    """
    R-06 VPN Login Without MFA
    Successful login via VPN without MFA authentication.
    """
    mask = (
        (df["event_type"] == "login_success") &
        (df["is_vpn"] == True) &
        (df["auth_method"] != "mfa")
    )
    flagged = df[mask].copy()
    flagged["rule_id"] = "R-06"
    flagged["rule_name"] = "VPN Login Without MFA"
    flagged["severity"] = "LOW"
    flagged["explanation"] = (
        "Login from VPN IP " + flagged["source_ip"] +
        " using " + flagged["auth_method"] +
        " — VPN connections should require MFA."
    )
    return flagged


def detect_password_reset_spike(df: pd.DataFrame) -> pd.DataFrame:
    """
    R-07 Password Reset Spike
    ≥ 3 password reset requests from same IP within 30 minutes.
    """
    return _rolling_window_flags(
        df,
        group_col="source_ip",
        event_types=["password_reset"],
        window_minutes=_RESET_SPIKE_WINDOW_MIN,
        threshold=_RESET_SPIKE_THRESHOLD,
        rule_id="R-07",
        rule_name="Password Reset Spike",
        severity="MEDIUM",
        explanation_template=(
            "IP {group_val} triggered {count} password reset requests "
            "within {window} min — possible account takeover attempt."
        ),
    )


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

DETECTORS = [
    detect_brute_force,
    detect_credential_stuffing,
    detect_off_hours_login,
    detect_impossible_travel,
    detect_repeated_lockout,
    detect_vpn_no_mfa,
    detect_password_reset_spike,
]

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def run_all_detectors(df: pd.DataFrame) -> pd.DataFrame:
    """
    Run every detector and return a unified DataFrame of flagged events,
    deduplicated by event_id + rule_id, sorted by severity then timestamp.
    """
    results = []
    for detector in DETECTORS:
        try:
            result = detector(df)
            if result is not None and not result.empty:
                results.append(result)
        except Exception as exc:
            print(f"[WARNING] {detector.__name__} raised: {exc}")

    if not results:
        return pd.DataFrame()

    combined = pd.concat(results, ignore_index=True)
    combined = combined.drop_duplicates(subset=["event_id", "rule_id"])
    combined["_sev_order"] = combined["severity"].map(SEVERITY_ORDER)
    combined = combined.sort_values(["_sev_order", "timestamp"]).drop(columns=["_sev_order"])
    combined = combined.reset_index(drop=True)
    return combined
