"""
generate_dataset.py
-------------------
Synthetic authentication log generator for ThreatLens.

Produces a realistic-looking CSV with ~2,000 events spanning 7 days.
Injects known attack patterns so that detection rules have something to find.

Usage:
    python src/generate_dataset.py            # writes data/raw/auth_logs.csv
    python src/generate_dataset.py --rows 500 # custom row count
"""

import argparse
import os
import random
import uuid
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd
from faker import Faker

fake = Faker()
Faker.seed(42)
random.seed(42)
np.random.seed(42)

# ---------------------------------------------------------------------------
# Static lookup tables
# ---------------------------------------------------------------------------

COUNTRIES = [
    ("US", 37.09, -95.71),
    ("GB", 55.38, -3.44),
    ("DE", 51.17, 10.45),
    ("CN", 35.86, 104.19),
    ("RU", 61.52, 105.32),
    ("BR", -14.24, -51.93),
    ("IN", 20.59, 78.96),
    ("AU", -25.27, 133.78),
    ("FR", 46.23, 2.21),
    ("NG", 9.08, 8.68),
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/114.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/605.1.15 Safari/605.1",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "python-requests/2.28.0",
    "curl/7.88.1",
    "Go-http-client/1.1",
]

AUTH_METHODS = ["password", "mfa", "sso", "api_key"]
FAILURE_REASONS = ["wrong_password", "account_locked", "mfa_failed"]


# ---------------------------------------------------------------------------
# Helper generators
# ---------------------------------------------------------------------------

# Diurnal hour weights: simulates a realistic enterprise login schedule.
# Hours 06-21 UTC are "business hours" across common global time zones and
# receive ~93% of legitimate traffic; the off-hours window (22-05 UTC) receives
# ~7%.  These weights match the R-03 threshold intent: off-hours logins are
# genuinely rare and warrant investigation.
#
# Weight table indexed by hour 0..23.  Values are proportional probabilities;
# they are normalised at runtime by random.choices().
_HOUR_WEIGHTS = [
    1,  # 00 off-hours (rare)
    1,  # 01
    1,  # 02
    1,  # 03
    1,  # 04
    2,  # 05 transition
    6,  # 06 business begins
    8,  # 07
    10, # 08
    10, # 09
    10, # 10
    10, # 11
    9,  # 12
    10, # 13
    10, # 14
    10, # 15
    9,  # 16
    8,  # 17
    7,  # 18
    5,  # 19
    4,  # 20
    3,  # 21 trailing off
    1,  # 22 off-hours
    1,  # 23
]

_HOURS = list(range(24))


def _rand_ip():
    return fake.ipv4_public()


def _rand_ts(base: datetime, jitter_minutes: int = 10080) -> datetime:
    """Return a UTC datetime within the jitter_minutes span, uniformly.

    Used for non-login events (failures, logouts, resets) where diurnal
    weighting is not required.
    """
    delta = random.randint(0, jitter_minutes)
    return base + timedelta(minutes=delta)


def _rand_ts_business(base: datetime, span_days: int = 7) -> datetime:
    """Return a UTC datetime biased toward business hours (06:00-21:00 UTC).

    Picks a random day in [0, span_days), then a random hour using
    _HOUR_WEIGHTS, then a random minute within that hour.  This produces
    ~7% of successful logins in the off-hours window (22:00-05:00 UTC),
    matching the intent of the R-03 detection rule.
    """
    day = random.randint(0, span_days - 1)
    hour = random.choices(_HOURS, weights=_HOUR_WEIGHTS, k=1)[0]
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base + timedelta(days=day, hours=hour, minutes=minute, seconds=second)


def _make_event(
    ts: datetime,
    username: str,
    source_ip: str,
    country_tuple,
    event_type: str,
    auth_method: str = "password",
    failure_reason: str = None,
    is_vpn: bool = False,
) -> dict:
    country, lat, lon = country_tuple
    return {
        "event_id": f"EVT-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
        "username": username,
        "source_ip": source_ip,
        "country": country,
        "event_type": event_type,
        "user_agent": random.choice(USER_AGENTS),
        "session_id": str(uuid.uuid4()) if event_type == "login_success" else None,
        "auth_method": auth_method,
        "failure_reason": failure_reason,
        "is_vpn": is_vpn,
        "latitude": round(lat + random.uniform(-2, 2), 4),
        "longitude": round(lon + random.uniform(-2, 2), 4),
    }


# ---------------------------------------------------------------------------
# Pattern injectors (attack scenarios)
# ---------------------------------------------------------------------------

def inject_brute_force(base_ts: datetime, events: list):
    """R-01: 8 rapid failures from one IP against one account."""
    ip = _rand_ip()
    user = fake.user_name()
    country = random.choice(COUNTRIES)
    for i in range(8):
        ts = base_ts + timedelta(seconds=i * 45)
        events.append(_make_event(ts, user, ip, country, "login_failure",
                                   failure_reason="wrong_password"))


def inject_credential_stuffing(base_ts: datetime, events: list):
    """R-02: one IP tries 5 different usernames within 12 minutes."""
    ip = _rand_ip()
    country = random.choice(COUNTRIES)
    users = [fake.user_name() for _ in range(5)]
    for i, user in enumerate(users):
        ts = base_ts + timedelta(minutes=i * 2.4)
        events.append(_make_event(ts, user, ip, country, "login_failure",
                                   failure_reason="wrong_password"))


def inject_impossible_travel(base_ts: datetime, events: list):
    """R-04: same user logs in from US then CN within 30 minutes."""
    user = fake.user_name()
    ts1 = base_ts
    ts2 = base_ts + timedelta(minutes=30)
    us = ("US", 37.09, -95.71)
    cn = ("CN", 35.86, 104.19)
    events.append(_make_event(ts1, user, _rand_ip(), us, "login_success", auth_method="mfa"))
    events.append(_make_event(ts2, user, _rand_ip(), cn, "login_success", auth_method="password"))


def inject_off_hours(base_ts: datetime, events: list):
    """R-03: successful login at 02:30 UTC."""
    ts = base_ts.replace(hour=2, minute=30, second=0)
    country = random.choice(COUNTRIES)
    events.append(_make_event(ts, fake.user_name(), _rand_ip(), country,
                               "login_success", auth_method="password"))


def inject_account_lockout(base_ts: datetime, events: list):
    """R-05: same account locked 4 times within 45 minutes."""
    user = fake.user_name()
    country = random.choice(COUNTRIES)
    for i in range(4):
        ts = base_ts + timedelta(minutes=i * 11)
        ip = _rand_ip()
        events.append(_make_event(ts, user, ip, country, "login_failure",
                                   failure_reason="account_locked"))


def inject_vpn_no_mfa(base_ts: datetime, events: list):
    """R-06: successful login over VPN without MFA."""
    country = random.choice(COUNTRIES)
    events.append(_make_event(base_ts, fake.user_name(), _rand_ip(), country,
                               "login_success", auth_method="password", is_vpn=True))


def inject_password_reset_spike(base_ts: datetime, events: list):
    """R-07: 4 password resets from same IP within 20 minutes."""
    ip = _rand_ip()
    country = random.choice(COUNTRIES)
    for i in range(4):
        ts = base_ts + timedelta(minutes=i * 4)
        events.append(_make_event(ts, fake.user_name(), ip, country,
                                   "password_reset", auth_method="password"))


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate(n_rows: int = 2000, output_path: str = "data/raw/auth_logs.csv"):
    base = datetime(2025, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    events = []

    # ── Inject attack patterns spread across the week ──────────────────────
    attack_injectors = [
        inject_brute_force,
        inject_credential_stuffing,
        inject_impossible_travel,
        inject_off_hours,
        inject_account_lockout,
        inject_vpn_no_mfa,
        inject_password_reset_spike,
    ]
    for idx, injector in enumerate(attack_injectors):
        ts = base + timedelta(days=idx, hours=random.randint(0, 20))
        injector(ts, events)

    # ── Normal background traffic ───────────────────────────────────────────
    # login_success uses _rand_ts_business so that timestamps are biased toward
    # 06:00-21:00 UTC, making off-hours logins (~7%) genuinely rare.
    # All other event types (failures, logouts, resets) keep uniform timing
    # since R-03 only fires on login_success.
    while len(events) < n_rows:
        user = fake.user_name()
        country = random.choice(COUNTRIES)
        ip = _rand_ip()
        roll = random.random()
        if roll < 0.70:
            ts = _rand_ts_business(base)
            events.append(_make_event(ts, user, ip, country, "login_success",
                                       auth_method=random.choice(AUTH_METHODS)))
        elif roll < 0.88:
            ts = _rand_ts(base)
            events.append(_make_event(ts, user, ip, country, "login_failure",
                                       failure_reason=random.choice(FAILURE_REASONS)))
        elif roll < 0.94:
            ts = _rand_ts(base)
            events.append(_make_event(ts, user, ip, country, "logout"))
        else:
            ts = _rand_ts(base)
            events.append(_make_event(ts, user, ip, country, "password_reset"))

    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    parent = os.path.dirname(output_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    df.to_csv(output_path, index=False)
    print(f"[generate_dataset] Wrote {len(df):,} rows -> {output_path}")
    return df


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, default=2000)
    parser.add_argument("--out", default="data/raw/auth_logs.csv")
    args = parser.parse_args()
    generate(args.rows, args.out)
