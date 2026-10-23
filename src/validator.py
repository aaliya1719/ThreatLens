"""
validator.py
------------
Input validation for ThreatLens log DataFrames.

All validation logic lives here, completely separate from the UI layer,
so it can be tested without Streamlit and reused by the notebook.

Public API
----------
validate_dataframe(df) -> ValidationResult
    Validate a raw pandas DataFrame against the ThreatLens schema.
    Returns a ValidationResult named-tuple with:
        ok      : bool  — True if the DataFrame is safe to analyse
        df      : pd.DataFrame | None — coerced, UTC-stamped DF (or None on failure)
        errors  : list[str]  — fatal problems (empty means ok)
        warnings: list[str]  — non-fatal notices
"""

from __future__ import annotations

import io
from typing import NamedTuple

import pandas as pd


# ---------------------------------------------------------------------------
# Schema constants (single source of truth — keep in sync with README)
# ---------------------------------------------------------------------------

REQUIRED_COLUMNS: list[str] = [
    "event_id",
    "timestamp",
    "username",
    "source_ip",
    "country",
    "event_type",
    "user_agent",
    "session_id",
    "auth_method",
    "failure_reason",
    "is_vpn",
    "latitude",
    "longitude",
]

VALID_EVENT_TYPES: set[str] = {
    "login_success",
    "login_failure",
    "logout",
    "password_reset",
}

VALID_AUTH_METHODS: set[str] = {"password", "mfa", "sso", "api_key"}

VALID_FAILURE_REASONS: set[str] = {"wrong_password", "account_locked", "mfa_failed"}

VALID_SEVERITIES: set[str] = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

class ValidationResult(NamedTuple):
    ok: bool
    df: pd.DataFrame | None
    errors: list
    warnings: list


# ---------------------------------------------------------------------------
# Public function
# ---------------------------------------------------------------------------

def validate_dataframe(df: pd.DataFrame) -> ValidationResult:
    """
    Validate and coerce a raw DataFrame for ThreatLens analysis.

    Checks performed (in order):
    1. Not empty.
    2. All required columns present.
    3. timestamp column parseable as UTC datetimes.
    4. is_vpn coercible to bool.
    5. latitude / longitude coercible to float; NaN rows flagged as warning.
    6. event_type values — unknown values are warned, not fatal.
    7. At least one event row survives coercion.

    Parameters
    ----------
    df : pd.DataFrame
        Raw DataFrame, typically loaded from a user-uploaded CSV.

    Returns
    -------
    ValidationResult
        .ok       True if analysis can proceed.
        .df       Coerced DataFrame with UTC timestamps (None if not ok).
        .errors   List of fatal error strings.
        .warnings List of non-fatal warning strings.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # ── 1. Empty file ────────────────────────────────────────────────────────
    if df is None or len(df) == 0:
        errors.append("The uploaded file is empty — no rows found.")
        return ValidationResult(ok=False, df=None, errors=errors, warnings=warnings)

    # ── 2. Required columns ──────────────────────────────────────────────────
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        errors.append(
            f"Missing required column(s): {', '.join(missing)}. "
            "See the README for the full schema."
        )
        return ValidationResult(ok=False, df=None, errors=errors, warnings=warnings)

    # Work on a copy from here so the caller's DataFrame is not mutated.
    df = df.copy()

    # ── 3. Timestamp parsing ─────────────────────────────────────────────────
    original_len = len(df)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
    bad_ts = df["timestamp"].isna().sum()
    if bad_ts == original_len:
        errors.append(
            "No parseable timestamps found in the 'timestamp' column. "
            "Expected format: YYYY-MM-DD HH:MM:SS (UTC)."
        )
        return ValidationResult(ok=False, df=None, errors=errors, warnings=warnings)
    if bad_ts > 0:
        warnings.append(
            f"{bad_ts:,} row(s) had unparseable timestamps and were dropped."
        )
        df = df.dropna(subset=["timestamp"])

    # ── 4. is_vpn coercion ───────────────────────────────────────────────────
    # pandas astype(bool) converts ANY non-empty string to True, so we must
    # detect the object/string case first and use an explicit value map.
    if df["is_vpn"].dtype == object:
        bool_map = {
            "True": True, "False": False,
            "true": True, "false": False,
            "TRUE": True, "FALSE": False,
            "1": True, "0": False,
            True: True, False: False,
            1: True, 0: False,
        }
        coerced = df["is_vpn"].map(bool_map)
        n_unrecognised = coerced.isna().sum()
        df["is_vpn"] = coerced.fillna(False).astype(bool)
        if n_unrecognised > 0:
            warnings.append(
                f"'is_vpn' had {n_unrecognised:,} unrecognised value(s); treated as False."
            )
    else:
        df["is_vpn"] = df["is_vpn"].astype(bool)

    # ── 5. Numeric lat/lon ───────────────────────────────────────────────────
    df["latitude"]  = pd.to_numeric(df["latitude"],  errors="coerce")
    df["longitude"] = pd.to_numeric(df["longitude"], errors="coerce")
    bad_coords = df[["latitude", "longitude"]].isna().any(axis=1).sum()
    if bad_coords > 0:
        warnings.append(
            f"{bad_coords:,} row(s) have missing or invalid latitude/longitude values. "
            "Rule R-04 (Impossible Travel) will skip these rows."
        )

    # ── 6. Unknown event_type values ─────────────────────────────────────────
    unknown_events = set(df["event_type"].dropna().unique()) - VALID_EVENT_TYPES
    if unknown_events:
        warnings.append(
            f"Unrecognised event_type value(s): {', '.join(sorted(unknown_events))}. "
            f"Expected: {', '.join(sorted(VALID_EVENT_TYPES))}. "
            "These rows will be present in the dataset but no rule targets them."
        )

    # ── 7. Minimum viable rows ───────────────────────────────────────────────
    if len(df) == 0:
        errors.append(
            "No valid rows remain after cleaning. "
            "Check timestamp format and required columns."
        )
        return ValidationResult(ok=False, df=None, errors=errors, warnings=warnings)

    return ValidationResult(ok=True, df=df, errors=errors, warnings=warnings)


# ---------------------------------------------------------------------------
# CSV loader helper (used by dashboard and tests)
# ---------------------------------------------------------------------------

def load_csv_bytes(raw_bytes: bytes) -> tuple[pd.DataFrame | None, str | None]:
    """
    Parse raw CSV bytes into a DataFrame.

    Returns (df, None) on success or (None, error_message) on failure.
    Does NOT perform schema validation — call validate_dataframe() next.
    """
    if not raw_bytes:
        return None, "Uploaded file is empty."
    try:
        df = pd.read_csv(io.BytesIO(raw_bytes))
        return df, None
    except Exception as exc:
        return None, f"Could not parse CSV: {exc}"
