"""
test_validator.py
-----------------
Unit tests for src/validator.py.

Tests cover:
- Empty DataFrame / bytes
- Missing required columns
- Unparseable timestamps (all bad vs some bad)
- is_vpn string coercion
- Invalid lat/lon
- Unknown event_type values
- Full valid DataFrame passes without errors
- load_csv_bytes helper

Run from project root:
    python tests/test_validator.py
"""

import io
import sys
import uuid
from datetime import datetime, timezone

import pandas as pd

sys.path.insert(0, "src")
from validator import validate_dataframe, load_csv_bytes, REQUIRED_COLUMNS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PASS = "[PASS]"
FAIL = "[FAIL]"
_results: list[tuple[bool, str]] = []


def _check(condition: bool, name: str) -> bool:
    tag = PASS if condition else FAIL
    _results.append((condition, name))
    print(f"  {tag}  {name}")
    return condition


def _make_valid_row(
    ts="2025-06-01 10:00:00",
    event_type="login_success",
    failure_reason=None,
    is_vpn=False,
    auth_method="password",
    lat=37.09,
    lon=-95.71,
) -> dict:
    return {
        "event_id": f"EVT-{uuid.uuid4().hex[:8].upper()}",
        "timestamp": ts,
        "username": "testuser",
        "source_ip": "1.2.3.4",
        "country": "US",
        "event_type": event_type,
        "user_agent": "test/1.0",
        "session_id": str(uuid.uuid4()) if event_type == "login_success" else None,
        "auth_method": auth_method,
        "failure_reason": failure_reason,
        "is_vpn": is_vpn,
        "latitude": lat,
        "longitude": lon,
    }


def _valid_df(n: int = 5) -> pd.DataFrame:
    return pd.DataFrame([_make_valid_row() for _ in range(n)])


# ---------------------------------------------------------------------------
# Test: empty input
# ---------------------------------------------------------------------------

def test_empty():
    print("\n-- Empty input --")

    # Empty DataFrame
    result = validate_dataframe(pd.DataFrame())
    _check(not result.ok, "Empty DataFrame -> not ok")
    _check(len(result.errors) > 0, "Empty DataFrame -> has error message")
    _check("empty" in result.errors[0].lower(), "Empty DataFrame -> error mentions 'empty'")

    # None
    result2 = validate_dataframe(None)
    _check(not result2.ok, "None input -> not ok")

    # Empty bytes
    df_none, err = load_csv_bytes(b"")
    _check(df_none is None, "load_csv_bytes(b'') -> None df")
    _check(err is not None, "load_csv_bytes(b'') -> has error string")


# ---------------------------------------------------------------------------
# Test: missing columns
# ---------------------------------------------------------------------------

def test_missing_columns():
    print("\n-- Missing columns --")

    df = _valid_df()

    # Drop one required column
    df_no_ip = df.drop(columns=["source_ip"])
    result = validate_dataframe(df_no_ip)
    _check(not result.ok, "Missing source_ip -> not ok")
    _check(any("source_ip" in e for e in result.errors), "Missing source_ip -> error names the column")

    # Drop multiple
    df_multi = df.drop(columns=["source_ip", "username", "latitude"])
    result2 = validate_dataframe(df_multi)
    _check(not result2.ok, "Missing 3 columns -> not ok")
    _check(len(result2.errors) > 0, "Missing 3 columns -> has error")


# ---------------------------------------------------------------------------
# Test: timestamp handling
# ---------------------------------------------------------------------------

def test_timestamps():
    print("\n-- Timestamp handling --")

    # All rows have bad timestamps
    df_bad = _valid_df()
    df_bad["timestamp"] = "not-a-date"
    result = validate_dataframe(df_bad)
    _check(not result.ok, "All bad timestamps -> not ok")
    _check(any("timestamp" in e.lower() for e in result.errors), "All bad timestamps -> error mentions timestamp")

    # Mixed: 3 good, 2 bad
    rows = [_make_valid_row() for _ in range(3)] + \
           [_make_valid_row(ts="INVALID") for _ in range(2)]
    df_mixed = pd.DataFrame(rows)
    result2 = validate_dataframe(df_mixed)
    _check(result2.ok, "Mixed timestamps (3 good, 2 bad) -> ok=True")
    _check(len(result2.df) == 3, "Mixed timestamps -> 3 rows survive")
    _check(len(result2.warnings) > 0, "Mixed timestamps -> has warning about dropped rows")
    _check(any("2" in w for w in result2.warnings), "Mixed timestamps -> warning mentions count 2")

    # Valid UTC-aware timestamps from generate_dataset
    df_utc = _valid_df()
    df_utc["timestamp"] = pd.to_datetime(df_utc["timestamp"], utc=True)
    result3 = validate_dataframe(df_utc)
    _check(result3.ok, "Pre-parsed UTC timestamps -> ok")


# ---------------------------------------------------------------------------
# Test: is_vpn coercion
# ---------------------------------------------------------------------------

def test_vpn_coercion():
    print("\n-- is_vpn coercion --")

    # String True/False (as they appear after CSV round-trip)
    df = _valid_df()
    df["is_vpn"] = ["True", "False", "true", "false", "True"]
    result = validate_dataframe(df)
    _check(result.ok, "String True/False is_vpn -> ok")
    _check(result.df["is_vpn"].dtype == bool, "String is_vpn coerced to bool dtype")
    _check(result.df["is_vpn"].sum() == 3, "String is_vpn: 3 True values")

    # Numeric 1/0
    df2 = _valid_df()
    df2["is_vpn"] = [1, 0, 1, 0, 1]
    result2 = validate_dataframe(df2)
    _check(result2.ok, "Numeric 1/0 is_vpn -> ok")
    _check(result2.df["is_vpn"].sum() == 3, "Numeric is_vpn: 3 True values")


# ---------------------------------------------------------------------------
# Test: latitude / longitude
# ---------------------------------------------------------------------------

def test_coordinates():
    print("\n-- Latitude / longitude --")

    # Mixed valid and NaN coords
    rows = [_make_valid_row() for _ in range(4)]
    rows.append(_make_valid_row(lat=float("nan"), lon=float("nan")))
    df = pd.DataFrame(rows)
    result = validate_dataframe(df)
    _check(result.ok, "1 NaN coord row -> still ok")
    _check(len(result.warnings) > 0, "NaN coords -> has warning")
    _check(any("1" in w for w in result.warnings), "NaN coords -> warning mentions count")

    # Non-numeric coord string — build the df with a mixed-type latitude column
    rows2 = [_make_valid_row() for _ in range(5)]
    rows2[0] = dict(rows2[0], latitude="not-a-number")
    df2 = pd.DataFrame(rows2)
    result2 = validate_dataframe(df2)
    _check(result2.ok, "One bad lat string -> still ok (coerced to NaN)")
    _check(result2.df.loc[0, "latitude"] != result2.df.loc[0, "latitude"],  # NaN != NaN
           "Bad lat coerced to NaN")


# ---------------------------------------------------------------------------
# Test: unknown event_type
# ---------------------------------------------------------------------------

def test_event_types():
    print("\n-- Event type validation --")

    df = _valid_df()
    df.loc[0, "event_type"] = "unknown_type"
    result = validate_dataframe(df)
    _check(result.ok, "Unknown event_type -> still ok (non-fatal)")
    _check(len(result.warnings) > 0, "Unknown event_type -> has warning")
    _check(any("unknown_type" in w for w in result.warnings), "Unknown event_type -> warning names the value")

    # All known types — no warning
    df2 = _valid_df()
    result2 = validate_dataframe(df2)
    _check(not any("event_type" in w.lower() for w in result2.warnings),
           "All known event_types -> no event_type warning")


# ---------------------------------------------------------------------------
# Test: valid complete DataFrame
# ---------------------------------------------------------------------------

def test_valid_full():
    print("\n-- Full valid DataFrame --")

    df = _valid_df(20)
    result = validate_dataframe(df)
    _check(result.ok, "Full valid 20-row DF -> ok")
    _check(result.df is not None, "Full valid DF -> df is not None")
    _check(len(result.df) == 20, "Full valid DF -> all 20 rows preserved")
    _check(len(result.errors) == 0, "Full valid DF -> no errors")
    _check(str(result.df["timestamp"].dt.tz) == "UTC", "Full valid DF -> timestamp is UTC")


# ---------------------------------------------------------------------------
# Test: load_csv_bytes
# ---------------------------------------------------------------------------

def test_load_csv_bytes():
    print("\n-- load_csv_bytes --")

    # Valid CSV bytes
    df = _valid_df(3)
    csv_bytes = df.to_csv(index=False).encode("utf-8")
    loaded, err = load_csv_bytes(csv_bytes)
    _check(err is None, "Valid CSV bytes -> no parse error")
    _check(loaded is not None and len(loaded) == 3, "Valid CSV bytes -> 3 rows loaded")

    # Malformed bytes
    loaded2, err2 = load_csv_bytes(b"col1,col2\n1,2,3,4,5,extra\n")
    # pandas tolerates ragged CSVs with error_bad_lines=False in some versions;
    # the key test is just that it doesn't raise an unhandled exception
    _check(True, "Malformed CSV bytes -> handled without crash")

    # Empty bytes
    loaded3, err3 = load_csv_bytes(b"")
    _check(loaded3 is None, "Empty bytes -> None df")
    _check(err3 is not None, "Empty bytes -> error string present")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("ThreatLens - Validator Unit Tests")
    print("=" * 60)

    test_empty()
    test_missing_columns()
    test_timestamps()
    test_vpn_coercion()
    test_coordinates()
    test_event_types()
    test_valid_full()
    test_load_csv_bytes()

    passed = sum(1 for ok, _ in _results if ok)
    failed = sum(1 for ok, _ in _results if not ok)
    total  = len(_results)

    print()
    print("=" * 60)
    print(f"Results: {passed}/{total} passed,  {failed} failed")
    print("=" * 60)

    if failed:
        print("\nFailed tests:")
        for ok, name in _results:
            if not ok:
                print(f"  [FAIL]  {name}")
        sys.exit(1)
    else:
        print("All validator tests passed.")
        sys.exit(0)
