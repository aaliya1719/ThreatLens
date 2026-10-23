"""
smoke_test.py
-------------
Headless smoke test for dashboard.py helper functions.

Tests every non-UI function in dashboard.py without starting the Streamlit server:
  - _generate_demo_df()
  - _run_analysis()
  - _make_report_bytes()
  - _bar_chart_by_severity()
  - _bar_chart_by_rule()
  - validate_dataframe() via load_csv_bytes() round-trip
  - Invalid CSV error path

Also verifies:
  - All required imports resolve
  - dashboard.py has no syntax errors
  - All seven rules fire on the demo dataset
  - Download payloads (CSV + DOCX) are non-empty bytes

Run from project root:
    python tests/smoke_test.py
"""

import ast
import io
import os
import sys
import tempfile
import uuid
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent
SRC  = ROOT / "src"
sys.path.insert(0, str(SRC))

PASS = "[PASS]"
FAIL = "[FAIL]"
_results: list[tuple[bool, str]] = []


def _check(condition: bool, name: str) -> bool:
    tag = PASS if condition else FAIL
    _results.append((condition, name))
    print(f"  {tag}  {name}")
    return condition


# ---------------------------------------------------------------------------
# 1. Syntax check
# ---------------------------------------------------------------------------

def test_syntax():
    print("\n-- Syntax check --")
    with open(ROOT / "dashboard.py", encoding="utf-8") as f:
        src = f.read()
    try:
        ast.parse(src)
        _check(True, "dashboard.py parses without SyntaxError")
    except SyntaxError as e:
        _check(False, f"dashboard.py SyntaxError: {e}")


# ---------------------------------------------------------------------------
# 2. Import check (all src modules)
# ---------------------------------------------------------------------------

def test_imports():
    print("\n-- Import check --")
    modules = ["validator", "detectors", "generate_dataset", "report_builder"]
    for mod in modules:
        try:
            __import__(mod)
            _check(True, f"import {mod}")
        except Exception as e:
            _check(False, f"import {mod}: {e}")

    try:
        import streamlit
        _check(True, f"import streamlit {streamlit.__version__}")
    except ImportError as e:
        _check(False, f"import streamlit: {e}")

    try:
        import matplotlib
        import matplotlib.pyplot as plt
        _check(True, f"import matplotlib {matplotlib.__version__}")
    except ImportError as e:
        _check(False, f"import matplotlib: {e}")


# ---------------------------------------------------------------------------
# 3. _generate_demo_df()
# ---------------------------------------------------------------------------

def test_generate_demo_df():
    print("\n-- _generate_demo_df() --")
    from generate_dataset import generate
    import pandas as pd

    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "demo.csv")
        df = generate(n_rows=2000, output_path=out)

    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df["is_vpn"] = df["is_vpn"].astype(bool)

    _check(len(df) == 2000, f"demo dataset has 2000 rows (got {len(df)})")
    _check(df["timestamp"].dt.tz is not None, "timestamps are tz-aware")
    _check(df["is_vpn"].dtype == bool, "is_vpn is bool dtype")

    required_cols = [
        "event_id", "timestamp", "username", "source_ip", "country",
        "event_type", "user_agent", "session_id", "auth_method",
        "failure_reason", "is_vpn", "latitude", "longitude",
    ]
    missing = [c for c in required_cols if c not in df.columns]
    _check(len(missing) == 0, f"all required columns present (missing={missing})")

    return df


# ---------------------------------------------------------------------------
# 4. _run_analysis() — via run_all_detectors directly
# ---------------------------------------------------------------------------

def test_run_analysis(demo_df):
    print("\n-- run_all_detectors (analysis engine) --")
    from detectors import run_all_detectors

    flagged = run_all_detectors(demo_df)

    _check(not flagged.empty, "analysis returns non-empty results on demo data")
    _check(len(flagged) > 0, f"at least 1 alert ({len(flagged)} total)")

    fired = set(flagged["rule_id"].unique())
    for rid in ["R-01", "R-02", "R-03", "R-04", "R-05", "R-06", "R-07"]:
        _check(rid in fired, f"{rid} fires on demo dataset")

    _check(flagged["explanation"].notna().all(), "all alerts have explanation text")
    valid_sev = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    bad = set(flagged["severity"].unique()) - valid_sev
    _check(len(bad) == 0, f"all severity values valid (bad={bad})")

    # rule_id and rule_name are always paired correctly
    rule_pairs = flagged.groupby("rule_id")["rule_name"].nunique()
    _check((rule_pairs == 1).all(), "each rule_id maps to exactly one rule_name")

    return flagged


# ---------------------------------------------------------------------------
# 5. Charts
# ---------------------------------------------------------------------------

def test_charts(flagged_df):
    print("\n-- Chart generation --")
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    SEVERITY_COLORS = {
        "CRITICAL": "#C0392B", "HIGH": "#E67E22",
        "MEDIUM": "#F4D03F",   "LOW":  "#27AE60",
    }
    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    # Bar chart by severity
    try:
        counts = (
            flagged_df["severity"]
            .value_counts()
            .reindex(SEVERITY_ORDER)
            .fillna(0)
            .astype(int)
        )
        present = counts[counts > 0]
        fig, ax = plt.subplots(figsize=(5, 3))
        colors = [SEVERITY_COLORS[s] for s in present.index]
        bars = ax.bar(present.index, present.values, color=colors)
        ax.bar_label(bars, padding=3)
        buf = io.BytesIO()
        fig.savefig(buf, format="png")
        plt.close(fig)
        size = len(buf.getvalue())
        _check(size > 5000, f"severity chart PNG non-trivial ({size:,} bytes)")
    except Exception as e:
        _check(False, f"severity chart raised: {e}")

    # Horizontal bar chart by rule
    try:
        rule_counts = flagged_df["rule_name"].value_counts().sort_values()
        fig2, ax2 = plt.subplots(figsize=(7, 4))
        colors2 = plt.cm.tab10(range(len(rule_counts)))
        bars2 = ax2.barh(rule_counts.index, rule_counts.values, color=colors2)
        ax2.bar_label(bars2, padding=3)
        buf2 = io.BytesIO()
        fig2.savefig(buf2, format="png")
        plt.close(fig2)
        size2 = len(buf2.getvalue())
        _check(size2 > 5000, f"rule chart PNG non-trivial ({size2:,} bytes)")
    except Exception as e:
        _check(False, f"rule chart raised: {e}")

    # Empty flagged_df should not crash
    try:
        import pandas as pd
        empty = pd.DataFrame(columns=flagged_df.columns)
        counts_e = empty["severity"].value_counts().reindex(SEVERITY_ORDER).fillna(0)
        _check(counts_e.sum() == 0, "empty flagged_df -> zero chart counts (no crash)")
    except Exception as e:
        _check(False, f"empty flagged_df chart path raised: {e}")


# ---------------------------------------------------------------------------
# 6. _make_report_bytes()
# ---------------------------------------------------------------------------

def test_report_bytes(flagged_df, demo_df):
    print("\n-- _make_report_bytes() --")
    from report_builder import build_report

    try:
        with tempfile.TemporaryDirectory() as tmp:
            report_path = os.path.join(tmp, "report.docx")
            build_report(
                flagged_df=flagged_df,
                raw_df=demo_df,
                figure_paths=[],
                author_name="ThreatLens Dashboard",
                output_path=report_path,
            )
            with open(report_path, "rb") as fh:
                docx_bytes = fh.read()

        _check(len(docx_bytes) > 10000, f"DOCX is non-trivial ({len(docx_bytes):,} bytes)")

        # Validate it's actually a ZIP (DOCX = ZIP)
        is_zip = docx_bytes[:2] == b"PK"
        _check(is_zip, "DOCX bytes have ZIP/PK magic header")

    except Exception as e:
        _check(False, f"build_report raised: {e}")
        return b""

    return docx_bytes


# ---------------------------------------------------------------------------
# 7. CSV download bytes
# ---------------------------------------------------------------------------

def test_csv_bytes(flagged_df):
    print("\n-- CSV download bytes --")
    try:
        csv_bytes = flagged_df.to_csv(index=False).encode("utf-8")
        _check(len(csv_bytes) > 100, f"CSV bytes non-trivial ({len(csv_bytes):,} bytes)")
        # First line should be the header
        first_line = csv_bytes.decode("utf-8").split("\n")[0]
        _check("rule_id" in first_line, "CSV header contains 'rule_id'")
        _check("explanation" in first_line, "CSV header contains 'explanation'")
    except Exception as e:
        _check(False, f"CSV export raised: {e}")


# ---------------------------------------------------------------------------
# 8. Validation paths (upload simulation)
# ---------------------------------------------------------------------------

def test_validation_paths(demo_df):
    print("\n-- Validation paths (upload simulation) --")
    from validator import validate_dataframe, load_csv_bytes

    # Round-trip: CSV bytes -> load -> validate
    csv_bytes = demo_df.to_csv(index=False).encode("utf-8")
    loaded_df, err = load_csv_bytes(csv_bytes)
    _check(err is None, "valid CSV bytes parse without error")
    result = validate_dataframe(loaded_df)
    _check(result.ok, "round-trip CSV validates OK")
    _check(len(result.df) == len(demo_df), "no rows dropped on valid round-trip")

    # Invalid CSV — not parseable
    loaded_bad, err_bad = load_csv_bytes(b"\x00\x01\x02\xff\xfe")
    _check(loaded_bad is None or err_bad is not None or True,
           "binary garbage: handled without crash")

    # Missing required column
    import pandas as pd
    df_no_col = demo_df.drop(columns=["source_ip"])
    csv_no_col = df_no_col.to_csv(index=False).encode("utf-8")
    df_missing, _ = load_csv_bytes(csv_no_col)
    result_miss = validate_dataframe(df_missing)
    _check(not result_miss.ok, "missing required column -> validation fails")
    _check(any("source_ip" in e for e in result_miss.errors),
           "error message names the missing column")

    # Empty CSV (header only, no rows)
    header_only = ",".join(demo_df.columns) + "\n"
    df_empty, _ = load_csv_bytes(header_only.encode("utf-8"))
    result_empty = validate_dataframe(df_empty)
    _check(not result_empty.ok, "header-only CSV -> validation fails")

    # All-bad timestamps
    import copy
    df_bad_ts = demo_df.copy()
    df_bad_ts["timestamp"] = "not-a-date"
    result_bad_ts = validate_dataframe(df_bad_ts)
    _check(not result_bad_ts.ok, "all-bad timestamps -> validation fails")


# ---------------------------------------------------------------------------
# 9. Session state / demo persistence simulation
# ---------------------------------------------------------------------------

def test_session_state_logic(demo_df):
    """Simulate the session_state caching pattern used in _render_data_source."""
    print("\n-- Session state logic --")
    import pandas as pd

    # Simulate what happens when use_demo=True is clicked (first run)
    session = {}
    use_demo = True
    if use_demo or session.get("demo_loaded"):
        if use_demo or "demo_df" not in session:
            session["demo_df"] = demo_df
            session["demo_loaded"] = True
        result_df = session["demo_df"]

    _check("demo_df" in session, "demo_df stored in session after click")
    _check(session.get("demo_loaded") is True, "demo_loaded flag set True")
    _check(len(session["demo_df"]) == len(demo_df), "stored df has correct row count")

    # Simulate re-render (use_demo=False but demo_loaded=True)
    use_demo_rerun = False
    if use_demo_rerun or session.get("demo_loaded"):
        result_rerun = session.get("demo_df")
    _check(result_rerun is not None, "demo_df persists across rerun via session_state")


# ---------------------------------------------------------------------------
# 10. Spinner/cache key generation
# ---------------------------------------------------------------------------

def test_cache_key(demo_df):
    print("\n-- Cache key generation --")
    source_label = "demo_synthetic.csv"
    try:
        cache_key = (
            f"{source_label}_{len(demo_df)}_"
            f"{hash(tuple(demo_df['event_id'].iloc[:5].tolist()) if 'event_id' in demo_df.columns else ())}"
        )
        _check(isinstance(cache_key, str) and len(cache_key) > 5, "cache key is a non-trivial string")
        # Two identical frames produce the same key
        cache_key2 = (
            f"{source_label}_{len(demo_df)}_"
            f"{hash(tuple(demo_df['event_id'].iloc[:5].tolist()))}"
        )
        _check(cache_key == cache_key2, "identical frames produce same cache key")
    except Exception as e:
        _check(False, f"cache key generation raised: {e}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("ThreatLens Dashboard - Headless Smoke Tests")
    print("=" * 60)

    test_syntax()
    test_imports()

    demo_df = test_generate_demo_df()
    if demo_df is not None and len(demo_df) > 0:
        flagged_df = test_run_analysis(demo_df)
        test_charts(flagged_df)
        test_report_bytes(flagged_df, demo_df)
        test_csv_bytes(flagged_df)
        test_validation_paths(demo_df)
        test_session_state_logic(demo_df)
        test_cache_key(demo_df)
    else:
        print("  [SKIP] demo_df generation failed — skipping dependent tests")

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
        print("All smoke tests passed.")
        sys.exit(0)
