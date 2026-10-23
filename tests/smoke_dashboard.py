"""
smoke_dashboard.py
------------------
Headless end-to-end smoke test that exercises every code path the Streamlit
dashboard uses, without needing a browser or Streamlit server.

Run:  python tests/smoke_dashboard.py
"""
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
SEVERITY_COLORS = {
    "CRITICAL": "#C0392B",
    "HIGH":     "#E67E22",
    "MEDIUM":   "#F4D03F",
    "LOW":      "#27AE60",
}

PASS = 0
FAIL = 0

def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        print(f"  [PASS]  {label}")
        PASS += 1
    else:
        print(f"  [FAIL]  {label}" + (f" — {detail}" if detail else ""))
        FAIL += 1

# ---------------------------------------------------------------------------
print("=== 1. Dependency imports ===")
# ---------------------------------------------------------------------------
try:
    import streamlit  # noqa: F401
    check("streamlit importable", True)
except ImportError as e:
    check("streamlit importable", False, str(e))

try:
    import numpy  # noqa: F401
    import seaborn  # noqa: F401
    import docx  # noqa: F401
    import faker  # noqa: F401
    import tabulate  # noqa: F401
    import pytz  # noqa: F401
    check("all other dependencies importable", True)
except ImportError as e:
    check("all other dependencies importable", False, str(e))

# ---------------------------------------------------------------------------
print()
print("=== 2. Synthetic dataset generation ===")
# ---------------------------------------------------------------------------
from generate_dataset import generate  # noqa: E402

with tempfile.TemporaryDirectory() as tmp:
    path = os.path.join(tmp, "test.csv")
    df_raw = generate(n_rows=2000, output_path=path)

check("generate() returns a DataFrame",   isinstance(df_raw, pd.DataFrame))
check("2000 rows produced",               len(df_raw) == 2000,  f"got {len(df_raw)}")
REQUIRED_COLS = [
    "event_id", "timestamp", "username", "source_ip", "country",
    "event_type", "user_agent", "session_id", "auth_method",
    "failure_reason", "is_vpn", "latitude", "longitude",
]
missing = [c for c in REQUIRED_COLS if c not in df_raw.columns]
check("all 13 schema columns present",    len(missing) == 0, f"missing: {missing}")

# ---------------------------------------------------------------------------
print()
print("=== 3. Validator ===")
# ---------------------------------------------------------------------------
from validator import validate_dataframe, load_csv_bytes  # noqa: E402

df_raw["timestamp"] = pd.to_datetime(df_raw["timestamp"], utc=True)
df_raw["is_vpn"]    = df_raw["is_vpn"].astype(bool)
result = validate_dataframe(df_raw)

check("validate_dataframe ok=True",    result.ok,          str(result.errors))
check("no validation errors",         len(result.errors) == 0, str(result.errors))
check("all 2000 rows pass validation", len(result.df) == 2000, f"got {len(result.df)}")

# round-trip through CSV bytes (simulates a file upload)
csv_bytes = df_raw.to_csv(index=False).encode("utf-8")
df_reload, parse_err = load_csv_bytes(csv_bytes)
check("load_csv_bytes round-trip has no parse error", parse_err is None, parse_err)
check("load_csv_bytes returns correct row count",      len(df_reload) == 2000, f"got {len(df_reload)}")

# ---------------------------------------------------------------------------
print()
print("=== 4. Detection engine ===")
# ---------------------------------------------------------------------------
from detectors import run_all_detectors, DETECTORS  # noqa: E402

flagged = run_all_detectors(result.df)
expected_rules = {"R-01", "R-02", "R-03", "R-04", "R-05", "R-06", "R-07"}
triggered      = set(flagged["rule_id"].unique())

check("flagged DataFrame is not empty",            not flagged.empty,  "no events flagged at all")
check("all 7 rules triggered",                     expected_rules == triggered,
      f"missing={expected_rules - triggered}, extra={triggered - expected_rules}")
check("all flagged rows have explanations",        flagged["explanation"].notna().all())
check("all severities are valid values",           flagged["severity"].isin(SEVERITY_ORDER).all())
check("rule_name column present and non-empty",    "rule_name" in flagged.columns and flagged["rule_name"].notna().all())

sev_counts = flagged["severity"].value_counts().to_dict()
check("CRITICAL alerts present (R-04)",  "CRITICAL" in sev_counts, str(sev_counts))
check("HIGH alerts present (R-01/R-02)", "HIGH"     in sev_counts, str(sev_counts))

# ---------------------------------------------------------------------------
print()
print("=== 5. CSV download ===")
# ---------------------------------------------------------------------------
csv_out   = flagged.to_csv(index=False).encode("utf-8")
df_csv_rt = pd.read_csv(io.BytesIO(csv_out))

check("CSV export non-empty",          len(csv_out) > 0)
check("CSV round-trip row count matches", len(df_csv_rt) == len(flagged), f"got {len(df_csv_rt)}, want {len(flagged)}")
check("CSV contains rule_id column",   "rule_id" in df_csv_rt.columns)
check("CSV contains explanation col",  "explanation" in df_csv_rt.columns)

# ---------------------------------------------------------------------------
print()
print("=== 6. DOCX report download ===")
# ---------------------------------------------------------------------------
from report_builder import build_report  # noqa: E402

with tempfile.TemporaryDirectory() as tmp:
    rpath = os.path.join(tmp, "report.docx")
    build_report(
        flagged_df=flagged,
        raw_df=result.df,
        figure_paths=[],
        author_name="ThreatLens Dashboard",
        output_path=rpath,
    )
    size       = os.path.getsize(rpath)
    with open(rpath, "rb") as fh:
        docx_bytes = fh.read()

check("DOCX file created",            size > 0, f"size={size}")
check("DOCX has valid PK header",     docx_bytes[:2] == b"PK",
      f"header={docx_bytes[:2]!r}")
check("DOCX larger than 10 KB",       size > 10_000,  f"only {size} bytes — suspiciously small")

# ---------------------------------------------------------------------------
print()
print("=== 7. Chart rendering ===")
# ---------------------------------------------------------------------------
# Severity bar chart
counts_sev = (
    flagged["severity"]
    .value_counts()
    .reindex(SEVERITY_ORDER)
    .fillna(0)
    .astype(int)
)
present_sev = counts_sev[counts_sev > 0]
fig1, ax1 = plt.subplots(figsize=(5, 3))
colors1 = [SEVERITY_COLORS[s] for s in present_sev.index]
ax1.bar(present_sev.index, present_sev.values, color=colors1)
buf1 = io.BytesIO()
fig1.savefig(buf1, format="png")
plt.close(fig1)
check("severity bar chart renders to PNG", len(buf1.getvalue()) > 0, f"bytes={len(buf1.getvalue())}")

# Rule horizontal bar chart
counts_rule = flagged["rule_name"].value_counts().sort_values()
fig2, ax2 = plt.subplots(figsize=(7, max(3, len(counts_rule) * 0.6)))
ax2.barh(counts_rule.index, counts_rule.values)
buf2 = io.BytesIO()
fig2.savefig(buf2, format="png")
plt.close(fig2)
check("rule bar chart renders to PNG",     len(buf2.getvalue()) > 0, f"bytes={len(buf2.getvalue())}")

# ---------------------------------------------------------------------------
print()
print("=== 8. Alert table filters ===")
# ---------------------------------------------------------------------------
# Severity filter
crit_rows = flagged[flagged["severity"] == "CRITICAL"]
check("severity filter CRITICAL -> rows > 0",    len(crit_rows) > 0, f"got {len(crit_rows)}")

# Rule filter
r01_rows = flagged[flagged["rule_id"] == "R-01"]
check("rule filter R-01 -> rows > 0",            len(r01_rows) > 0,  f"got {len(r01_rows)}")

# IP / username text search
search_term = "1"
mask = (
    flagged["source_ip"].str.contains(search_term, case=False, na=False) |
    flagged["username"].str.contains(search_term, case=False, na=False)
)
check("text search returns some rows",            mask.sum() > 0, f"got {mask.sum()}")

# Combined filter
combined = flagged[(flagged["severity"] == "HIGH") & (flagged["rule_id"] == "R-01")]
check("combined severity+rule filter works",      len(combined) >= 0)   # just must not crash

# Display column subset used by the dashboard table
display_cols = [
    "timestamp", "rule_id", "rule_name", "severity",
    "username", "source_ip", "country", "event_type", "explanation",
]
try:
    view = flagged[display_cols].copy()
    view["explanation"] = view["explanation"].str[:90] + "…"
    check("dashboard display columns accessible", True)
    check("explanation truncation works",         view["explanation"].str.len().max() <= 93)
except Exception as e:
    check("dashboard display columns accessible", False, str(e))

# ---------------------------------------------------------------------------
print()
print("=" * 60)
total = PASS + FAIL
print(f"Results: {PASS}/{total} passed,  {FAIL} failed")
if FAIL == 0:
    print("Dashboard smoke test PASSED — safe to submit.")
else:
    print("DASHBOARD SMOKE TEST FAILED — review failures above.")
print("=" * 60)
sys.exit(0 if FAIL == 0 else 1)
