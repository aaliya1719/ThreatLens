"""
dashboard.py
------------
ThreatLens — Security Log Analyzer  |  Streamlit dashboard

Run from the project root:
    streamlit run dashboard.py

The dashboard uses the existing src/ detection engine directly.
All analysis logic lives in src/detectors.py and src/validator.py.
This file is UI only.
"""

from __future__ import annotations

import io
import os
import sys
import tempfile
from pathlib import Path

import pandas as pd
import streamlit as st
import matplotlib
matplotlib.use("Agg")          # non-interactive backend — no display required
import matplotlib.pyplot as plt

# ── src/ on path so the existing modules are importable ─────────────────────
_SRC = Path(__file__).parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from validator import validate_dataframe, load_csv_bytes
from detectors import run_all_detectors, DETECTORS
from generate_dataset import generate
from report_builder import build_report

# ---------------------------------------------------------------------------
# Page config (must be the FIRST Streamlit call)
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="ThreatLens — Security Log Analyzer",
    page_icon=":shield:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "#C0392B",
    "HIGH":     "#E67E22",
    "MEDIUM":   "#F4D03F",
    "LOW":      "#27AE60",
}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

RULE_DOCS = {
    "R-01": ("Brute Force",              "HIGH",     "≥ 5 login failures from same IP within 10 min"),
    "R-02": ("Credential Stuffing",      "HIGH",     "≥ 3 failures across ≥ 3 usernames from one IP / 15 min"),
    "R-03": ("Off-Hours Login",          "MEDIUM",   "Successful login between 22:00–05:00 UTC"),
    "R-04": ("Impossible Travel",        "CRITICAL", "Same user logs in from locations > 500 km apart within 60 min"),
    "R-05": ("Repeated Account Lockout", "MEDIUM",   "Same account locked ≥ 3 times within 60 min"),
    "R-06": ("VPN Login Without MFA",    "LOW",      "Successful VPN login using non-MFA method"),
    "R-07": ("Password Reset Spike",     "MEDIUM",   "≥ 3 password reset requests from same IP within 30 min"),
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _severity_badge(sev: str) -> str:
    colors = {
        "CRITICAL": "background:#C0392B;color:#fff",
        "HIGH":     "background:#E67E22;color:#fff",
        "MEDIUM":   "background:#F4D03F;color:#000",
        "LOW":      "background:#27AE60;color:#fff",
    }
    style = colors.get(sev, "background:#888;color:#fff")
    return f'<span style="padding:2px 8px;border-radius:4px;font-size:0.82em;font-weight:600;{style}">{sev}</span>'


@st.cache_data(show_spinner=False)
def _run_analysis(df_key: str, df: pd.DataFrame) -> pd.DataFrame:
    """Cache analysis results keyed by a hash of the uploaded data."""
    return run_all_detectors(df)


def _generate_demo_df() -> pd.DataFrame:
    """Generate the synthetic demo dataset in memory (no disk write)."""
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "demo.csv")
        df = generate(n_rows=2000, output_path=out)
    df["timestamp"] = pd.to_datetime(df["timestamp"], utc=True)
    df["is_vpn"] = df["is_vpn"].astype(bool)
    return df


def _make_report_bytes(flagged_df: pd.DataFrame, raw_df: pd.DataFrame) -> bytes:
    """Build the .docx report and return its bytes for download."""
    with tempfile.TemporaryDirectory() as tmp:
        report_path = os.path.join(tmp, "ThreatLens_Report.docx")
        build_report(
            flagged_df=flagged_df,
            raw_df=raw_df,
            figure_paths=[],         # no pre-generated figures in dashboard mode
            author_name="ThreatLens Dashboard",
            output_path=report_path,
        )
        with open(report_path, "rb") as fh:
            return fh.read()


def _bar_chart_by_severity(flagged_df: pd.DataFrame) -> plt.Figure:
    counts = (
        flagged_df["severity"]
        .value_counts()
        .reindex(SEVERITY_ORDER)
        .fillna(0)
        .astype(int)
    )
    present = counts[counts > 0]
    if present.empty:
        return None

    fig, ax = plt.subplots(figsize=(5, 3))
    colors = [SEVERITY_COLORS[s] for s in present.index]
    bars = ax.bar(present.index, present.values, color=colors, edgecolor="white", linewidth=0.8)
    ax.bar_label(bars, padding=3, fontsize=10)
    ax.set_title("Alerts by Severity", fontsize=12, fontweight="bold", pad=8)
    ax.set_ylabel("Count")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    return fig


def _bar_chart_by_rule(flagged_df: pd.DataFrame) -> plt.Figure:
    counts = flagged_df["rule_name"].value_counts().sort_values()
    if counts.empty:
        return None

    fig, ax = plt.subplots(figsize=(7, max(3, len(counts) * 0.6)))
    colors = plt.cm.tab10(range(len(counts)))
    bars = ax.barh(counts.index, counts.values, color=colors, edgecolor="white", linewidth=0.5)
    ax.bar_label(bars, padding=3, fontsize=9)
    ax.set_title("Alerts by Detection Rule", fontsize=12, fontweight="bold", pad=8)
    ax.set_xlabel("Events Flagged")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    return fig


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

def _render_sidebar():
    with st.sidebar:
        st.markdown(
            "<div style='background:#1a376e;border-radius:6px;padding:10px 14px;margin-bottom:4px'>"
            "<span style='color:#fff;font-size:1.15em;font-weight:700'>🔍 ThreatLens</span><br>"
            "<span style='color:#b0c8f0;font-size:0.8em'>Security Log Analyzer</span>"
            "</div>",
            unsafe_allow_html=True,
        )
        st.caption("IBM SkillsBuild Cyber Security 2026")
        st.divider()

        st.markdown("### Detection Rules")
        for rule_id, (name, sev, logic) in RULE_DOCS.items():
            color = SEVERITY_COLORS.get(sev, "#888")
            st.markdown(
                f"**{rule_id}** — {name}  \n"
                f"<small style='color:{color}'>{sev}</small>  \n"
                f"<small>{logic}</small>",
                unsafe_allow_html=True,
            )
        st.divider()

        st.markdown("### About")
        st.info(
            "ThreatLens applies **rule-based detection** to structured "
            "authentication logs. An alert indicates a log pattern matched "
            "a rule — **it is not proof of an attack**. All findings "
            "require human review before any action is taken.",
            icon="ℹ️",
        )
        st.caption(
            "No data is stored permanently. "
            "Uploaded files are processed in memory and discarded when the session ends."
        )


# ---------------------------------------------------------------------------
# Data source panel
# ---------------------------------------------------------------------------

def _render_data_source() -> tuple[pd.DataFrame | None, str]:
    """
    Render the data-source panel and return (validated_df, source_label).
    Returns (None, "") if no data has been loaded yet.
    """
    st.subheader("1. Load Log Data")

    col_upload, col_demo = st.columns([3, 1], gap="large")

    with col_upload:
        uploaded = st.file_uploader(
            "Upload a CSV log file",
            type=["csv"],
            help="File must contain the required columns. See README for the schema.",
        )

    with col_demo:
        st.markdown("**Or use the demo dataset**")
        use_demo = st.button(
            "Generate synthetic demo logs",
            use_container_width=True,
            help="Generates 2,000 synthetic events with all 7 attack patterns injected.",
        )

    # ── Decide which source to use ───────────────────────────────────────────
    if uploaded is not None:
        raw_bytes = uploaded.read()
        raw_df, parse_err = load_csv_bytes(raw_bytes)
        if parse_err:
            st.error(f"**CSV parse error:** {parse_err}", icon="🚫")
            return None, ""
        result = validate_dataframe(raw_df)
        for err in result.errors:
            st.error(f"**Validation error:** {err}", icon="🚫")
        for warn in result.warnings:
            st.warning(warn, icon="⚠️")
        if not result.ok:
            return None, ""
        st.success(
            f"Loaded {len(result.df):,} valid events from **{uploaded.name}**.",
            icon="✅",
        )
        return result.df, uploaded.name

    if use_demo or st.session_state.get("demo_loaded"):
        if use_demo or "demo_df" not in st.session_state:
            with st.spinner("Generating synthetic demo dataset (2,000 events)…"):
                demo_df = _generate_demo_df()
            st.session_state["demo_df"] = demo_df
            st.session_state["demo_loaded"] = True
        demo_df = st.session_state["demo_df"]
        st.info(
            f"Using **synthetic demo dataset** — {len(demo_df):,} events. "
            "All data is fictional. Injected patterns ensure all 7 rules fire.",
            icon="🧪",
        )
        return demo_df, "demo_synthetic.csv"

    return None, ""


# ---------------------------------------------------------------------------
# Analysis + results
# ---------------------------------------------------------------------------

def _render_summary_metrics(raw_df: pd.DataFrame, flagged_df: pd.DataFrame):
    st.subheader("2. Summary")

    total = len(raw_df)
    n_flagged = len(flagged_df)
    n_critical = int((flagged_df["severity"] == "CRITICAL").sum()) if n_flagged else 0
    n_high     = int((flagged_df["severity"] == "HIGH").sum())     if n_flagged else 0
    n_medium   = int((flagged_df["severity"] == "MEDIUM").sum())   if n_flagged else 0
    n_low      = int((flagged_df["severity"] == "LOW").sum())      if n_flagged else 0
    n_rules    = flagged_df["rule_id"].nunique() if n_flagged else 0

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Events analysed", f"{total:,}")
    c2.metric("Alerts fired", f"{n_flagged:,}")
    c3.metric("Rules triggered", str(n_rules))
    c4.metric("CRITICAL", str(n_critical), delta=None)
    c5.metric("HIGH", str(n_high), delta=None)
    c6.metric("MEDIUM / LOW", f"{n_medium} / {n_low}")

    st.caption(
        "An alert indicates a log entry matched a detection rule. "
        "**This is not confirmation of an attack.** Review each finding manually."
    )


def _render_charts(flagged_df: pd.DataFrame):
    st.subheader("3. Charts")

    if flagged_df.empty:
        st.info("No alerts to visualise.", icon="ℹ️")
        return

    col_sev, col_rule = st.columns(2, gap="large")

    with col_sev:
        fig_sev = _bar_chart_by_severity(flagged_df)
        if fig_sev:
            st.pyplot(fig_sev, use_container_width=True)
            plt.close(fig_sev)

    with col_rule:
        fig_rule = _bar_chart_by_rule(flagged_df)
        if fig_rule:
            st.pyplot(fig_rule, use_container_width=True)
            plt.close(fig_rule)


def _render_alert_table(flagged_df: pd.DataFrame):
    st.subheader("4. Alert Table")

    if flagged_df.empty:
        st.info("No alerts detected in this dataset.", icon="✅")
        return

    # ── Filters ──────────────────────────────────────────────────────────────
    col_f1, col_f2, col_f3 = st.columns(3)

    with col_f1:
        sev_options = ["All"] + [s for s in SEVERITY_ORDER if s in flagged_df["severity"].values]
        sev_filter = st.selectbox("Filter by Severity", sev_options, key="sev_filter")

    with col_f2:
        rule_options = ["All"] + sorted(flagged_df["rule_id"].unique().tolist())
        rule_filter = st.selectbox("Filter by Rule", rule_options, key="rule_filter")

    with col_f3:
        search = st.text_input("Search IP or username", key="search_filter", placeholder="e.g. 192.168.1.1")

    # ── Apply filters ─────────────────────────────────────────────────────────
    view = flagged_df.copy()
    if sev_filter != "All":
        view = view[view["severity"] == sev_filter]
    if rule_filter != "All":
        view = view[view["rule_id"] == rule_filter]
    if search.strip():
        mask = (
            view["source_ip"].str.contains(search.strip(), case=False, na=False) |
            view["username"].str.contains(search.strip(), case=False, na=False)
        )
        view = view[mask]

    st.caption(f"Showing {len(view):,} of {len(flagged_df):,} alerts")

    # ── Display columns ───────────────────────────────────────────────────────
    display_cols = [
        "timestamp", "rule_id", "rule_name", "severity",
        "username", "source_ip", "country", "event_type", "explanation",
    ]
    # Truncate explanation for table readability (full text in expander below)
    view_display = view[display_cols].copy()
    view_display["explanation"] = view_display["explanation"].str[:90] + "…"
    view_display = view_display.rename(columns={
        "timestamp": "Timestamp",
        "rule_id": "Rule",
        "rule_name": "Rule Name",
        "severity": "Severity",
        "username": "Username",
        "source_ip": "Source IP",
        "country": "Country",
        "event_type": "Event Type",
        "explanation": "Explanation (truncated)",
    })

    st.dataframe(
        view_display,
        use_container_width=True,
        height=min(40 + 35 * min(len(view_display), 20), 750),
        hide_index=True,
    )

    # ── Expanded detail for top critical/high ─────────────────────────────────
    top_hits = view[view["severity"].isin(["CRITICAL", "HIGH"])].head(5)
    if not top_hits.empty:
        with st.expander(f"Top {len(top_hits)} CRITICAL/HIGH alert details"):
            for _, row in top_hits.iterrows():
                sev = row["severity"]
                color = SEVERITY_COLORS.get(sev, "#888")
                st.markdown(
                    f"<div style='border-left:4px solid {color};padding:6px 12px;margin-bottom:8px;'>"
                    f"<strong>[{row['rule_id']}] {row['rule_name']}</strong> &nbsp; "
                    f"<span style='color:{color};font-weight:600'>{sev}</span><br>"
                    f"<small>{row['timestamp']} &nbsp;|&nbsp; {row['username']} @ {row['source_ip']} ({row['country']})</small><br>"
                    f"{row['explanation']}"
                    f"</div>",
                    unsafe_allow_html=True,
                )


def _render_downloads(flagged_df: pd.DataFrame, raw_df: pd.DataFrame, source_label: str):
    st.subheader("5. Downloads")

    if flagged_df.empty:
        st.info("No alerts to download.", icon="ℹ️")
        return

    col_csv, col_docx = st.columns(2, gap="large")

    with col_csv:
        csv_bytes = flagged_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download Flagged Events (CSV)",
            data=csv_bytes,
            file_name="threatlens_flagged_events.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.caption(f"{len(flagged_df):,} alert rows, all columns included.")

    with col_docx:
        with st.spinner("Building investigation report…"):
            try:
                docx_bytes = _make_report_bytes(flagged_df, raw_df)
                st.download_button(
                    label="Download Investigation Report (DOCX)",
                    data=docx_bytes,
                    file_name="threatlens_report.docx",
                    mime="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    use_container_width=True,
                )
                st.caption("Auto-generated Word report with findings, rules, and recommendations.")
            except Exception as exc:
                st.error(f"Report generation failed: {exc}", icon="🚫")


# ---------------------------------------------------------------------------
# Main layout
# ---------------------------------------------------------------------------

def main():
    # ── Header ───────────────────────────────────────────────────────────────
    st.markdown(
        """
        <div style='background:linear-gradient(90deg,#1a376e,#2e5fa3);
                    padding:18px 24px;border-radius:8px;margin-bottom:16px'>
            <h1 style='color:#fff;margin:0;font-size:1.9em'>
                🔍 ThreatLens — Security Log Analyzer
            </h1>
            <p style='color:#b0c8f0;margin:4px 0 0'>
                IBM SkillsBuild Cyber Security 2026 &nbsp;|&nbsp;
                Rule-based authentication log analysis
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Disclaimer banner
    st.warning(
        "**Important:** ThreatLens uses rule-based pattern matching on structured log data. "
        "A flagged event indicates a log pattern matched a rule — "
        "**it is not proof of an attack or a security incident**. "
        "All alerts require human review. This tool does not claim to detect all threats "
        "and is not a substitute for a full SIEM.",
        icon="⚠️",
    )

    _render_sidebar()

    # ── Step 1: Load data ─────────────────────────────────────────────────────
    df, source_label = _render_data_source()

    if df is None:
        st.divider()
        _render_rules_reference()
        return

    st.divider()

    # ── Step 2: Run analysis ──────────────────────────────────────────────────
    # Use a deterministic cache key so re-uploads rerun analysis
    cache_key = f"{source_label}_{len(df)}_{hash(tuple(df['event_id'].iloc[:5].tolist()) if 'event_id' in df.columns else ())}"

    with st.spinner("Running detection rules…"):
        flagged_df = _run_analysis(cache_key, df)

    if flagged_df.empty:
        st.success("Analysis complete. No alerts were detected in this dataset.", icon="✅")
    else:
        st.success(
            f"Analysis complete — **{len(flagged_df):,} alert(s)** across "
            f"**{flagged_df['rule_id'].nunique()} rule(s)**.",
            icon="🚨",
        )

    # ── Results ───────────────────────────────────────────────────────────────
    _render_summary_metrics(df, flagged_df)
    st.divider()
    _render_charts(flagged_df)
    st.divider()
    _render_alert_table(flagged_df)
    st.divider()
    _render_downloads(flagged_df, df, source_label)


def _render_rules_reference():
    """Show the detection rules when no data is loaded yet."""
    st.subheader("Detection Rules Reference")
    st.caption(
        "Upload a CSV or click **Generate synthetic demo logs** to start. "
        "All seven rules below will be applied automatically."
    )
    rows = []
    for rid, (name, sev, logic) in RULE_DOCS.items():
        rows.append({"Rule ID": rid, "Name": name, "Severity": sev, "Logic": logic})
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)

    st.markdown("#### Required CSV Schema")
    schema = [
        ("event_id", "string", "Unique event ID (EVT-XXXXXXXX)"),
        ("timestamp", "datetime", "UTC timestamp — YYYY-MM-DD HH:MM:SS"),
        ("username", "string", "Account username"),
        ("source_ip", "string", "Client IPv4 address"),
        ("country", "string", "2-letter country code"),
        ("event_type", "string", "login_success | login_failure | logout | password_reset"),
        ("user_agent", "string", "Browser / client user-agent string"),
        ("session_id", "string", "Session ID (null for failures)"),
        ("auth_method", "string", "password | mfa | sso | api_key"),
        ("failure_reason", "string", "wrong_password | account_locked | mfa_failed | null"),
        ("is_vpn", "boolean", "True / False"),
        ("latitude", "float", "Approx. latitude of source IP"),
        ("longitude", "float", "Approx. longitude of source IP"),
    ]
    st.dataframe(
        pd.DataFrame(schema, columns=["Column", "Type", "Description"]),
        use_container_width=True,
        hide_index=True,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()
