"""
report_builder.py
-----------------
Builds the [AuthorName]_ProjectReport.docx from analysis results.

Depends only on python-docx and standard library.
Called from the final notebook cell.
"""

import os
from datetime import datetime, timezone

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": RGBColor(0xC0, 0x39, 0x2B),
    "HIGH":     RGBColor(0xE6, 0x7E, 0x22),
    "MEDIUM":   RGBColor(0xF1, 0xC4, 0x0F),
    "LOW":      RGBColor(0x27, 0xAE, 0x60),
}

RECOMMENDATIONS = {
    "R-01": "Enable account lockout policy after 5 failed attempts. Deploy IP-based rate limiting on login endpoints.",
    "R-02": "Implement CAPTCHA and per-IP request throttling. Monitor for known credential-leak databases.",
    "R-03": "Alert SOC team on off-hours logins. Require step-up MFA authentication for non-business-hours access.",
    "R-04": "Suspend session and force re-authentication. Notify user via out-of-band channel (email/SMS).",
    "R-05": "Trigger mandatory password reset workflow. Notify account owner of repeated lockout.",
    "R-06": "Enforce MFA policy for all VPN-originating authentication. Audit VPN ACLs.",
    "R-07": "Rate-limit password reset emails per IP. Add CAPTCHA to password reset flow.",
}


def _set_cell_bg(cell, hex_color: str):
    """Set table cell background colour via direct XML manipulation."""
    tc = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd = tcPr.find(qn("w:shd"))
    if shd is None:
        from docx.oxml import OxmlElement
        shd = OxmlElement("w:shd")
        tcPr.append(shd)
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_color)


def _heading(doc: Document, text: str, level: int = 1):
    h = doc.add_heading(text, level=level)
    h.alignment = WD_ALIGN_PARAGRAPH.LEFT
    return h


def _para(doc: Document, text: str, bold: bool = False, italic: bool = False):
    p = doc.add_paragraph()
    run = p.add_run(text)
    run.bold = bold
    run.italic = italic
    return p


# ---------------------------------------------------------------------------
# Main builder
# ---------------------------------------------------------------------------

def build_report(
    flagged_df,
    raw_df,
    figure_paths: list,
    author_name: str = "Student",
    output_path: str = "Aaliya_ProjectReport.docx",
):
    """
    Build the .docx project report.

    Parameters
    ----------
    flagged_df  : DataFrame returned by run_all_detectors()
    raw_df      : Original loaded DataFrame (for dataset statistics)
    figure_paths: List of PNG file paths to embed as figures
    author_name : Name printed on the cover page
    output_path : Destination .docx path
    """
    doc = Document()

    # ── Page margins ────────────────────────────────────────────────────────
    for section in doc.sections:
        section.top_margin    = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin   = Inches(1.25)
        section.right_margin  = Inches(1.25)

    # ── Cover Page ──────────────────────────────────────────────────────────
    cover_title = doc.add_paragraph()
    cover_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = cover_title.add_run("ThreatLens — Security Log Analyzer")
    run.bold = True
    run.font.size = Pt(24)
    run.font.color.rgb = RGBColor(0x1A, 0x37, 0x6E)

    doc.add_paragraph()
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub.add_run("Project Report\nIBM SkillsBuild Cyber Security 2026").italic = True

    doc.add_paragraph()
    meta = doc.add_paragraph()
    meta.alignment = WD_ALIGN_PARAGRAPH.CENTER
    ts_now = datetime.now(timezone.utc).strftime("%B %d, %Y")
    meta.add_run(f"Author: {author_name}\nDate: {ts_now}")

    doc.add_page_break()

    # ── 1. Executive Summary ─────────────────────────────────────────────────
    _heading(doc, "1. Executive Summary")
    n_events = len(raw_df)
    n_flagged = len(flagged_df) if flagged_df is not None and not flagged_df.empty else 0
    n_rules = flagged_df["rule_id"].nunique() if n_flagged > 0 else 0

    _para(doc, (
        f"ThreatLens analyzed {n_events:,} authentication log events spanning "
        f"{(raw_df['timestamp'].max() - raw_df['timestamp'].min()).days} days. "
        f"Rule-based analysis identified {n_flagged:,} suspicious events matching "
        f"{n_rules} distinct threat patterns. "
        "All detections are based on transparent, explainable rules requiring no "
        "machine-learning models or external threat intelligence feeds."
    ))

    if n_flagged > 0:
        sev_counts = flagged_df["severity"].value_counts()
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                p = doc.add_paragraph(style="List Bullet")
                run = p.add_run(f"{sev}: {count} event(s)")
                run.bold = True
                color = SEVERITY_COLORS.get(sev)
                if color:
                    run.font.color.rgb = color

    # ── 2. Dataset Overview ──────────────────────────────────────────────────
    _heading(doc, "2. Dataset Overview")
    _para(doc, (
        "The dataset used in this analysis is a clearly labelled SYNTHETIC authentication "
        "log generated by ThreatLens's bundled generator (src/generate_dataset.py). "
        "All usernames, IP addresses, and events are fictional. The dataset contains "
        "deliberately injected patterns that match each detection rule, "
        "so that the rule engine has events to find. It does not represent real user activity."
    ))
    _para(doc, "Dataset Statistics:", bold=True)

    stats_table = doc.add_table(rows=1, cols=2)
    stats_table.style = "Light Shading"
    hdr = stats_table.rows[0].cells
    hdr[0].text = "Metric"
    hdr[1].text = "Value"

    stats = [
        ("Total Events", f"{n_events:,}"),
        ("Date Range", f"{raw_df['timestamp'].min().date()} to {raw_df['timestamp'].max().date()}"),
        ("Unique Users", f"{raw_df['username'].nunique():,}"),
        ("Unique Source IPs", f"{raw_df['source_ip'].nunique():,}"),
        ("Unique Countries", f"{raw_df['country'].nunique():,}"),
        ("Login Failures", f"{(raw_df['event_type'] == 'login_failure').sum():,}"),
        ("Login Successes", f"{(raw_df['event_type'] == 'login_success').sum():,}"),
        ("Password Resets", f"{(raw_df['event_type'] == 'password_reset').sum():,}"),
    ]
    for label, value in stats:
        row = stats_table.add_row().cells
        row[0].text = label
        row[1].text = value

    doc.add_paragraph()
    _para(doc, (
        "Note: This is a clearly labeled synthetic dataset. All usernames, "
        "IP addresses, and session identifiers are fictional. No real user data "
        "was used in this project."
    ), italic=True)

    # ── 3. Detection Rules Applied ───────────────────────────────────────────
    _heading(doc, "3. Detection Rules Applied")
    _para(doc, (
        "ThreatLens applies seven deterministic, rule-based detectors. "
        "Each rule has a fixed threshold, a defined time window, and produces "
        "a human-readable explanation for every flagged event."
    ))

    rules_table = doc.add_table(rows=1, cols=4)
    rules_table.style = "Light Shading"
    headers = ["Rule ID", "Name", "Logic Summary", "Severity"]
    for i, h in enumerate(headers):
        rules_table.rows[0].cells[i].text = h

    rules = [
        ("R-01", "Brute Force", "≥ 5 failures from same IP within 10 min", "HIGH"),
        ("R-02", "Credential Stuffing", "≥ 3 failures across ≥ 3 users from one IP / 15 min", "HIGH"),
        ("R-03", "Off-Hours Login", "Successful login between 22:00–05:00 UTC", "MEDIUM"),
        ("R-04", "Impossible Travel", "Same user logs in from locations > 500 km apart / 60 min", "CRITICAL"),
        ("R-05", "Repeated Account Lockout", "Same account locked ≥ 3 times within 60 min", "MEDIUM"),
        ("R-06", "VPN Login Without MFA", "Successful VPN login without MFA", "LOW"),
        ("R-07", "Password Reset Spike", "≥ 3 resets from same IP within 30 min", "MEDIUM"),
    ]
    for rule_id, name, logic, sev in rules:
        row = rules_table.add_row().cells
        row[0].text = rule_id
        row[1].text = name
        row[2].text = logic
        row[3].text = sev

    # ── 4. Findings ──────────────────────────────────────────────────────────
    _heading(doc, "4. Findings")
    if n_flagged == 0:
        _para(doc, "No suspicious events were detected in this dataset.")
    else:
        _para(doc, f"{n_flagged:,} events were flagged across {n_rules} rule categories.")
        doc.add_paragraph()

        # Summary table per rule
        summary = (
            flagged_df.groupby(["rule_id", "rule_name", "severity"])
            .size()
            .reset_index(name="flagged_count")
            .sort_values("rule_id")
        )
        sum_table = doc.add_table(rows=1, cols=4)
        sum_table.style = "Light Shading"
        for i, h in enumerate(["Rule ID", "Rule Name", "Severity", "Events Flagged"]):
            sum_table.rows[0].cells[i].text = h
        for _, row_data in summary.iterrows():
            row = sum_table.add_row().cells
            row[0].text = row_data["rule_id"]
            row[1].text = row_data["rule_name"]
            row[2].text = row_data["severity"]
            row[3].text = str(row_data["flagged_count"])

        # Top 5 flagged IPs
        doc.add_paragraph()
        _heading(doc, "4.1 Top Attacker IPs", level=2)
        top_ips = (
            flagged_df[flagged_df["severity"].isin(["CRITICAL", "HIGH"])]
            ["source_ip"].value_counts().head(5)
        )
        if not top_ips.empty:
            ip_table = doc.add_table(rows=1, cols=2)
            ip_table.style = "Light Shading"
            ip_table.rows[0].cells[0].text = "Source IP"
            ip_table.rows[0].cells[1].text = "High/Critical Flags"
            for ip, cnt in top_ips.items():
                r = ip_table.add_row().cells
                r[0].text = ip
                r[1].text = str(cnt)
        else:
            _para(doc, "No high/critical IP findings.")

    # ── 5. Visualizations ────────────────────────────────────────────────────
    if figure_paths:
        _heading(doc, "5. Visualizations")
        fig_labels = [
            "Figure 1: Login Events Over Time",
            "Figure 2: Hourly Login Heatmap (Day of Week vs Hour)",
            "Figure 3: Top 10 Source IPs by Failure Count",
            "Figure 4: Flagged Events by Severity",
            "Figure 5: Flagged Events by Rule",
            "Figure 6: Authentication Method Distribution",
        ]
        for i, path in enumerate(figure_paths):
            if os.path.exists(path):
                label = fig_labels[i] if i < len(fig_labels) else f"Figure {i+1}"
                _para(doc, label, bold=True)
                try:
                    doc.add_picture(path, width=Inches(5.5))
                    doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
                except Exception:
                    _para(doc, f"[Figure not renderable: {path}]", italic=True)
                doc.add_paragraph()

    # ── 6. Recommendations ───────────────────────────────────────────────────
    _heading(doc, "6. Recommendations")
    if n_flagged > 0:
        triggered_rules = flagged_df["rule_id"].unique()
        for rule_id in sorted(triggered_rules):
            rec = RECOMMENDATIONS.get(rule_id)
            if rec:
                p = doc.add_paragraph(style="List Bullet")
                p.add_run(f"{rule_id}: ").bold = True
                p.add_run(rec)
    else:
        _para(doc, "No specific recommendations — no threats were detected.")

    _para(doc, (
        "\nGeneral best practice: Centralise log collection into a SIEM, "
        "enforce MFA for all remote access, and review these findings with "
        "your security team before taking any automated action."
    ), italic=True)

    # ── 7. Limitations & Scope ────────────────────────────────────────────────
    _heading(doc, "7. Limitations and Scope")
    limitations = [
        "This analysis is limited to structured authentication log data. Network-layer, "
        "endpoint, or application-layer attacks are out of scope.",
        "Rule thresholds (e.g., 5 failures in 10 minutes) are illustrative. Production "
        "deployment requires tuning to the specific environment to reduce false positives.",
        "The dataset used here is synthetic. Results on real production logs will differ.",
        "This project does not claim to detect all cyberattacks. It demonstrates a subset "
        "of detectable patterns using rule-based methods.",
        "No automated remediation is performed. All outputs are advisory only.",
    ]
    for lim in limitations:
        doc.add_paragraph(lim, style="List Bullet")

    # ── 8. Conclusion ─────────────────────────────────────────────────────────
    _heading(doc, "8. Conclusion")
    _para(doc, (
        "ThreatLens demonstrates that meaningful threat detection can be achieved "
        "with transparent, rule-based logic applied to structured authentication logs — "
        "without requiring machine learning, paid services, or proprietary tools. "
        "The project is reproducible, beginner-accessible, and provides a solid "
        "foundation for further expansion into SIEM integration or anomaly-based detection."
    ))

    # ── Footer ────────────────────────────────────────────────────────────────
    doc.add_page_break()
    footer_p = doc.add_paragraph()
    footer_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    footer_run = footer_p.add_run(
        f"ThreatLens · IBM SkillsBuild Cyber Security 2026 · {author_name} · {ts_now}"
    )
    footer_run.font.size = Pt(9)
    footer_run.font.color.rgb = RGBColor(0x88, 0x88, 0x88)

    # ── Save ──────────────────────────────────────────────────────────────────
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    doc.save(output_path)
    print(f"[report_builder] Report saved -> {output_path}")
    return output_path
