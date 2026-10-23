# ThreatLens — Security Log Analyzer

> **IBM SkillsBuild Cyber Security 2026 Project**  
> Beginner-friendly, rule-based authentication log analysis with explainable threat detection.

---

## Overview

ThreatLens parses security/authentication event logs, applies transparent rule-based logic to detect suspicious patterns (brute-force attempts, off-hours logins, credential stuffing indicators, and impossible travel), assigns severity levels, and produces a human-readable investigation report.

Two interfaces are provided:
- **Streamlit dashboard** (`dashboard.py`) — interactive web UI with CSV upload, live charts, filterable alert table, and one-click report download.
- **Jupyter notebook** (`Aaliya_ThreatLens.ipynb`) — reproducible, step-by-step analysis with embedded charts and auto-generated report.

**No paid APIs, no credentials, no external services required.** A synthetic dataset generator is bundled so both interfaces run end-to-end without a real log source.

---

## Project Structure

```
ThreatLens/
├── dashboard.py                       ← Streamlit web dashboard
├── Aaliya_ThreatLens.ipynb            ← Jupyter analysis notebook
├── Aaliya_ProjectReport.docx          ← Auto-generated project report
├── requirements.txt                   ← Python dependencies
├── README.md                          ← This file
├── data/
│   ├── raw/
│   │   └── auth_logs.csv              ← Input dataset (synthetic or real)
│   └── processed/
│       └── flagged_events.csv         ← Events flagged by detection rules
├── outputs/
│   ├── figures/                       ← Charts saved by notebook
│   └── reports/                       ← Exported CSV reports
├── src/
│   ├── generate_dataset.py            ← Synthetic log generator
│   ├── detectors.py                   ← Rule-based detection engine
│   ├── validator.py                   ← Input validation (shared by dashboard + notebook)
│   └── report_builder.py             ← .docx report generation
└── tests/
    ├── test_detectors.py              ← Detector unit + integration tests
    └── test_validator.py              ← Validator unit tests
```

---

## Dataset Schema

| Column | Type | Description |
|--------|------|-------------|
| `event_id` | string | Unique event identifier (`EVT-XXXXXXXX`) |
| `timestamp` | datetime | UTC timestamp of the event |
| `username` | string | Account username |
| `source_ip` | string | Client IP address (IPv4) |
| `country` | string | Geolocation country of source IP |
| `event_type` | string | `login_success`, `login_failure`, `logout`, `password_reset` |
| `user_agent` | string | Browser / client user-agent string |
| `session_id` | string | Session identifier (null for failures) |
| `auth_method` | string | `password`, `mfa`, `sso`, `api_key` |
| `failure_reason` | string | `wrong_password`, `account_locked`, `mfa_failed`, null |
| `is_vpn` | boolean | Whether source IP is a known VPN exit node |
| `latitude` | float | Approx. latitude of source IP |
| `longitude` | float | Approx. longitude of source IP |

---

## Detection Rules (Explainable, Rule-Based)

| Rule ID | Name | Logic | Severity |
|---------|------|-------|----------|
| R-01 | Brute Force | ≥ 5 failed logins from same IP within 10 min | HIGH |
| R-02 | Credential Stuffing | ≥ 3 failed logins targeting ≥ 3 different usernames from one IP within 15 min | HIGH |
| R-03 | Off-Hours Login Success | Successful login between 22:00–05:00 UTC | MEDIUM |
| R-04 | Impossible Travel | Same user logs in from two countries > 500 km apart within 1 hour | CRITICAL |
| R-05 | Repeated Account Lockout | Same account locked ≥ 3 times within 1 hour | MEDIUM |
| R-06 | VPN + MFA Bypass | Successful login via VPN without MFA | LOW |
| R-07 | Password Reset Spike | ≥ 3 password reset requests from same IP within 30 min | MEDIUM |

> **Scope disclaimer:** These rules detect specific known patterns in structured log data. They do not claim to detect all cyberattacks or replace a full SIEM.

---

## Quick Start

### Streamlit Dashboard (recommended)

```bash
# 1. Clone / unzip the project
cd ThreatLens

# 2. Install dependencies (Python 3.9+ recommended)
pip install -r requirements.txt

# 3. Launch the dashboard
streamlit run dashboard.py

# 4. Open http://localhost:8501 in your browser
#    Click "Generate synthetic demo logs" to run a demo instantly,
#    or upload your own CSV file matching the schema below.
```

### Jupyter Notebook (for reproducible analysis)

```bash
# After installing dependencies (step 2 above):
jupyter notebook Aaliya_ThreatLens.ipynb

# Run all cells (Cell -> Run All)
# The notebook auto-generates a synthetic dataset and produces
# figures and a .docx report in the project root.
```

### Run tests

```bash
python tests/test_detectors.py   # 51 detector unit tests
python tests/test_validator.py   # validator unit tests
```

---

## Using a Real Dataset

Replace `data/raw/auth_logs.csv` with any CSV file that matches the schema above (see Dataset Schema). The notebook validates column presence at startup and will raise a clear error if required columns are missing.

**Compatible public sources (optional):**
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) — network intrusion dataset (requires column mapping)
- [KDD Cup 1999](http://kdd.ics.uci.edu/databases/kddcup99/kddcup99.html) — classic network log data (requires column mapping)
- Linux `/var/log/auth.log` — parse with the provided `src/generate_dataset.py` adapter

---

## Outputs

- **`outputs/figures/`** — PNG charts (login timeline, failure heatmap, top attacker IPs, severity distribution)
- **`outputs/reports/flagged_events.csv`** — Machine-readable flagged event export
- **`Aaliya_ProjectReport.docx`** — Auto-generated Word report with findings, charts, and recommendations

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `pandas` | Log parsing, grouping, rule evaluation |
| `numpy` | Numerical operations, distance calculations |
| `matplotlib` / `seaborn` | Visualizations |
| `python-docx` | Automated .docx report generation |
| `Faker` | Synthetic log data generation |
| `tabulate` | Pretty-print tables in notebook output |
| `pytz` | Timezone-aware datetime handling |

---

## Author

**Aaliya** — IBM SkillsBuild Cyber Security 2026

---

## Disclaimer

This project uses a **synthetic dataset** generated programmatically. All IP addresses, usernames, and events are fictional. The detection rules are educational demonstrations of rule-based log analysis and do not constitute production security tooling.
