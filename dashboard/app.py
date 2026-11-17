"""Streamlit dashboard for the cloud-native network security monitor.

Run from the repository root:
    streamlit run dashboard/app.py

The dashboard reads the SQLite database created by src/database.py. It is
read-only: it does not collect AWS logs, run detections, or change finding
statuses. Those responsibilities belong to the backend/pipeline.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path
from typing import Any

import pandas as pd
import streamlit as st


# ---------------------------------------------------------------------------
# Page configuration and paths
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Cloud Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "security_monitor.db"
DB_PATH = Path(os.getenv("DB_PATH", str(DEFAULT_DB_PATH))).expanduser()


# ---------------------------------------------------------------------------
# Database access
# ---------------------------------------------------------------------------

def get_connection() -> sqlite3.Connection:
    """Open a read-only connection to an existing SQLite database."""
    if not DB_PATH.exists():
        raise FileNotFoundError(
            f"Database not found at '{DB_PATH}'. Run the event collection and "
            "processing pipeline first, or set DB_PATH to the correct database."
        )

    # SQLite URI mode=ro prevents accidental database creation or mutation.
    connection = sqlite3.connect(f"{DB_PATH.resolve().as_uri()}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def table_exists(connection: sqlite3.Connection, table_name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,),
    ).fetchone()
    return row is not None


@st.cache_data(ttl=15, show_spinner=False)
def load_dashboard_data(db_path: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load recent events and findings; refresh automatically every 15 seconds."""
    path = Path(db_path)
    if not path.exists():
        return pd.DataFrame(), pd.DataFrame()

    connection = sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)
    try:
        event_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(events)")
        } if table_exists(connection, "events") else set()

        finding_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(findings)")
        } if table_exists(connection, "findings") else set()

        events = pd.DataFrame()
        findings = pd.DataFrame()

        if event_columns:
            events = pd.read_sql_query(
                """
                SELECT id, event_type, timestamp, source_ip, destination_ip,
                       destination_port, action, payload_json
                FROM events
                ORDER BY id DESC
                LIMIT 5000
                """,
                connection,
            )

        if finding_columns:
            findings = pd.read_sql_query(
                """
                SELECT id, rule_id, title, description, timestamp, source_ip,
                       destination_ip, destination_port, severity, risk_score,
                       status, recommendation, payload_json
                FROM findings
                ORDER BY id DESC
                LIMIT 5000
                """,
                connection,
            )

        return events, findings
    finally:
        connection.close()


def safe_payload(value: Any) -> dict[str, Any]:
    """Decode a stored JSON payload without crashing the dashboard."""
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        decoded = json.loads(value)
        return decoded if isinstance(decoded, dict) else {}
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# Presentation helpers
# ---------------------------------------------------------------------------

def show_database_error(message: str) -> None:
    st.error(message)
    st.info(
        "The dashboard is a visualization layer. First run the collector, "
        "parser, detector, risk scorer, and database pipeline so that "
        "`data/security_monitor.db` contains events and findings."
    )


def severity_counts(findings: pd.DataFrame) -> pd.Series:
    expected = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    if findings.empty or "severity" not in findings:
        return pd.Series(0, index=expected, dtype="int64")
    counts = findings["severity"].fillna("INFORMATIONAL").str.upper().value_counts()
    return pd.Series({severity: int(counts.get(severity, 0)) for severity in expected})


# ---------------------------------------------------------------------------
# Dashboard UI
# ---------------------------------------------------------------------------

st.title("🛡️ Cloud-Native Network Security Monitor")
st.caption(
    "AWS network telemetry • Explainable threat detection • Risk-based findings"
)

with st.sidebar:
    st.header("Dashboard controls")
    st.caption(f"Database: `{DB_PATH}`")
    refresh = st.button("↻ Refresh dashboard", use_container_width=True)
    if refresh:
        st.cache_data.clear()
        st.rerun()

    st.divider()
    st.markdown("**Data source**")
    st.caption("SQLite database populated by the backend processing pipeline.")
    st.markdown("**Refresh interval**")
    st.caption("Cached data refreshes every 15 seconds.")

if not DB_PATH.exists():
    show_database_error(
        f"SQLite database was not found: `{DB_PATH}`"
    )
    st.stop()

try:
    events_df, findings_df = load_dashboard_data(str(DB_PATH))
except (sqlite3.Error, pd.errors.DatabaseError, OSError) as exc:
    show_database_error(f"Unable to read the SQLite database: {exc}")
    st.stop()

if events_df.empty and findings_df.empty:
    st.warning("The database exists, but no events or findings are available yet.")
    st.info(
        "Add data through the backend pipeline. The dashboard will display "
        "events and findings after they are stored."
    )
    st.stop()

# Normalize fields used for filtering and visualization.
if not findings_df.empty:
    findings_df["severity"] = (
        findings_df["severity"].fillna("INFORMATIONAL").astype(str).str.upper()
    )
    findings_df["status"] = (
        findings_df["status"].fillna("OPEN").astype(str).str.upper()
    )
    findings_df["risk_score"] = pd.to_numeric(
        findings_df["risk_score"], errors="coerce"
    ).fillna(0).astype(int)
    findings_df["timestamp_dt"] = pd.to_datetime(
        findings_df["timestamp"], errors="coerce", utc=True
    )

if not events_df.empty:
    events_df["timestamp_dt"] = pd.to_datetime(
        events_df["timestamp"], errors="coerce", utc=True
    )

# Sidebar filters apply to findings and leave the headline total counts intact.
with st.sidebar:
    st.divider()
    st.subheader("Finding filters")

    available_severities = (
        sorted(findings_df["severity"].dropna().unique().tolist())
        if not findings_df.empty else []
    )
    selected_severities = st.multiselect(
        "Severity",
        options=available_severities,
        default=available_severities,
    )

    available_statuses = (
        sorted(findings_df["status"].dropna().unique().tolist())
        if not findings_df.empty else []
    )
    selected_statuses = st.multiselect(
        "Status",
        options=available_statuses,
        default=available_statuses,
    )

    available_rules = (
        sorted(findings_df["rule_id"].dropna().astype(str).unique().tolist())
        if not findings_df.empty else []
    )
    selected_rules = st.multiselect(
        "Detection rule",
        options=available_rules,
        default=available_rules,
    )

filtered_findings = findings_df.copy()
if not filtered_findings.empty:
    if selected_severities:
        filtered_findings = filtered_findings[
            filtered_findings["severity"].isin(selected_severities)
        ]
    else:
        filtered_findings = filtered_findings.iloc[0:0]

    if selected_statuses:
        filtered_findings = filtered_findings[
            filtered_findings["status"].isin(selected_statuses)
        ]
    else:
        filtered_findings = filtered_findings.iloc[0:0]

    if selected_rules:
        filtered_findings = filtered_findings[
            filtered_findings["rule_id"].astype(str).isin(selected_rules)
        ]
    else:
        filtered_findings = filtered_findings.iloc[0:0]

# Top-level KPI cards.
all_counts = severity_counts(findings_df)
open_count = (
    int((findings_df["status"] == "OPEN").sum())
    if not findings_df.empty else 0
)
average_risk = (
    round(float(findings_df["risk_score"].mean()), 1)
    if not findings_df.empty else 0
)

st.subheader("Security overview")
k1, k2, k3, k4, k5 = st.columns(5)
k1.metric("Network / API events", f"{len(events_df):,}")
k2.metric("Total findings", f"{len(findings_df):,}")
k3.metric("Open findings", f"{open_count:,}")
k4.metric("Critical findings", f"{int(all_counts['CRITICAL']):,}")
k5.metric("Average risk score", f"{average_risk}/100")

st.divider()

# Severity distribution and rule distribution.
left, right = st.columns(2)
with left:
    st.subheader("Findings by severity")
    severity_chart = all_counts[all_counts > 0]
    if severity_chart.empty:
        st.info("No findings to chart.")
    else:
        st.bar_chart(severity_chart)

with right:
    st.subheader("Findings by detection rule")
    if findings_df.empty:
        st.info("No findings to chart.")
    else:
        rule_counts = (
            findings_df.groupby("rule_id")
            .size()
            .sort_values(ascending=False)
        )
        st.bar_chart(rule_counts)

st.divider()

# Network monitoring summaries.
st.subheader("Network monitoring")
network_events = (
    events_df[events_df["event_type"] == "NETWORK_FLOW"].copy()
    if not events_df.empty and "event_type" in events_df
    else pd.DataFrame()
)

n1, n2, n3 = st.columns(3)
n1.metric("Network flow records", f"{len(network_events):,}")

if not network_events.empty:
    accepted = int(
        network_events["action"].fillna("").str.upper().eq("ACCEPT").sum()
    )
    rejected = int(
        network_events["action"].fillna("").str.upper().eq("REJECT").sum()
    )
    n2.metric("Accepted flows", f"{accepted:,}")
    n3.metric("Rejected flows", f"{rejected:,}")

    source_counts = (
        network_events["source_ip"].fillna("Unknown")
        .value_counts()
        .head(10)
    )
    port_counts = (
        pd.to_numeric(network_events["destination_port"], errors="coerce")
        .dropna()
        .astype(int)
        .value_counts()
        .head(10)
    )

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Top source IPs**")
        st.bar_chart(source_counts)
    with c2:
        st.markdown("**Most targeted destination ports**")
        st.bar_chart(port_counts)
else:
    n2.metric("Accepted flows", "—")
    n3.metric("Rejected flows", "—")
    st.info("No normalized NETWORK_FLOW records are currently stored.")

st.divider()

# Findings table.
st.subheader("Security findings")
st.caption(
    f"Showing {len(filtered_findings):,} findings after sidebar filters "
    f"(maximum {5000:,} most recently inserted records loaded)."
)

if filtered_findings.empty:
    st.info("No findings match the selected filters.")
else:
    display_columns = [
        "id",
        "rule_id",
        "title",
        "severity",
        "risk_score",
        "status",
        "timestamp",
        "source_ip",
        "destination_ip",
        "destination_port",
    ]
    display_columns = [
        column for column in display_columns
        if column in filtered_findings.columns
    ]
    st.dataframe(
        filtered_findings[display_columns],
        use_container_width=True,
        hide_index=True,
    )

    st.markdown("**Finding investigation**")
    options = filtered_findings["id"].astype(int).tolist()
    selected_finding_id = st.selectbox(
        "Select a finding ID",
        options=options,
        format_func=lambda value: (
            f"#{value} — "
            f"{filtered_findings.loc[filtered_findings['id'] == value, 'rule_id'].iloc[0]} — "
            f"{filtered_findings.loc[filtered_findings['id'] == value, 'title'].iloc[0]}"
        ),
    )
    selected_row = filtered_findings[
        filtered_findings["id"] == selected_finding_id
    ].iloc[0]

    with st.expander("View finding details", expanded=True):
        detail_left, detail_right = st.columns(2)
        with detail_left:
            st.write("**Description**")
            st.write(selected_row.get("description") or "Not provided.")
            st.write("**Recommended action**")
            st.write(selected_row.get("recommendation") or "Not provided.")
        with detail_right:
            st.write(f"**Severity:** {selected_row.get('severity', 'Unknown')}")
            st.write(f"**Risk score:** {selected_row.get('risk_score', 0)}/100")
            st.write(f"**Status:** {selected_row.get('status', 'Unknown')}")
            st.write(f"**Timestamp:** {selected_row.get('timestamp', 'Unknown')}")

        payload = safe_payload(selected_row.get("payload_json"))
        if payload:
            st.write("**Full finding evidence**")
            st.json(payload)

st.divider()

# Recent events table.
st.subheader("Recent events")
if events_df.empty:
    st.info("No events are stored yet.")
else:
    event_columns = [
        "id",
        "event_type",
        "timestamp",
        "source_ip",
        "destination_ip",
        "destination_port",
        "action",
    ]
    event_columns = [
        column for column in event_columns if column in events_df.columns
    ]
    st.dataframe(
        events_df[event_columns].head(100),
        use_container_width=True,
        hide_index=True,
    )

st.caption(
    "This dashboard presents heuristic security findings for investigation. "
    "A finding is not, by itself, confirmation of a successful attack."
)
