
import re
from pathlib import Path

import pandas as pd
import streamlit as st

# Optional automatic refresh support
try:
    from streamlit_autorefresh import st_autorefresh
    AUTO_REFRESH_AVAILABLE = True
except ImportError:
    AUTO_REFRESH_AVAILABLE = False


# Dashboard configuration
st.set_page_config(
    page_title="Windows Process Investigator",
    page_icon="🛡️",
    layout="wide"
)

REPORT_FILE = Path(__file__).with_name("investigation_report.txt")


def get_field(block, field_name):
    """Extract a field from one investigation report block."""
    pattern = rf"^\s*{re.escape(field_name)}\s*:\s*(.*?)\s*$"
    match = re.search(pattern, block, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else "N/A"


def load_report():
    """Read and parse investigation_report.txt."""
    if not REPORT_FILE.exists():
        return pd.DataFrame()

    try:
        content = REPORT_FILE.read_text(
            encoding="utf-8",
            errors="replace"
        )
    except OSError as error:
        st.error(f"Could not read report file: {error}")
        return pd.DataFrame()

    blocks = re.split(
        r"(?=^\s*PROCESS INVESTIGATION\s*$)",
        content,
        flags=re.MULTILINE | re.IGNORECASE
    )

    records = []

    for block in blocks:
        if not re.search(
            r"^\s*PROCESS INVESTIGATION\s*$",
            block,
            re.MULTILINE | re.IGNORECASE
        ):
            continue

        process = get_field(block, "Process")

        if process == "N/A":
            continue

        records.append({
            "Time": get_field(block, "Time"),
            "Process": process,
            "PID": get_field(block, "PID"),
            "Parent": get_field(block, "Parent"),
            "User": get_field(block, "User"),
            "Integrity": get_field(block, "Integrity"),
            "Severity": get_field(block, "Severity").upper(),
            "Reason": get_field(block, "Reason"),
            "Command Line": get_field(block, "CommandLine"),
            "Hashes": get_field(block, "Hashes"),
        })

    return pd.DataFrame(records)


# Dashboard heading
st.title("🛡️ Windows Process Investigation Dashboard")
st.caption("Sysmon-based Windows process investigation")

# Automatic refresh every 5 seconds
if AUTO_REFRESH_AVAILABLE:
    st_autorefresh(
        interval=5000,
        key="process_dashboard_refresh"
    )
else:
    st.info(
        "Automatic refresh is not installed. "
        "Install it using the command shown at the bottom."
    )

# Manual refresh
if st.button("🔄 Refresh Report"):
    st.rerun()

# Load report
df = load_report()

if df.empty:
    st.warning("No investigation records found.")
    st.write("Check that investigation_report.txt contains process records.")
    st.code(str(REPORT_FILE))
    st.stop()

# Normalize severity
df["Severity"] = (
    df["Severity"]
    .fillna("UNKNOWN")
    .astype(str)
    .str.strip()
    .str.upper()
)

# Security overview metrics
total = len(df)
high = int((df["Severity"] == "HIGH").sum())
medium = int((df["Severity"] == "MEDIUM").sum())
low = int((df["Severity"] == "LOW").sum())
unknown = int((df["Severity"] == "UNKNOWN").sum())

st.subheader("📊 Security Overview")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Records", total)
col2.metric("High Risk", high)
col3.metric("Medium Risk", medium)
col4.metric("Low Risk", low)

if unknown:
    st.caption(f"Records with unknown severity: {unknown}")

st.divider()

# HIGH severity alert
st.subheader("🚨 Security Alerts")

high_risk_processes = df[df["Severity"] == "HIGH"]

if not high_risk_processes.empty:
    st.error(
        f"ALERT: {len(high_risk_processes)} HIGH severity "
        "record(s) detected. Investigate these processes."
    )

    st.dataframe(
        high_risk_processes[
            ["Time", "Process", "PID", "Parent", "Reason"]
        ],
        use_container_width=True,
        hide_index=True
    )
else:
    st.success("No HIGH severity records found in the current report.")

st.caption(
    "Alerts depend on the severity assigned by your investigator script. "
    "A LOW severity result does not guarantee that a process is safe."
)

st.divider()

# Severity distribution chart
st.subheader("📈 Risk Distribution")

severity_counts = (
    df["Severity"]
    .value_counts()
    .reindex(["HIGH", "MEDIUM", "LOW"], fill_value=0)
)

st.bar_chart(severity_counts)

st.divider()

# Severity filter
st.subheader("🔍 Process Investigation Records")

severity_options = ["ALL"] + sorted(df["Severity"].unique().tolist())

selected_severity = st.selectbox(
    "Filter by severity",
    severity_options
)

filtered_df = df.copy()

if selected_severity != "ALL":
    filtered_df = filtered_df[
        filtered_df["Severity"] == selected_severity
    ]

st.caption(f"Showing {len(filtered_df)} of {total} records")

# Process table
display_columns = [
    "Time",
    "Process",
    "PID",
    "Parent",
    "User",
    "Integrity",
    "Severity",
    "Reason",
]

st.dataframe(
    filtered_df[display_columns],
    use_container_width=True,
    hide_index=True
)

# CSV export
st.subheader("⬇️ Export Investigation Report")

csv_data = filtered_df.to_csv(index=False).encode("utf-8-sig")

st.download_button(
    label="Download CSV Report",
    data=csv_data,
    file_name="process_investigation_report.csv",
    mime="text/csv"
)

st.caption(
    "CSV export contains records matching the current severity filter."
)

st.divider()

# Process details
st.subheader("📋 Process Details")

if not filtered_df.empty:
    selected_index = st.selectbox(
        "Select a process to inspect",
        filtered_df.index.tolist(),
        format_func=lambda index: (
            f"{filtered_df.loc[index, 'Process']} "
            f"(PID: {filtered_df.loc[index, 'PID']})"
        ),
        key="process_detail_selector"
    )

    selected_record = filtered_df.loc[selected_index]

    col1, col2 = st.columns(2)

    with col1:
        st.write("**Process:**", selected_record["Process"])
        st.write("**PID:**", selected_record["PID"])
        st.write("**Parent:**", selected_record["Parent"])
        st.write("**User:**", selected_record["User"])
        st.write("**Integrity:**", selected_record["Integrity"])

    with col2:
        st.write("**Time:**", selected_record["Time"])
        st.write("**Severity:**", selected_record["Severity"])
        st.write("**Reason:**", selected_record["Reason"])

    st.write("**Command Line**")
    st.code(str(selected_record["Command Line"]))

    st.write("**Hashes**")
    st.code(str(selected_record["Hashes"]))

else:
    st.info("No records match the selected severity filter.")

# Footer
st.divider()
st.caption(f"Report file: {REPORT_FILE}")

if AUTO_REFRESH_AVAILABLE:
    st.caption("Automatic refresh: every 5 seconds")
else:
    st.code("python -m pip install streamlit-autorefresh")
