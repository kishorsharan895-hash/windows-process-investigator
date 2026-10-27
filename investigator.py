
import time
import win32evtlog
import win32api
import win32con
import xml.etree.ElementTree as ET
from datetime import datetime

LOG_NAME = "Microsoft-Windows-Sysmon/Operational"
QUERY = "*[System[(EventID=1)]]"
REPORT = "investigation_report.txt"
POLL_SECONDS = 3
BATCH_SIZE = 32


def close_handle(handle):
    """Close a Windows Event Log handle safely."""
    if handle is not None:
        try:
            win32api.CloseHandle(handle)
        except Exception:
            pass


def parse_event(event):
    xml = win32evtlog.EvtRender(
        event, win32evtlog.EvtRenderEventXml
    )
    root = ET.fromstring(xml)
    data = {}

    system_tag = "{http://schemas.microsoft.com/win/2004/08/events/event}System"
    record_tag = "{http://schemas.microsoft.com/win/2004/08/events/event}EventRecordID"

    record_id = 0
    system = root.find(system_tag)

    if system is not None:
        record = system.find(record_tag)
        if record is not None and record.text:
            record_id = int(record.text)

    for item in root.iter():
        if item.tag.endswith("Data"):
            name = item.attrib.get("Name")
            if name:
                data[name] = item.text or ""

    return record_id, data


def classify(data):
    process = data.get("Image", "")
    parent = data.get("ParentImage", "")

    severity = "LOW"
    reason = "No configured suspicious pattern matched"

    p = process.lower()
    par = parent.lower()

    if "\\temp\\" in p:
        severity = "MEDIUM"
        reason = "Executable running from Temp directory"

    suspicious_tools = [
        "mimikatz.exe",
        "nc.exe",
        "ncat.exe",
        "psexec.exe",
    ]

    if any(tool in p for tool in suspicious_tools):
        severity = "HIGH"
        reason = "Known suspicious tool name detected"

    office_apps = [
        "winword.exe",
        "excel.exe",
        "outlook.exe",
    ]
    scripting_tools = [
        "powershell.exe",
        "cmd.exe",
    ]

    if any(app in par for app in office_apps):
        if any(tool in p for tool in scripting_tools):
            severity = "HIGH"
            reason = "Office application spawned PowerShell/CMD"

    return process, parent, severity, reason


def write_event(data):
    process, parent, severity, reason = classify(data)

    details = (
        "\n----------------------------------------\n"
        "PROCESS INVESTIGATION\n"
        "Time       : " + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n"
        "Process    : " + process + "\n"
        "PID        : " + str(data.get("ProcessId", "")) + "\n"
        "Parent     : " + parent + "\n"
        "User       : " + str(data.get("User", "")) + "\n"
        "Integrity  : " + str(data.get("IntegrityLevel", "")) + "\n"
        "CommandLine: " + str(data.get("CommandLine", "")) + "\n"
        "Hashes     : " + str(data.get("Hashes", "")) + "\n"
        "Severity   : " + severity + "\n"
        "Reason     : " + reason + "\n"
    )

    print(details, flush=True)

    with open(REPORT, "a", encoding="utf-8") as f:
        f.write(details + "\n")
        f.flush()

    if severity == "HIGH":
        print("!!! HIGH SEVERITY ALERT !!!", flush=True)


def get_latest_record_id():
    handle = None
    events = []

    try:
        handle = win32evtlog.EvtQuery(
            LOG_NAME,
            win32evtlog.EvtQueryReverseDirection,
            QUERY,
        )

        events = win32evtlog.EvtNext(handle, 1)

        if not events:
            return 0

        record_id, _ = parse_event(events[0])
        return record_id

    finally:
        for event in events:
            close_handle(event)
        close_handle(handle)


def get_new_events(last_id):
    """Read recent records and return only records newer than last_id."""
    handle = None
    pending = []

    try:
        handle = win32evtlog.EvtQuery(
            LOG_NAME,
            win32evtlog.EvtQueryReverseDirection,
            QUERY,
        )

        stop_reading = False

        while not stop_reading:
            batch = win32evtlog.EvtNext(handle, BATCH_SIZE)

            if not batch:
                break

            for index, event in enumerate(batch):
                try:
                    record_id, data = parse_event(event)

                    if record_id <= last_id:
                        stop_reading = True
                        break

                    pending.append((record_id, data))

                finally:
                    close_handle(event)

            # Close any handles in the remainder of a batch we did not parse.
            if stop_reading:
                for event in batch[index + 1:]:
                    close_handle(event)
                break

    finally:
        close_handle(handle)

    return sorted(pending, key=lambda item: item[0])


def main():
    print("=" * 45)
    print(" WINDOWS PROCESS INVESTIGATOR")
    print(" LIVE MONITORING MODE")
    print("=" * 45)

    last_id = get_latest_record_id()

    with open(REPORT, "a", encoding="utf-8") as f:
        f.write(
            "\n\nMonitoring session started: "
            + datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            + "\n"
        )

    print("Monitoring new Sysmon process events...")
    print("Report:", REPORT)
    print("Poll interval:", POLL_SECONDS, "seconds")
    print("Stop with Ctrl+C.\n")

    try:
        while True:
            pending = get_new_events(last_id)

            for record_id, data in pending:
                write_event(data)
                last_id = max(last_id, record_id)

            time.sleep(POLL_SECONDS)

    except KeyboardInterrupt:
        print("\nMonitoring stopped by user.")

    except Exception as exc:
        print("\nMonitoring error:", exc)
        print("Check Sysmon, permissions, and Event Log configuration.")


if __name__ == "__main__":
    main()
