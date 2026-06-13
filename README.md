# sentinel-process-agent
### Windows Service & Process Monitoring Agent

A Python-based process and service monitoring agent that detects 
malicious, unauthorized, or suspicious process behavior. 
Built and tested on Kali Linux as a Linux-compatible implementation 
of Windows process monitoring concepts.

---

## Project Structure

| File | Purpose |
|------|---------|
| agent.py | Main runner — orchestrates all modules |
| process_enum.py | Enumerates all active processes |
| parent_child.py | Detects suspicious parent-child relationships |
| startup_audit.py | Audits systemd services and cron jobs |
| process_whitelist.py | Flags unknown and suspicious-path processes |
| report_gen.py | Generates JSON and TXT detection reports |

---

## How It Works

1. Enumerates all running processes with PID, PPID, path, and user
2. Builds a process tree and checks for anomalous parent-child pairs
3. Audits startup services and scheduled cron jobs
4. Compares processes against a whitelist and flags suspicious paths
5. Exports a timestamped JSON report and plain-text summary

---
## Sample Output

    SENTINEL PROCESS MONITORING AGENT
    Started: 2026-06-08 05:36:28
    [STEP 1] Enumerating active processes... 174 processes found
    [STEP 2] Analyzing parent-child process tree... 0 suspicious pairs
    [STEP 3] Auditing startup services... 127 services, 18 cron entries
    [STEP 4] Detecting unauthorized processes... 72 unknown processes
    [STEP 5] Generating reports... JSON + TXT reports exported

---
---

## Requirements

- Python 3.x
- psutil library

## Installation

pip install psutil
python3 agent.py
