import datetime
from process_enum import enumerate_processes
from parent_child import build_process_tree, detect_suspicious_pairs
from startup_audit import audit_systemd_services, audit_cron_jobs, flag_suspicious_services
from process_whitelist import detect_unauthorized_processes
from report_gen import generate_report

SUSPICIOUS_KEYWORDS = [
    'tmp', 'temp', 'hidden', 'unknown', 'backdoor',
    'exploit', 'payload', 'shell', 'reverse', 'malware'
]

def refine_service_alerts(alerts):
    refined = []
    for alert in alerts:
        name = alert['service'].lower()
        if 'systemd' not in name:
            refined.append(alert)
    return refined

def run_agent():
    print("=" * 60)
    print("  SENTINEL PROCESS MONITORING AGENT")
    print(f"  Started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    print("\n[STEP 1] Enumerating active processes...")
    process_list = enumerate_processes()
    print(f"  → {len(process_list)} processes found")

    print("\n[STEP 2] Analyzing parent-child process tree...")
    tree = build_process_tree()
    tree_alerts = detect_suspicious_pairs(tree)
    print(f"  → {len(tree_alerts)} suspicious pairs detected")

    print("\n[STEP 3] Auditing startup services and cron jobs...")
    services = audit_systemd_services()
    cron_entries = audit_cron_jobs()
    raw_service_alerts = flag_suspicious_services(services)
    service_alerts = refine_service_alerts(raw_service_alerts)
    print(f"  → {len(services)} services audited")
    print(f"  → {len(cron_entries)} cron entries found")
    print(f"  → {len(service_alerts)} suspicious services (after false positive filtering)")

    print("\n[STEP 4] Detecting unauthorized processes...")
    unknown_procs, path_alerts = detect_unauthorized_processes()
    print(f"  → {len(unknown_procs)} unknown/unlisted processes")
    print(f"  → {len(path_alerts)} processes from suspicious paths")

    print("\n[STEP 5] Generating reports...")
    json_path, txt_path = generate_report(
        process_list,
        tree_alerts,
        service_alerts,
        cron_entries,
        unknown_procs,
        path_alerts
    )
    print(f"  → JSON report: {json_path}")
    print(f"  → TXT report : {txt_path}")

    total_alerts = len(tree_alerts) + len(service_alerts) + len(path_alerts)
    print("\n" + "=" * 60)
    print(f"  SCAN COMPLETE — {total_alerts} total alerts generated")
    print("=" * 60)

if __name__ == "__main__":
    run_agent()
