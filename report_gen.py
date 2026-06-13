import json
import datetime
import os

def generate_report(process_list, tree_alerts, service_alerts, cron_entries, unknown_procs, path_alerts):
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

    report = {
        'report_metadata': {
            'title': 'Windows Service & Process Monitoring Agent — Detection Report',
            'generated': timestamp,
            'platform': 'Linux (Kali)',
            'total_processes_scanned': len(process_list),
        },
        'summary': {
            'suspicious_parent_child_pairs': len(tree_alerts),
            'suspicious_services': len(service_alerts),
            'cron_entries_found': len(cron_entries),
            'unknown_processes': len(unknown_procs),
            'processes_from_suspicious_paths': len(path_alerts),
            'total_alerts': len(tree_alerts) + len(service_alerts) + len(path_alerts)
        },
        'alerts': {
            'parent_child_alerts': tree_alerts,
            'service_alerts': service_alerts,
            'suspicious_path_alerts': path_alerts
        },
        'data': {
            'cron_entries': cron_entries,
            'unknown_processes': unknown_procs
        }
    }

    json_path = f'detection_report_{report_time}.json'
    with open(json_path, 'w') as f:
        json.dump(report, f, indent=4)

    txt_path = f'detection_report_{report_time}.txt'
    with open(txt_path, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("  SENTINEL PROCESS MONITORING AGENT — DETECTION REPORT\n")
        f.write("=" * 60 + "\n")
        f.write(f"  Generated  : {timestamp}\n")
        f.write(f"  Platform   : Linux (Kali)\n")
        f.write(f"  Processes  : {len(process_list)} scanned\n")
        f.write("=" * 60 + "\n\n")
        f.write("[ SUMMARY ]\n")
        f.write(f"  Suspicious parent-child pairs : {len(tree_alerts)}\n")
        f.write(f"  Suspicious services           : {len(service_alerts)}\n")
        f.write(f"  Cron entries found            : {len(cron_entries)}\n")
        f.write(f"  Unknown processes             : {len(unknown_procs)}\n")
        f.write(f"  Suspicious path processes     : {len(path_alerts)}\n")
        f.write(f"  TOTAL ALERTS                  : {len(tree_alerts) + len(service_alerts) + len(path_alerts)}\n\n")
        f.write("[ PARENT-CHILD ALERTS ]\n")
        if tree_alerts:
            for a in tree_alerts:
                f.write(f"  [HIGH] {a['parent']} (PID {a['parent_pid']}) → {a['child']} (PID {a['child_pid']})\n")
        else:
            f.write("  No suspicious parent-child relationships detected.\n")
        f.write("\n[ SERVICE ALERTS ]\n")
        if service_alerts:
            for a in service_alerts:
                f.write(f"  [HIGH] Suspicious service: {a['service']}\n")
        else:
            f.write("  No suspicious services detected.\n")
        f.write("\n[ SUSPICIOUS PATH ALERTS ]\n")
        if path_alerts:
            for a in path_alerts:
                f.write(f"  [CRITICAL] {a['name']} (PID {a['pid']}) running from {a['exe']}\n")
        else:
            f.write("  No processes running from suspicious paths.\n")
        f.write("\n[ UNKNOWN PROCESSES (first 20) ]\n")
        for p in unknown_procs[:20]:
            f.write(f"  PID {p['pid']} | {p['name']} | {p['exe'] or 'no path'} | {p['username']}\n")
        f.write("\n[ CRON ENTRIES ]\n")
        for c in cron_entries:
            f.write(f"  Path: {c['path']}\n")
        f.write("\n" + "=" * 60 + "\n")
        f.write("  END OF REPORT\n")
        f.write("=" * 60 + "\n")

    return json_path, txt_path

if __name__ == "__main__":
    print("[*] Report generator module loaded successfully")
