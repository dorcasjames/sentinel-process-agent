import subprocess
import os

SUSPICIOUS_KEYWORDS = [
    'tmp', 'temp', 'hidden', 'unknown', 'backdoor',
    'exploit', 'payload', 'shell', 'reverse', 'malware'
]

def audit_systemd_services():
    services = []
    try:
        result = subprocess.run(
            ['systemctl', 'list-units', '--type=service', '--all', '--no-pager', '--plain'],
            capture_output=True, text=True
        )
        lines = result.stdout.strip().split('\n')
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 4:
                services.append({
                    'name': parts[0],
                    'load': parts[1],
                    'active': parts[2],
                    'sub': parts[3],
                    'source': 'systemd'
                })
    except Exception as e:
        print(f"[!] systemctl error: {e}")
    return services

def audit_cron_jobs():
    cron_entries = []
    cron_paths = [
        '/etc/crontab',
        '/etc/cron.d',
        '/etc/cron.daily',
        '/etc/cron.hourly',
        '/etc/cron.weekly',
        '/etc/cron.monthly'
    ]
    for path in cron_paths:
        if os.path.isfile(path):
            try:
                with open(path, 'r') as f:
                    content = f.read().strip()
                    if content:
                        cron_entries.append({'path': path, 'content': content})
            except PermissionError:
                cron_entries.append({'path': path, 'content': 'ACCESS DENIED'})
        elif os.path.isdir(path):
            try:
                files = os.listdir(path)
                for f in files:
                    cron_entries.append({'path': os.path.join(path, f), 'content': 'directory entry'})
            except PermissionError:
                cron_entries.append({'path': path, 'content': 'ACCESS DENIED'})
    return cron_entries

def flag_suspicious_services(services):
    alerts = []
    for svc in services:
        name_lower = svc['name'].lower()
        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in name_lower:
                alerts.append({
                    'type': 'SUSPICIOUS_SERVICE_NAME',
                    'service': svc['name'],
                    'severity': 'HIGH'
                })
    return alerts

if __name__ == "__main__":
    print("[*] Auditing systemd services...")
    services = audit_systemd_services()
    print(f"[+] Services found: {len(services)}")
    print("[*] Auditing cron jobs...")
    crons = audit_cron_jobs()
    print(f"[+] Cron entries found: {len(crons)}")
    print("[*] Flagging suspicious services...")
    alerts = flag_suspicious_services(services)
    if alerts:
        print(f"[!] Suspicious services detected: {len(alerts)}")
        for a in alerts:
            print(a)
    else:
        print("[-] No suspicious services detected")
