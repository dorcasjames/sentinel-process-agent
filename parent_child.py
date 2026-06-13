import psutil

SUSPICIOUS_PAIRS = [
    ('winword.exe', 'powershell.exe'),
    ('excel.exe', 'cmd.exe'),
    ('svchost.exe', 'cmd.exe'),
    ('explorer.exe', 'powershell.exe'),
    ('python3', 'bash'),
    ('bash', 'ncat'),
    ('bash', 'nc'),
    ('apache2', 'bash'),
    ('nginx', 'bash'),
    ('php', 'bash'),
    ('python3', 'sh'),
]

def build_process_tree():
    tree = {}
    for proc in psutil.process_iter(['pid', 'ppid', 'name']):
        try:
            info = proc.info
            tree[info['pid']] = {
                'name': info['name'],
                'ppid': info['ppid']
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return tree

def detect_suspicious_pairs(tree):
    alerts = []
    for pid, data in tree.items():
        child_name = data['name']
        ppid = data['ppid']
        if ppid in tree:
            parent_name = tree[ppid]['name']
            for suspicious_parent, suspicious_child in SUSPICIOUS_PAIRS:
                if parent_name == suspicious_parent and child_name == suspicious_child:
                    alerts.append({
                        'type': 'SUSPICIOUS_PARENT_CHILD',
                        'parent': parent_name,
                        'parent_pid': ppid,
                        'child': child_name,
                        'child_pid': pid,
                        'severity': 'HIGH'
                    })
    return alerts

if __name__ == "__main__":
    tree = build_process_tree()
    print(f"[+] Process tree built: {len(tree)} entries")
    alerts = detect_suspicious_pairs(tree)
    if alerts:
        print(f"[!] Suspicious pairs detected: {len(alerts)}")
        for a in alerts:
            print(a)
    else:
        print("[-] No suspicious parent-child pairs detected")
