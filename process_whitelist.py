import psutil
import os

WHITELIST = [
    'systemd', 'kthreadd', 'bash', 'python3', 'sshd', 'cron',
    'dbus-daemon', 'NetworkManager', 'systemd-journal', 'systemd-logind',
    'systemd-udevd', 'systemd-resolved', 'systemd-timesyncd', 'polkitd',
    'rsyslogd', 'login', 'su', 'sudo', 'top', 'htop', 'ps', 'grep',
    'nano', 'vim', 'cat', 'ls', 'cp', 'mv', 'rm', 'mkdir', 'chmod',
    'chown', 'find', 'curl', 'wget', 'git', 'ssh', 'sftp', 'ftp',
    'apache2', 'nginx', 'mysql', 'postgresql', 'redis-server',
    'NetworkManager', 'wpa_supplicant', 'dhclient', 'avahi-daemon',
    'ufw', 'iptables', 'firewalld', 'auditd', 'accounts-daemon',
    'gdm', 'lightdm', 'Xorg', 'gnome-shell', 'xfce4-session',
    'kworker', 'ksoftirqd', 'migration', 'rcu_sched', 'watchdog',
    'pool_workqueue_release', 'kdevtmpfs', 'netns', 'inet_frag_wq',
    'kauditd', 'khungtaskd', 'oom_reaper', 'writeback', 'kcompactd0',
    'ksmd', 'khugepaged', 'kintegrityd', 'kblockd', 'blkcg_punt_bio',
    'edac-poller', 'devfreq_wq', 'kswapd0', 'kthrotld', 'irq',
    'i915', 'card0-crtc', 'ttm', 'xe', 'cfg80211', 'kstrp',
    'zswap-shrink', 'charger_manager', 'scsi_eh', 'scsi_tmf',
    'usb-storage', 'ipv6_addrconf', 'jbd2', 'ext4-rsv-conver',
    'nfsiod', 'rpciod', 'xprtiod', 'cryptd', 'vmstat', 'gvfsd',
    'at-spi-bus-laun', 'dconf-service', 'gvfs-udisks2-vo', 'udisksd',
    'packagekitd', 'ModemManager', 'thermald', 'irqbalance',
]

SUSPICIOUS_PATHS = [
    '/tmp/', '/var/tmp/', '/dev/shm/', '/run/user/',
    os.path.expanduser('~/Downloads/'),
    os.path.expanduser('~/Desktop/'),
]

def detect_unauthorized_processes():
    alerts = []
    unknown_processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'username']):
        try:
            info = proc.info
            name = info['name']
            exe = info['exe'] or ''
            is_whitelisted = any(
                name == w or name.startswith(w) for w in WHITELIST
            )
            if not is_whitelisted:
                unknown_processes.append({
                    'pid': info['pid'],
                    'name': name,
                    'exe': exe,
                    'username': info['username']
                })
            for sus_path in SUSPICIOUS_PATHS:
                if exe.startswith(sus_path):
                    alerts.append({
                        'type': 'PROCESS_FROM_SUSPICIOUS_PATH',
                        'pid': info['pid'],
                        'name': name,
                        'exe': exe,
                        'severity': 'CRITICAL'
                    })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return unknown_processes, alerts

if __name__ == "__main__":
    print("[*] Checking processes against whitelist...")
    unknown, path_alerts = detect_unauthorized_processes()
    print(f"[+] Unknown/unlisted processes: {len(unknown)}")
    for p in unknown[:10]:
        print(p)
    if path_alerts:
        print(f"\n[!] Processes running from suspicious paths: {len(path_alerts)}")
        for a in path_alerts:
            print(a)
    else:
        print("\n[-] No processes running from suspicious paths")
