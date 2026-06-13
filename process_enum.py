import psutil
import datetime

def enumerate_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'username', 'status', 'create_time']):
        try:
            info = proc.info
            ct = info.get('create_time')
            if ct is not None:
                info['create_time'] = datetime.datetime.fromtimestamp(ct).strftime('%Y-%m-%d %H:%M:%S')
            else:
                info['create_time'] = 'N/A'
            processes.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return processes

if __name__ == "__main__":
    procs = enumerate_processes()
    print(f"[+] Total processes found: {len(procs)}")
    for p in procs[:5]:
        print(p)
