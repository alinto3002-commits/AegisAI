import os
import subprocess

def ping_host(host: str):
    # Command injection via os.system (CWE-78)
    os.system("ping -c 1 " + host)

def run_backup_script(target_dir: str):
    # Subprocess execution with shell=True (CWE-78)
    cmd = f"tar -czf backup.tar.gz {target_dir}"
    subprocess.call(cmd, shell=True)
