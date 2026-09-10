import subprocess
import sys

print("Invoking native WSL python script to fix ns3 CRLF...", flush=True)

try:
    cmd = [
        "wsl", "-d", "Ubuntu-22.04", "--exec", "bash", "-c",
        "export PYTHONPATH=\"\" && cd '/home/force123/roshyy/Kyber-6G project/Kyber-6G project/ns-3-dev' && python3 fix_ns3.py"
    ]
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in iter(process.stdout.readline, ''):
        print(line, end='')
        sys.stdout.flush()
        
    process.wait()
    print(f"WSL Pipeline exited with code {process.returncode}")

except Exception as e:
    print(f"Failed to execute: {e}")
