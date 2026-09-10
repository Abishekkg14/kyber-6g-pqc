import subprocess
import sys

print("Invoking final orchestration pipeline...", flush=True)

try:
    cmd = [
        "wsl", "-d", "Ubuntu-22.04", "--exec", "bash", "-c",
        "python3 '/home/force123/roshyy/Kyber-6G project/Kyber-6G project/ns-3-dev/run_pipeline.py'"
    ]
    
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in iter(process.stdout.readline, ''):
        print(line, end='')
        sys.stdout.flush()
        
    process.wait()
    print(f"WSL Pipeline exited with code {process.returncode}")

except Exception as e:
    print(f"Failed to execute: {e}")
