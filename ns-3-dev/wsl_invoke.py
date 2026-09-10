import subprocess
import sys

print("Invoking WSL bash script natively through Subprocess to bypass PowerShell parsing...", flush=True)

try:
    cmd = [
        "wsl",
        "-d", "Ubuntu-22.04",
        "--",
        "bash", "-c",
        "cd '/home/force123/roshyy/Kyber-6G project/Kyber-6G project/ns-3-dev' && bash scratch/run_drone_experiments.sh"
    ]
    
    # Run the process and pipe output directly to stdout so we can see it live
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    
    for line in iter(process.stdout.readline, ''):
        print(line, end='')
        sys.stdout.flush()
        
    process.wait()
    print(f"WSL Pipeline exited with code {process.returncode}")

except Exception as e:
    print(f"Failed to execute: {e}")
