import os
import subprocess
import sys

# Target the EXT4 Linux partition explicitly
current_dir = "/home/force123/roshyy/Kyber-6G project/Kyber-6G project/ns-3-dev"
ns3_path = os.path.join(current_dir, "ns3")
script_path = os.path.join(current_dir, "scratch/run_drone_experiments.sh")

print(f"[Pipeline] Hardcoded execution dir: {current_dir}")

def convert_to_lf(filepath):
    try:
        if not os.path.exists(filepath):
            print(f"[Pipeline] Error: File {filepath} does not exist.")
            return False
            
        with open(filepath, 'rb') as f:
            content = f.read()
        content = content.replace(b'\r\n', b'\n')
        with open(filepath, 'wb') as f:
            f.write(content)
        os.chmod(filepath, 0o755)
        print(f"[Pipeline] Successfully converted {filepath} to LF format.")
        return True
    except Exception as e:
        print(f"[Pipeline] Failed to process {filepath}: {e}")
        return False

# Strip CRLF
convert_to_lf(ns3_path)
convert_to_lf(script_path)

print(f"[Pipeline] Executing drone evaluation experiments...")
try:
    env = os.environ.copy()
    if "PYTHONPATH" in env:
        del env["PYTHONPATH"]
        
    process = subprocess.Popen(
        ["bash", script_path], 
        cwd=current_dir, 
        env=env,
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        text=True
    )
    
    for line in iter(process.stdout.readline, ''):
        print(line, end='')
        sys.stdout.flush()
        
    process.wait()
    print(f"[Pipeline] Drone evaluation finished with exit code {process.returncode}")
    
except Exception as e:
    print(f"[Pipeline] Execution crashed completely: {e}")
