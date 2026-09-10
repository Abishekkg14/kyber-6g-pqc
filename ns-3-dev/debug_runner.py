import subprocess

try:
    res = subprocess.run(["python3", "./ns3", "--version"], capture_output=True, text=True)
    print("=== STDOUT ===")
    print(res.stdout)
    print("=== STDERR ===")
    print(res.stderr)
except Exception as e:
    print(f"FAILED TO EXECUTE: {e}")
