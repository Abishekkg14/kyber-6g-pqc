import subprocess
print(subprocess.run([
    "wsl", "-d", "Ubuntu-22.04", "--", "bash", "-c",
    "cd \"/home/force123/roshyy/Kyber-6G project/Kyber-6G project/ns-3-dev\" && ls -la && python3 ns3 --version"
], capture_output=True, text=True))
