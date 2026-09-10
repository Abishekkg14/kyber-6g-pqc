import os

def convert_to_lf(filepath):
    with open(filepath, 'rb') as f:
        content = f.read()
    content = content.replace(b'\r\n', b'\n')
    with open(filepath, 'wb') as f:
        f.write(content)
    print(f"Converted {filepath} to LF")

convert_to_lf('ns3')
convert_to_lf('scratch/run_drone_experiments.sh')
