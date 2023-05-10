import time
import subprocess
import random
import sys
import tqdm

with open("binaries-reduced") as f:
    files = f.readlines()

files = [f[:-1] for f in files] # remove trailing newline
random.shuffle(files)

print("Trying...")
mm = {}
i = 0
for file in tqdm.tqdm(files):
    i += 1
    ret = subprocess.run(["timeout", "3600", "python", "main.py", file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    mm[file] = b"Plan found!" in ret.stdout
    if mm[file]:
        print(f"{len(1 for k, v in mm.items() if v)}/{len(mm)} exploited.")
