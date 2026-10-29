#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Python on Slate: subprocess, threads, JSON and hashlib."""
import hashlib
import json
import subprocess
import threading

results = {}


def work(i):
    results[i] = hashlib.sha256(str(i).encode()).hexdigest()


threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
for t in threads:
    t.start()
for t in threads:
    t.join()
out = subprocess.run(["sh", "-c", "echo $((6*7))"], capture_output=True, text=True).stdout.strip()
doc = json.loads(json.dumps({"answer": int(out), "hashes": results}))
ok = doc["answer"] == 42 and len(doc["hashes"]) == 8
print("python-demo: threads=8 answer=%s %s" % (out, "ok" if ok else "FAILED"))
raise SystemExit(0 if ok else 1)
