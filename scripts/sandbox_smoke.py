#!/usr/bin/env python3
"""
Fixed sandbox checks for SENTINEL's sandbox_smoke.py.

Run standalone:
    SENTINEL_SANDBOX_RUNTIME=runsc-nonet python scripts/sandbox_smoke_fixes.py

Or import into sandbox_smoke.py and register the check_* functions.
Each check returns (passed: bool, detail: str).

Findings these encode (gVisor / runsc):
  * NoNewPrivs is not shown in /proc/self/status -> probe with prctl(39) instead.
  * --pids-limit counts the sentry's own host threads (~50-80 overhead), and
    hitting it kills the container (exit 2, no output) instead of EAGAIN.
  * --pids-limit 32 does not even start under runsc.
  * docker exit 125 = failed to start, never a valid "pass".
"""
import os
import subprocess
import sys

IMAGE = os.environ.get("SENTINEL_SANDBOX_IMAGE", "python:3.12-slim")
RUNTIME = os.environ.get("SENTINEL_SANDBOX_RUNTIME", "runsc-nonet")
# Keep equal to the value the real harness passes (import it from config if possible).
PROD_PIDS_LIMIT = int(os.environ.get("SENTINEL_PIDS_LIMIT", "256"))
# runsc needs headroom for the sentry; below this the container won't start.
MIN_RUNSC_PIDS_LIMIT = 64


def _run(code, *, pids_limit, extra=(), timeout=90):
    cmd = [
        "docker", "run", "--rm", f"--runtime={RUNTIME}",
        "--network", "none",
        "--pids-limit", str(pids_limit),
        *extra,
        IMAGE, "python", "-u", "-c", code,
    ]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


# --- 1. no-new-privileges: probe from inside the sandbox -------------------
def check_no_new_privs():
    rc, out, err = _run(
        "import ctypes;print(ctypes.CDLL(None).prctl(39,0,0,0,0))",
        pids_limit=PROD_PIDS_LIMIT,
        extra=["--security-opt", "no-new-privileges", "--user", "65534:65534"],
    )
    return out == "1", f"rc={rc} prctl(PR_GET_NO_NEW_PRIVS)={out!r} {err[-120:]}"


# --- 2. pids limit: 200-fork probe at limit 64 -----------------------------
FORK_BOMB = """
import os,time
n=0
try:
    for _ in range(200):
        if os.fork()==0:
            time.sleep(5); os._exit(0)
        n+=1
except OSError:
    print("capped at",n,flush=True)
else:
    print("NOT capped, forked",n,flush=True)
"""


def check_pids_limit():
    rc, out, err = _run(FORK_BOMB, pids_limit=MIN_RUNSC_PIDS_LIMIT)
    if rc == 125:  # docker failed to start: not a real result
        return False, f"container failed to start: {err[-200:]}"
    if "NOT capped" in out:
        return False, out
    # runc: prints "capped at N", rc 0.
    # runsc: sentry dies at the cap, rc != 0, usually no output.
    if "capped at" in out or rc != 0:
        return True, f"rc={rc} out={out!r}"
    return False, f"unexpected: rc={rc} out={out!r} err={err[-120:]}"


# --- 3. headroom: modest workload must survive at the production limit -----
MODEST = """
import os,time
pids=[]
for _ in range(20):
    p=os.fork()
    if p==0:
        time.sleep(1); os._exit(0)
    pids.append(p)
for p in pids: os.waitpid(p,0)
print("ok",flush=True)
"""


def check_pids_headroom():
    rc, out, err = _run(MODEST, pids_limit=PROD_PIDS_LIMIT)
    return rc == 0 and out == "ok", f"rc={rc} out={out!r} {err[-120:]}"


# --- 4. harness floor: runsc must not be given a pids limit that can't boot -
def check_pids_floor():
    ok = PROD_PIDS_LIMIT >= MIN_RUNSC_PIDS_LIMIT
    return ok, f"PROD_PIDS_LIMIT={PROD_PIDS_LIMIT} (floor {MIN_RUNSC_PIDS_LIMIT})"


# --- 5. memory limit: must be an OOM kill (137), not a startup failure (125)
def check_memory_limit():
    rc, out, err = _run(
        "b=bytearray(600*1024*1024); b[::4096]=b'x'*len(b[::4096]); print('survived')",
        pids_limit=PROD_PIDS_LIMIT,
        extra=["--memory", "256m", "--memory-swap", "256m"],
    )
    return rc == 137 and "survived" not in out, f"exit={rc} out={out!r}"


CHECKS = [
    ("no-new-privileges set (prctl probe in sandbox)", check_no_new_privs),
    ("pids limit enforced (200 forks at limit 64 must be capped/killed)", check_pids_limit),
    (f"pids headroom (20 forks at production limit {PROD_PIDS_LIMIT})", check_pids_headroom),
    ("pids limit floor for runsc", check_pids_floor),
    ("memory limit enforced (must be OOM exit 137)", check_memory_limit),
]


def main():
    print(f"image={IMAGE} runtime={RUNTIME} prod_pids_limit={PROD_PIDS_LIMIT}")
    passed = 0
    for name, fn in CHECKS:
        try:
            ok, detail = fn()
        except subprocess.TimeoutExpired:
            ok, detail = False, "timed out"
        passed += ok
        print(f"{'PASS' if ok else 'FAIL'}  {name}\n      {detail}\n")
    print(f"{passed}/{len(CHECKS)} passed")
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
