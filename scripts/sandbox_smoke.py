#!/usr/bin/env python3
"""L3 smoke test: run on a host with Docker (and optionally gVisor).

Drives sentinel.sandbox.runner.Sandbox, so it tests the exact `docker run` line SENTINEL builds.

  cd SENTINEL-main && pip install -e .
  python scripts/sandbox_smoke.py                        # plain Docker (runc)
  SENTINEL_SANDBOX_RUNTIME=runsc python scripts/sandbox_smoke.py   # gVisor
  python scripts/sandbox_smoke.py --image python:3.12-slim

Exit code 0 only if every check passes. Each check runs a tiny Python program inside the container
and judges its output. A check that cannot run (e.g. image pull failed) counts as a failure.
"""
import argparse
import json
import os
import subprocess
import sys

from sentinel.sandbox.runner import Sandbox, SandboxUnavailable

IMAGE = "python:3.12-slim"


def prog(code: str, **spec):
    return {"image": IMAGE, "command": ["python", "-c", code], **spec}


# Each program prints one JSON object. `judge` returns (ok, detail).
CHECKS = []


def check(name):
    def deco(fn):
        CHECKS.append((name, fn))
        return fn
    return deco


@check("no network by default (1.1.1.1:443 must be unreachable)")
def _net(sb):
    r = sb.run(prog("import socket,sys\n"
                    "try:\n socket.create_connection(('1.1.1.1',443),3); print('CONNECTED')\n"
                    "except Exception as e: print('blocked', type(e).__name__)"), "", {})
    return ("blocked" in r.stdout and "CONNECTED" not in r.stdout), r.stdout.strip() or r.stderr[-200:]


@check("DNS also fails with network=none")
def _dns(sb):
    r = sb.run(prog("import socket\n"
                    "try:\n socket.gethostbyname('example.com'); print('RESOLVED')\n"
                    "except Exception as e: print('blocked', type(e).__name__)"), "", {})
    return ("blocked" in r.stdout), r.stdout.strip() or r.stderr[-200:]


@check("root filesystem is read-only")
def _ro(sb):
    r = sb.run(prog("try:\n open('/etc/sentinel_probe','w').write('x'); print('WROTE')\n"
                    "except Exception as e: print('blocked', type(e).__name__)"), "", {})
    return ("blocked" in r.stdout), r.stdout.strip() or r.stderr[-200:]


@check("/tmp is writable but noexec")
def _tmp(sb):
    code = ("import os,stat,subprocess\n"
            "p='/tmp/x.sh'\nopen(p,'w').write('#!/bin/sh\\necho hi\\n'); os.chmod(p,0o755)\n"
            "try:\n subprocess.run([p],check=True,capture_output=True); print('EXECUTED')\n"
            "except Exception as e: print('wrote-but-noexec', type(e).__name__)")
    r = sb.run(prog(code), "", {})
    return ("wrote-but-noexec" in r.stdout), r.stdout.strip() or r.stderr[-200:]


@check("runs as 65534 (nobody), not root")
def _uid(sb):
    r = sb.run(prog("import os;print(os.getuid(),os.getgid())"), "", {})
    return r.stdout.split() == ["65534", "65534"], r.stdout.strip() or r.stderr[-200:]


@check("all capabilities dropped (CapEff == 0)")
def _caps(sb):
    code = ("for l in open('/proc/self/status'):\n"
            " if l.startswith('CapEff'): print(l.split()[1])")
    r = sb.run(prog(code), "", {})
    v = r.stdout.strip()
    return v != "" and int(v, 16) == 0, v or r.stderr[-200:]


@check("no-new-privileges set")
def _nnp(sb):
    code = ("for l in open('/proc/self/status'):\n"
            " if l.startswith('NoNewPrivs'): print(l.split()[1])")
    r = sb.run(prog(code), "", {})
    return r.stdout.strip() == "1", r.stdout.strip() or "(not reported; see note for gVisor)"


@check("memory limit enforced (600MB alloc under 256m must die)")
def _mem(sb):
    r = sb.run(prog("b=b'x'*(600*1024*1024); print('ALLOCATED')", timeout=30), "", {})
    return ("ALLOCATED" not in r.stdout and r.exit_code not in (0, None)), f"exit={r.exit_code}"


@check("pids limit enforced (64): forking 200 must hit the cap")
def _pids(sb):
    code = ("import os,time\nkids=0\n"
            "for _ in range(200):\n"
            " try:\n"
            "  if os.fork()==0: time.sleep(2); os._exit(0)\n"
            "  kids+=1\n"
            " except OSError: break\n"
            "print(kids)")
    r = sb.run(prog(code, timeout=30), "", {})
    try:
        n = int(r.stdout.strip().splitlines()[-1])
    except Exception:
        return False, r.stdout.strip() or r.stderr[-200:]
    return n < 100, f"forked {n} children before failing"


@check("timeout kills the container (no stray container left)")
def _timeout(sb):
    r = sb.run(prog("import time;time.sleep(60)", timeout=3), "", {})
    left = subprocess.run([sb.docker, "ps", "-q", "--filter", "name=sentinel-"],
                          capture_output=True, text=True).stdout.strip()
    return (r.timed_out and left == ""), f"timed_out={r.timed_out}, leftover containers={'yes' if left else 'no'}"


@check("secret arrives via env only, never in the docker argv")
def _env(sb):
    secret = "TOKEN-" + os.urandom(8).hex()
    argv = sb.command(prog("pass"), ["SENTINEL_TOKEN"])
    leaked = any(secret in a for a in argv)
    r = sb.run(prog("import os;print(os.environ.get('SENTINEL_TOKEN',''))"), "", {"SENTINEL_TOKEN": secret})
    return (not leaked and r.stdout.strip() == secret), f"in argv={leaked}, visible in container={r.stdout.strip() == secret}"


@check("host env (e.g. AWS_*, ANTHROPIC_API_KEY) is NOT visible in the container")
def _hostenv(sb):
    os.environ["SENTINEL_SMOKE_CANARY"] = "should-not-appear"
    r = sb.run(prog("import os;print(sorted(k for k in os.environ if 'CANARY' in k or 'AWS' in k or 'ANTHROPIC' in k))"),
               "", {})
    return r.stdout.strip() == "[]", r.stdout.strip() or r.stderr[-200:]


@check("stdin JSON args reach the tool")
def _stdin(sb):
    payload = json.dumps({"text": "hello"})
    r = sb.run(prog("import sys,json;print(json.load(sys.stdin)['text'])"), payload, {})
    return r.stdout.strip() == "hello", r.stdout.strip() or r.stderr[-200:]


def runtime_report(sb):
    """Informational: is this actually gVisor? Compares container kernel to host kernel."""
    r = sb.run(prog("import platform,subprocess\n"
                    "print(platform.release())\n"
                    "d=subprocess.run(['dmesg'],capture_output=True,text=True)\n"
                    "print('gvisor-dmesg' if 'gVisor' in (d.stdout+d.stderr) else 'no-gvisor-dmesg')"), "", {})
    host = os.uname().release
    lines = r.stdout.split()
    inside = lines[0] if lines else "?"
    gv = "gvisor-dmesg" in r.stdout
    print(f"\nruntime requested : {sb.runtime or 'default (runc)'}")
    print(f"host kernel       : {host}")
    print(f"container kernel  : {inside}")
    if sb.runtime:
        sandboxed = gv or inside != host
        print(f"gVisor in effect  : {'YES' if sandboxed else 'NO - container sees the host kernel; runtime not applied'}")
        return sandboxed
    return True


def main():
    global IMAGE
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", default=IMAGE)
    a = ap.parse_args()
    IMAGE = a.image
    sb = Sandbox()
    print(f"image={IMAGE} runtime={sb.runtime or 'default'}")
    failed = 0
    for name, fn in CHECKS:
        try:
            ok, detail = fn(sb)
        except SandboxUnavailable as e:
            print(f"FAIL  {name}\n      sandbox unavailable: {e}")
            return 2
        except Exception as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        print(f"{'PASS' if ok else 'FAIL'}  {name}\n      {detail}")
        failed += (not ok)
    if not runtime_report(sb):
        failed += 1
    print(f"\n{len(CHECKS) + 1 - failed}/{len(CHECKS) + 1} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
