"""L3: run tools in a locked-down container. Fails closed: never falls back to running on the host.

Runtime: set SENTINEL_SANDBOX_RUNTIME=runsc for gVisor (or a Kata/Firecracker-backed runtime your
Docker is configured with). Default network is none. Network "proxy" attaches the container to an
operator-created --internal Docker network whose only exit is the allowlisting proxy (egress.py).
"""
import os
import secrets
import shutil
import subprocess
from dataclasses import dataclass

DEFAULTS = {"network": "none", "timeout": 10, "memory": "256m", "cpus": "0.5", "pids": 64, "max_output": 65536}
_PASS_ENV = ("PATH", "HOME", "DOCKER_HOST", "DOCKER_CONFIG")


class SandboxUnavailable(RuntimeError):
    pass


@dataclass
class RunResult:
    exit_code: int | None
    stdout: str
    stderr: str
    timed_out: bool = False


class Sandbox:
    def __init__(self, docker: str = "docker", runtime: str | None = None,
                 egress_network: str | None = None, egress_proxy: str | None = None):
        self.docker = docker
        self.runtime = runtime or os.getenv("SENTINEL_SANDBOX_RUNTIME")
        self.egress_network = egress_network or os.getenv("SENTINEL_EGRESS_NETWORK")
        self.egress_proxy = egress_proxy or os.getenv("SENTINEL_EGRESS_PROXY")

    def command(self, spec: dict, env_names: list[str], name: str = "sentinel") -> list[str]:
        s = {**DEFAULTS, **spec}
        net = "none"
        proxy_env: list[str] = []
        if s["network"] == "proxy":
            if not (self.egress_network and self.egress_proxy):
                raise SandboxUnavailable("network=proxy needs SENTINEL_EGRESS_NETWORK and SENTINEL_EGRESS_PROXY")
            net = self.egress_network
            for v in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
                proxy_env += ["-e", f"{v}={self.egress_proxy}"]
        elif s["network"] != "none":
            raise ValueError(f"unknown network mode {s['network']!r}")
        cmd = [
            self.docker, "run", "--rm", "-i", "--name", name,
            "--network", net,
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", str(s["pids"]), "--memory", str(s["memory"]), "--cpus", str(s["cpus"]),
            "--user", "65534:65534",
        ]
        if self.runtime:
            cmd += ["--runtime", self.runtime]
        cmd += proxy_env
        for n in env_names:  # name only: value comes from our process env, so it never shows in argv/ps
            cmd += ["-e", n]
        return cmd + [s["image"], *s["command"]]

    def run(self, spec: dict, stdin: str, env: dict[str, str]) -> RunResult:
        if shutil.which(self.docker) is None:
            raise SandboxUnavailable(f"{self.docker!r} not found; refusing to run on the host")
        s = {**DEFAULTS, **spec}
        name = f"sentinel-{secrets.token_hex(6)}"
        cmd = self.command(spec, sorted(env), name)
        penv = {k: os.environ[k] for k in _PASS_ENV if k in os.environ} | env
        try:
            p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, errors="replace",
                               timeout=s["timeout"], env=penv)
        except subprocess.TimeoutExpired:
            subprocess.run([self.docker, "kill", name], capture_output=True, env=penv)
            return RunResult(None, "", "", timed_out=True)
        cap = s["max_output"]
        return RunResult(p.returncode, p.stdout[:cap], p.stderr[:cap])
