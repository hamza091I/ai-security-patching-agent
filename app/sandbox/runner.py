"""Best-effort hardened subprocess runner for optional external scanners."""
import os
import resource
import shutil
import subprocess
import tempfile
from pathlib import Path


def _limits(cpu_seconds, memory_mb):
    def apply():
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        memory = memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
    return apply


def run_isolated(command, source_code="", filename="input.txt", timeout=30, memory_mb=256, env=None):
    """Run an external scanner with no inherited secrets, files, or stdin."""
    if not isinstance(command, (list, tuple)) or not command:
        raise ValueError("command must be a non-empty argv list")
    root = Path(tempfile.mkdtemp(prefix="security-scan-"))
    try:
        input_path = root / Path(filename).name
        input_path.write_text(source_code, encoding="utf-8")
        input_path.chmod(0o400)
        safe_env = {"PATH": os.getenv("PATH", "/usr/bin:/bin"), "HOME": str(root), "PYTHONUNBUFFERED": "1"}
        if env:
            safe_env.update({str(k): str(v) for k, v in env.items()})
        preexec = _limits(max(1, int(timeout)), max(64, int(memory_mb))) if os.name == "posix" else None
        completed = subprocess.run(list(command), cwd=root, env=safe_env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   timeout=max(1, timeout), preexec_fn=preexec)
        return {"returncode": completed.returncode, "stdout": completed.stdout[:1_000_000], "stderr": completed.stderr[:1_000_000], "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        return {"returncode": None, "stdout": (exc.stdout or "")[:1_000_000], "stderr": (exc.stderr or "")[:1_000_000], "timed_out": True}
    finally:
        shutil.rmtree(root, ignore_errors=True)
