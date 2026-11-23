"""Safe runner for optional external tools (nmap, subfinder, amass, ...).

Never uses a shell. Arguments are passed as a list, output is size-capped, and every run has a timeout.
Callers must pass only validated hostnames (they cannot start with '-').
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from typing import Callable, Sequence


class ToolNotFound(Exception):
    pass


@dataclass
class ToolResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


def run_tool(name: str, args: Sequence[str], *, timeout: float = 60.0, max_output: int = 2_000_000,
             which: Callable[[str], str | None] = shutil.which) -> ToolResult:
    path = which(name)
    if not path:
        raise ToolNotFound(f"{name} is not installed.")
    if any(not isinstance(a, str) or "\x00" in a for a in args):
        raise ValueError("Invalid tool argument.")
    try:
        done = subprocess.run([path, *args], capture_output=True, timeout=timeout, shell=False,
                              stdin=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired as exc:
        return ToolResult(-1, (exc.stdout or b"")[:max_output].decode("utf-8", "replace"), "timed out", True)
    return ToolResult(done.returncode, done.stdout[:max_output].decode("utf-8", "replace"),
                      done.stderr[:20_000].decode("utf-8", "replace"))
