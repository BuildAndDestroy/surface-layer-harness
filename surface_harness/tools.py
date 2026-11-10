"""Run external recon tools either as local binaries or inside Docker.

Nothing is ever installed on the host. Resolution order in ``auto`` mode:
  1. a binary with that name on PATH (e.g. when running inside the harness image)
  2. ``docker run --rm <image> <tool> ...`` using the surface-tools image
  3. unavailable -> callers fall back to the built-in Python implementation
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

KNOWN_TOOLS = ("subfinder", "dnsx", "httpx", "naabu", "nmap")


@dataclass
class ToolResult:
    ok: bool
    stdout: str
    stderr: str
    returncode: int


class ToolRunner:
    def __init__(self, mode: str = "auto", image: str = "surface-tools:latest", log=print):
        self.mode = mode
        self.image = image
        self.log = log
        self._docker_ok: bool | None = None
        self._cache: dict[str, str | None] = {}

    # -- discovery ---------------------------------------------------------
    def _local_ok(self, tool: str) -> bool:
        path = shutil.which(tool)
        if not path:
            return False
        if tool == "httpx":
            # Don't confuse the Python 'httpx' CLI with ProjectDiscovery's httpx.
            try:
                out = subprocess.run([path, "-version"], capture_output=True, text=True, timeout=10)  # noqa: S603
                return "projectdiscovery" in (out.stdout + out.stderr).lower()
            except Exception:  # noqa: BLE001 - any failure means "not PD httpx"
                return False
        return True

    def _docker_available(self) -> bool:
        if self._docker_ok is None:
            ok = False
            if shutil.which("docker"):
                try:
                    r = subprocess.run(  # noqa: S603 - fixed argv, no shell
                        ["docker", "image", "inspect", self.image],  # noqa: S607 - docker resolved via PATH
                        capture_output=True, timeout=20,
                    )
                    ok = r.returncode == 0
                    if not ok:
                        self.log(f"[tools] docker image {self.image} not found; build it with `make tools-image`")
                except Exception:  # noqa: BLE001 - docker unavailable/broken
                    ok = False
            self._docker_ok = ok
        return self._docker_ok

    def backend(self, tool: str) -> str | None:
        """Return 'local', 'docker' or None for a given tool."""
        if tool in self._cache:
            return self._cache[tool]
        b: str | None = None
        if self.mode in ("auto", "local") and self._local_ok(tool):
            b = "local"
        elif self.mode in ("auto", "docker") and self._docker_available():
            b = "docker"
        self._cache[tool] = b
        return b

    def available(self, tool: str) -> bool:
        return self.mode != "none" and self.backend(tool) is not None

    # -- execution ---------------------------------------------------------
    async def run(
        self,
        tool: str,
        args: list[str],
        stdin_lines: list[str] | None = None,
        timeout: float = 900,
        net_admin: bool = False,
    ) -> ToolResult:
        """Run a tool. Input lines go through a temp file mounted at /work/input.txt
        (use the literal placeholder ``{input}`` in args to reference it)."""
        backend = self.backend(tool)
        if backend is None:
            return ToolResult(False, "", f"{tool} unavailable", -1)

        with tempfile.TemporaryDirectory(prefix="surface-") as tmp:
            input_path = Path(tmp) / "input.txt"
            input_path.write_text("\n".join(stdin_lines or []) + "\n")
            if backend == "local":
                argv = [tool] + [a.replace("{input}", str(input_path)) for a in args]
            else:
                argv = ["docker", "run", "--rm", "-i", "--network", "host",
                        "-v", f"{tmp}:/work:ro"]
                if net_admin:
                    argv += ["--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW"]
                # Pass through provider config (e.g. subfinder API keys) if present.
                pcfg = Path(os.path.expanduser("~/.config/subfinder/provider-config.yaml"))
                if tool == "subfinder" and pcfg.exists():
                    argv += ["-v", f"{pcfg}:/root/.config/subfinder/provider-config.yaml:ro"]
                argv += [self.image, tool] + [a.replace("{input}", "/work/input.txt") for a in args]

            proc = await asyncio.create_subprocess_exec(
                *argv, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except TimeoutError:
                proc.kill()
                await proc.wait()
                return ToolResult(False, "", f"{tool} timed out after {timeout}s", -1)
            return ToolResult(
                proc.returncode == 0,
                out.decode(errors="replace"),
                err.decode(errors="replace"),
                proc.returncode or 0,
            )
