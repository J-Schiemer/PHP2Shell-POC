"""Docker lab lifecycle for a single PHP target."""
from __future__ import annotations

import json
import shlex
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import elf, wire

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DOCKER_DIR = PROJECT_ROOT / "docker"
OUT_DIR = PROJECT_ROOT / "out"
RUNS_DIR = OUT_DIR / "runs"

LIBPHP_CANDIDATES = (
    "/usr/lib/apache2/modules/libphp.so",
    "/usr/local/lib/libphp.so",
)


class LabError(RuntimeError):
    pass


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@dataclass
class Lab:
    image: str
    role: str
    port: int | None = None
    name: str | None = None
    docker: str = "docker"
    fatal_backtraces: int | None = None
    out_dir: Path = field(default_factory=lambda: OUT_DIR)
    www_dir: Path = field(default_factory=lambda: DOCKER_DIR / "www")
    conf_dir: Path = field(default_factory=lambda: DOCKER_DIR)

    def __post_init__(self) -> None:
        self.port = self.port or free_port()
        self.name = self.name or "p2s-%s-%d" % (self.role, self.port)
        self.out_dir.mkdir(parents=True, exist_ok=True)

    @property
    def docker_cmd(self) -> list[str]:
        return shlex.split(self.docker)

    def _run(self, args: list[str], check: bool = True) -> subprocess.CompletedProcess:
        result = subprocess.run(self.docker_cmd + args, capture_output=True, text=True)
        if check and result.returncode != 0:
            raise LabError(
                "docker %s failed (%d): %s"
                % (" ".join(args[:3]), result.returncode,
                   (result.stderr or result.stdout).strip())
            )
        return result

    def start(self, ready_timeout: float = 90.0) -> None:
        self._run(["rm", "-f", self.name], check=False)
        mount = [
            "-v", f"{self.www_dir}:/var/www/html:ro",
            "-v", f"{self.conf_dir / 'apache-single.conf'}:/etc/apache2/conf-enabled/zz-p2s.conf:ro",
            "-v", f"{self.conf_dir / 'php-lab.ini'}:/usr/local/etc/php/conf.d/zz-lab.ini:ro",
            "-v", f"{self.out_dir}:/out",
        ]
        if self.fatal_backtraces is not None:
            ini = self.out_dir / ("php-backtrace-%s.ini" % self.role)
            ini.write_text(
                "fatal_error_backtraces = %d\n"
                "zend.exception_ignore_args = 0\n" % self.fatal_backtraces
            )
            mount += ["-v", f"{ini}:/usr/local/etc/php/conf.d/zz-backtrace.ini:ro"]

        args = [
            "run", "-d", "--name", self.name,
            "--platform", "linux/amd64",
            "--label", "php2shell-check=1",
            "--memory", "1g", "--memory-swap", "1g",
            "--cpus", "2",
            "--security-opt", "no-new-privileges:true",
            "-p", f"127.0.0.1:{self.port}:80",
            *mount,
            self.image,
            "/bin/sh", "-c",
            "cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini; "
            "chown -R www-data:www-data /out; exec apache2-foreground",
        ]
        self._run(args)
        self.wait_ready(ready_timeout)

    def wait_ready(self, timeout: float = 90.0) -> None:
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            try:
                response = wire.get("127.0.0.1", self.port, "/index.php", timeout=3)
                if response.status == 200:
                    return
                last = "HTTP %s" % response.status
            except OSError as exc:
                last = repr(exc)
            time.sleep(0.3)
        raise LabError("target %s did not become ready: %s" % (self.name, last or "timeout"))

    def stop(self) -> None:
        if self.name:
            self._run(["rm", "-f", self.name], check=False)

    def logs(self, since: str | None = None) -> str:
        args = ["logs", "--timestamps"]
        if since:
            args += ["--since", since]
        args.append(self.name)
        result = self._run(args, check=False)
        return (result.stdout or "") + (result.stderr or "")

    def inspect(self) -> dict:
        result = self._run(["inspect", self.name], check=False)
        if result.returncode != 0:
            return {}
        try:
            return json.loads(result.stdout)[0]
        except (ValueError, IndexError, KeyError):
            return {}

    def worker_pids(self) -> list[int]:
        result = self._run(["exec", self.name, "ps", "-eo", "pid=,ppid=,cmd="],
                           check=False)
        if result.returncode != 0:
            return []
        pids: list[int] = []
        for line in result.stdout.splitlines():
            fields = line.split(None, 2)
            if len(fields) < 3:
                continue
            pid, ppid, cmd = fields
            if "apache2" in cmd and ppid != "0":
                try:
                    pids.append(int(pid))
                except ValueError:
                    pass
        return pids

    def effective_config(self) -> dict:
        try:
            response = wire.get("127.0.0.1", self.port, "/info.php", timeout=5)
            if response.status == 200:
                return json.loads(response.body.decode("utf-8", "replace"))
        except (OSError, ValueError):
            pass
        return {}

    def health(self) -> bool:
        try:
            response = wire.get("127.0.0.1", self.port, "/index.php", timeout=5)
            return response.status == 200 and b"OK" in response.body
        except OSError:
            return False

    def offsets(self) -> dict[str, int]:
        return elf.offsets_from_container(self.name)

    def copy_libphp(self, dest: Path) -> Path:
        return elf.copy_libphp(self.name, dest, LIBPHP_CANDIDATES)

    def remove_out_file(self, name: str) -> None:
        self._run(["exec", self.name, "rm", "-f", "/out/" + name], check=False)
