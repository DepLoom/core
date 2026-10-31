"""Optional, bounded full npm resolver check for a planning-only root model.

A failed npm attempt is context-bound evidence, never a static solver nogood.
Resolution success proves neither installation, lifecycle nor application checks.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Callable, Mapping

from verification_process_supervisor import run_supervised


def root_model_coverage() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "scope": "DECLARED_PACKAGE_PEERS_AND_ENVIRONMENT",
        "transitivePlacement": "NOT_MODELED",
        "optimalityScope": "EXTRACTED_FINITE_DOMAINS_ONLY",
        "fullDependencyTreeProven": False,
    }


def _digest(path: Path) -> str | None:
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def _npm_command() -> list[str]:
    node = shutil.which("node")
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if not node or not npm:
        raise OSError("npm runtime unavailable")
    candidates = [Path(npm).parent / "node_modules/npm/bin/npm-cli.js",
                  Path(node).resolve().parent / "node_modules/npm/bin/npm-cli.js",
                  Path(npm).resolve()]
    script = next((p for p in candidates if p.is_file() and p.suffix == ".js"), None)
    if script is None:
        raise OSError("npm CLI JavaScript entrypoint unavailable")
    return [node, str(script)]


def _validate_project(
    rows: list[dict[str, Any]], source: Path, output: Path, *, registry: str,
    options: Mapping[str, Any], remaining: Callable[[], float | None],
) -> dict[str, Any]:
    before = {name: _digest(source / name) for name in ("package.json", "package-lock.json", ".npmrc")}
    package = json.loads((source / "package.json").read_text(encoding="utf-8-sig"))
    if package.get("workspaces") or str(package.get("packageManager", "npm")).split("@", 1)[0] not in ("", "npm"):
        return {"status": "UNKNOWN", "code": "UNSUPPORTED_PROJECT_TOPOLOGY"}
    sections = ("dependencies", "devDependencies", "optionalDependencies")
    names = {name for section in sections for name in package.get(section, {})}
    assignment: dict[str, str] = {}
    for row in rows:
        name = row["package"]
        version = row.get("target") or row.get("current")
        if name in assignment or not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?", version):
            return {"status": "UNKNOWN", "code": "INCOMPLETE_OR_AMBIGUOUS_ASSIGNMENT"}
        assignment[name] = version
    if names != set(assignment):
        return {"status": "UNKNOWN", "code": "ROOT_INVENTORY_MISMATCH"}
    for section in sections:
        if section in package:
            package[section] = {name: assignment[name] for name in package[section]}
    output.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(prefix="resolver-", dir=output))
    (workspace / "package.json").write_text(json.dumps(package, indent=2) + "\n", encoding="utf-8")
    if (source / ".npmrc").is_file():
        shutil.copyfile(source / ".npmrc", workspace / ".npmrc")
    # Fresh-lock resolution is explicit: never modify or overwrite the source lock.
    argv = _npm_command() + [
        "install", "--package-lock-only", "--package-lock=true", "--strict-peer-deps=true",
        "--engine-strict=true", "--ignore-scripts=true", "--force=false", "--legacy-peer-deps=false",
        "--install-strategy=hoisted", "--prefer-dedupe=false", "--no-audit", "--no-fund",
        "--offline=" + str(bool(options.get("offline", False))).lower(), "--prefer-offline=false",
    ]
    if registry:
        argv += ["--registry", registry]
    if options.get("cache"):
        argv += ["--cache", str(options["cache"])]
    left = remaining()
    cap = min(60, max(1, int(options.get("timeoutSeconds", 60))))
    if left is not None:
        cap = min(cap, math.floor(left))
    if cap < 1:
        return {"status": "UNKNOWN", "code": "DRAFT_BUDGET_EXHAUSTED"}
    identity = {
        "sourceInputs": before, "exactAssignment": dict(sorted(assignment.items())),
        "registrySha256": hashlib.sha256(registry.encode()).hexdigest(),
        "npmEntrypointSha256": _digest(Path(argv[1])), "nodeBinarySha256": _digest(Path(argv[0])),
        "lockMode": "FRESH", "installStrategy": "hoisted", "strictPeers": True,
        "engineStrict": True, "ignoreScripts": True, "force": False, "legacyPeerDeps": False,
        "offline": bool(options.get("offline", False)),
    }
    identity_hash = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    start = time.monotonic()
    try:
        proc = run_supervised(argv, workspace, timeout_seconds=cap, progress_label="Draft npm resolution preflight")
        text = proc.stdout or ""
        (output / "output.txt").write_text(text, encoding="utf-8")
        code_match = re.search(r"npm (?:error|ERR!) code ([A-Z][A-Z0-9_]+)", text)
        code = code_match.group(1) if code_match else ("OK" if proc.returncode == 0 else "NPM_RESOLUTION_ERROR")
        status = "RESOLUTION_PASSED" if proc.returncode == 0 else (
            "RESOLUTION_FAILED" if code in ("ERESOLVE", "EBADENGINE") else "UNKNOWN")
        if status == "RESOLUTION_PASSED":
            lock = json.loads((workspace / "package-lock.json").read_text(encoding="utf-8-sig"))
            installed = lock.get("packages", {})
            if any(installed.get("node_modules/" + name, {}).get("version") != version for name, version in assignment.items()):
                status, code = "UNKNOWN", "LOCK_ASSIGNMENT_MISMATCH"
        result = {"status": status, "code": code, "exitCode": proc.returncode,
                  "outputSha256": _digest(output / "output.txt"),
                  "lockSha256": _digest(workspace / "package-lock.json")}
    except subprocess.TimeoutExpired:
        result = {"status": "UNKNOWN", "code": "RESOLVER_TIMEOUT"}
    except (OSError, ValueError, TypeError):
        result = {"status": "UNKNOWN", "code": "RESOLVER_EVIDENCE_UNAVAILABLE"}
    after = {name: _digest(source / name) for name in before}
    if before != after:
        result = {"status": "UNKNOWN", "code": "SOURCE_INPUT_CHANGED"}
    result.update(identity=identity, identitySha256=identity_hash, workspace=str(workspace),
                  elapsedMs=round((time.monotonic() - start) * 1000), learningAllowed=False,
                  installation="NOT_RUN", runtime="NOT_RUN", sourceUnchanged=before == after)
    (output / "receipt.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def validate_draft_plan(
    plan: Mapping[str, Any], project_paths: Mapping[str, Path], *, artifacts_dir: Path,
    registry: str, options: Mapping[str, Any], remaining: Callable[[], float | None],
) -> dict[str, Any]:
    results = {}
    for group in plan["proposals"]:
        name = group["project"]
        if name not in project_paths:
            results[name] = {"status": "UNKNOWN", "code": "PROJECT_PATH_UNAVAILABLE"}
            continue
        try:
            results[name] = _validate_project(
                group["rows"], Path(project_paths[name]),
                artifacts_dir / "package-manager" / hashlib.sha256(name.encode()).hexdigest()[:12],
                registry=registry, options=options, remaining=remaining,
            )
        except (OSError, ValueError, TypeError, KeyError):
            results[name] = {"status": "UNKNOWN", "code": "PREFLIGHT_INPUT_UNAVAILABLE"}
    states = {r["status"] for r in results.values()}
    status = "RESOLUTION_FAILED" if "RESOLUTION_FAILED" in states else (
        "RESOLUTION_PASSED" if states == {"RESOLUTION_PASSED"} else "UNKNOWN")
    return {"schemaVersion": 1, "status": status, "projects": results, "learningAllowed": False,
            "installation": "NOT_RUN", "runtime": "NOT_RUN"}


def validation_notice(validation: Mapping[str, Any], language: str) -> str:
    status = validation["status"]
    if status == "NOT_RUN":
        return ("\n\nМодель охватывает peer/environment прямых пакетов; transitive placement = NOT_MODELED. Разрешение полного npm-дерева: NOT_RUN.\n" if language == "ru" else
                "\n\nConstraint model: declared package peers/environment only; transitive placement is NOT_MODELED. Full npm resolution was NOT_RUN.\n")
    if status != "RESOLUTION_PASSED":
        code = "PM_VALIDATION_FAILED" if status == "RESOLUTION_FAILED" else "PM_VALIDATION_UNKNOWN"
        return (f"\n\n{code}: разрешение полного дерева не подтверждено. Не применяйте это назначение; требуется диагностика/перепланирование. Это не доказательство UNSAT.\n" if language == "ru" else
                f"\n\n{code}: full dependency resolution did not pass. Do not apply this assignment; diagnosis/replanning is required. This is not an UNSAT proof.\n")
    return ("\n\nРазрешение полного npm-дерева прошло; установка, lifecycle, исходники и runtime остаются NOT_VERIFIED. Транзитивное размещение не моделируется статическим IR.\n" if language == "ru" else
            "\n\nFull npm resolution passed; installation, lifecycle, source checks and runtime remain NOT_VERIFIED. Transitive placement is not modeled by the static IR.\n")
