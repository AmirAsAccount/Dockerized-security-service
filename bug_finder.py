
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path

DEFAULT_TIMEOUT = 300
STANDARD_RULESETS = ["p/python", "p/dockerfile"]
IGNORED_FOLDERS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
SCANNERS_BY_TARGET = {
    "image": ["trivy"],
    "path": ["trivy", "gitleaks", "hadolint", "semgrep"],
}

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"

SEVERITY_ORDER = {Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2,
        Severity.LOW: 1, Severity.UNKNOWN: 0}

class BugClass(str, Enum):
    CVE = "cve"            
    SECRET = "secret"      
    MISCONFIG = "misconfig"
    CODE = "code"          

@dataclass
class Finding:
    tool: str
    bug_class: BugClass
    severity: Severity
    rule_id: str
    title: str
    file: str | None = None
    line: int | None = None
    package: str | None = None
    version: str | None = None
    commit: str | None = None
    fix: str | None = None
    reference: str | None = None
    also_reported_by: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["bug_class"] = self.bug_class.value
        d["severity"] = self.severity.value
        return d

def severity_from(value: str | None, aliases: dict[str, str] | None = None) -> Severity:
    v = (value or "").strip().lower()
    if aliases:
        v = aliases.get(v, v)
    try:
        return Severity(v)
    except ValueError:
        return Severity.UNKNOWN

def normalize_file(p: str | None) -> str | None:
    return os.path.normpath(p) if p else p

class ScanError(Exception):
    pass

def execute_scanner(args: list[str], cwd: Path | None = None,
             timeout: int = DEFAULT_TIMEOUT, ok_codes: tuple[int, ...] = (0, 1)) -> str:
    try:
        result = subprocess.run(args, cwd=cwd, capture_output=True,
                                text=True, timeout=timeout)
    except FileNotFoundError:
        raise ScanError(f"{args[0]} is not installed")
    except subprocess.TimeoutExpired:
        raise ScanError(f"{args[0]} timed out after {timeout}s")
    if result.returncode not in ok_codes:
        raise ScanError(f"{args[0]} exited with code {result.returncode}: "
                        f"{result.stderr.strip()[:300]}")
    return result.stdout

def installed_scanners(kind: str = "path") -> dict[str, str | None]:
    return {tool: shutil.which(tool) for tool in SCANNERS_BY_TARGET[kind]}

def list_dockerfiles(root: Path) -> list[str]:
    found = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in IGNORED_FOLDERS]
        for name in filenames:
            if name == "Dockerfile" or name.startswith("Dockerfile.") \
                    or name.endswith(".dockerfile"):
                found.append(str(Path(dirpath, name).relative_to(root)))
    return sorted(found)

def parse_trivy(data: dict, is_image: bool) -> list[Finding]:
    findings = []
    for result in data.get("Results") or []:
        target = None if is_image else normalize_file(result.get("Target"))
        for v in result.get("Vulnerabilities") or []:
            fixed = v.get("FixedVersion")
            findings.append(Finding(
                tool="trivy", bug_class=BugClass.CVE,
                severity=severity_from(v.get("Severity")),
                rule_id=v.get("VulnerabilityID", "unknown"),
                title=v.get("Title") or v.get("VulnerabilityID", ""),
                file=target, package=v.get("PkgName"),
                version=v.get("InstalledVersion"),
                fix=f"Upgrade to {fixed}" if fixed else None,
                reference=v.get("PrimaryURL")))
        for s in result.get("Secrets") or []:
            findings.append(Finding(
                tool="trivy", bug_class=BugClass.SECRET,
                severity=severity_from(s.get("Severity")),
                rule_id=s.get("RuleID", "unknown"),
                title=s.get("Title") or "Secret",
                file=target, line=s.get("StartLine"),
                fix="Revoke this secret and remove it from code and git history"))
        for m in result.get("Misconfigurations") or []:
            if m.get("Status", "FAIL") != "FAIL":
                continue
            findings.append(Finding(
                tool="trivy", bug_class=BugClass.MISCONFIG,
                severity=severity_from(m.get("Severity")),
                rule_id=m.get("ID") or m.get("AVDID") or "unknown",
                title=m.get("Title") or m.get("Message", ""),
                file=target,
                line=(m.get("CauseMetadata") or {}).get("StartLine") or None,
                fix=m.get("Resolution"), reference=m.get("PrimaryURL")))
    return findings

def parse_gitleaks(leaks: list[dict]) -> list[Finding]:
    return [Finding(
        tool="gitleaks", bug_class=BugClass.SECRET, severity=Severity.HIGH,
        rule_id=leak.get("RuleID", "unknown"),
        title=leak.get("Description") or leak.get("RuleID", "Secret"),
        file=normalize_file(leak.get("File")), line=leak.get("StartLine"),
        commit=leak.get("Commit") or None,
        fix="Revoke this secret; deleting it does not remove it from git history")
        for leak in leaks]

HADOLINT_SEVERITIES = {"error": "high", "warning": "medium", "info": "low", "style": "low"}

def parse_hadolint(items: list[dict]) -> list[Finding]:
    findings = []
    for item in items:
        code = item.get("code", "unknown")
        ref = (f"https://github.com/hadolint/hadolint/wiki/{code}" if code.startswith("DL")
               else f"https://www.shellcheck.net/wiki/{code}")
        findings.append(Finding(
            tool="hadolint", bug_class=BugClass.MISCONFIG,
            severity=severity_from(item.get("level"), HADOLINT_SEVERITIES),
            rule_id=code, title=item.get("message", ""),
            file=normalize_file(item.get("file")), line=item.get("line"),
            reference=ref))
    return findings

SEMGREP_SEVERITIES = {"error": "high", "warning": "medium", "info": "low"}

def parse_semgrep(data: dict) -> list[Finding]:
    findings = []
    for r in data.get("results") or []:
        extra = r.get("extra") or {}
        path = normalize_file(r.get("path"))
        is_dockerfile = bool(path) and Path(path).name.startswith("Dockerfile")
        refs = (extra.get("metadata") or {}).get("references") or []
        message = " ".join((extra.get("message") or "").split())
        findings.append(Finding(
            tool="semgrep",
            bug_class=BugClass.MISCONFIG if is_dockerfile else BugClass.CODE,
            severity=severity_from(extra.get("severity"), SEMGREP_SEVERITIES),
            rule_id=r.get("check_id", "unknown"),
            title=message[:200], file=path,
            line=(r.get("start") or {}).get("line"),
            reference=refs[0] if refs else None))
    return findings

def scan_trivy(target: str, is_image: bool, timeout: int) -> list[Finding]:
    if is_image:
        args = ["trivy", "image", "--format", "json", "--quiet",
                "--scanners", "vuln,secret", target]
        out = execute_scanner(args, timeout=timeout)
    else:
        args = ["trivy", "fs", "--format", "json", "--quiet",
                "--scanners", "vuln,secret,misconfig", "."]
        out = execute_scanner(args, cwd=Path(target), timeout=timeout)
    return parse_trivy(json.loads(out or "{}"), is_image)

def scan_gitleaks(root: Path, timeout: int) -> list[Finding]:
    mode = "git" if (root / ".git").exists() else "dir"
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        execute_scanner(["gitleaks", mode, ".", "--report-format", "json",
                  "--report-path", str(report), "--redact", "--no-banner",
                  "--exit-code", "0"], cwd=root, timeout=timeout)
        text = report.read_text() if report.exists() else ""
    return parse_gitleaks(json.loads(text or "[]"))

def scan_hadolint(root: Path, timeout: int) -> list[Finding]:
    dockerfiles = list_dockerfiles(root)
    if not dockerfiles:
        return []
    out = execute_scanner(["hadolint", "--format", "json", *dockerfiles],
                   cwd=root, timeout=timeout)
    return parse_hadolint(json.loads(out or "[]"))

def scan_semgrep(root: Path, configs: list[str], timeout: int) -> list[Finding]:
    config_args = [arg for c in configs for arg in ("--config", c)]
    out = execute_scanner(["semgrep", "scan", "--json", "--quiet", "--metrics=off",
                    "--disable-version-check", *config_args, "."],
                   cwd=root, timeout=timeout)
    return parse_semgrep(json.loads(out or "{}"))

def finding_identity(f: Finding) -> tuple:
    if f.bug_class == BugClass.CVE:
        return ("cve", f.rule_id)
    if f.bug_class in (BugClass.CODE, BugClass.SECRET) and f.file and f.line:
        return (f.bug_class.value, f.file, f.line, f.commit or "")
    return (f.bug_class.value, f.tool, f.rule_id, f.file or "", f.line or 0)

def combine_duplicates(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple, Finding] = {}
    for f in findings:
        key = finding_identity(f)
        if key not in merged:
            merged[key] = f
            continue
        keep, other = merged[key], f
        if SEVERITY_ORDER[other.severity] > SEVERITY_ORDER[keep.severity]:  # most severe report leads
            keep, other = other, keep
            merged[key] = keep
        tag = f"{other.tool}:{other.rule_id}"
        if tag != f"{keep.tool}:{keep.rule_id}" and tag not in keep.also_reported_by:
            keep.also_reported_by.append(tag)
        for t in other.also_reported_by:
            if t not in keep.also_reported_by:
                keep.also_reported_by.append(t)
        if other.package and keep.package and other.package not in keep.package.split(", "):
            keep.package = f"{keep.package}, {other.package}"
    return list(merged.values())

def scan_target(kind: str, target: str, *, semgrep_configs: list[str] | None = None,
         timeout: int = DEFAULT_TIMEOUT) -> dict:
    if kind not in SCANNERS_BY_TARGET:
        raise ValueError(f"unknown scan type {kind!r}; use 'path' or 'image'")
    if not target or target.startswith("-"):
        raise ValueError("target must not be empty or start with '-'")

    if kind == "image":
        jobs = {"trivy": lambda: scan_trivy(target, True, timeout)}
    else:
        root = Path(target).resolve(strict=True)
        if not root.is_dir():
            raise ValueError(f"{target} is not a folder")
        target = str(root)
        jobs = {
            "trivy": lambda: scan_trivy(target, False, timeout),
            "gitleaks": lambda: scan_gitleaks(root, timeout),
            "hadolint": lambda: scan_hadolint(root, timeout),
            "semgrep": lambda: scan_semgrep(root, semgrep_configs or STANDARD_RULESETS, timeout),
        }

    raw: list[Finding] = []
    tools_run, errors = [], []
    for name, job in jobs.items():
        try:
            raw.extend(job())
            tools_run.append(name)
        except (ScanError, json.JSONDecodeError) as e:
            errors.append({"tool": name, "error": str(e)})

    findings = sorted(combine_duplicates(raw), key=lambda f: (-SEVERITY_ORDER[f.severity], f.bug_class.value,
                                                  f.file or "", f.line or 0))
    summary = {s.value: 0 for s in Severity}
    for f in findings:
        summary[f.severity.value] += 1
    return {
        "target": target, "type": kind,
        "tools_run": tools_run, "errors": errors,
        "raw_count": len(raw), "total": len(findings),
        "summary": summary,
        "findings": [f.to_dict() for f in findings],
    }

def show_report(report: dict) -> None:
    s = report["summary"]
    print(f"\nTarget:  {report['target']} ({report['type']})")
    print(f"Tools:   {', '.join(report['tools_run']) or 'none'}")
    for e in report["errors"]:
        print(f"  ! {e['tool']}: {e['error']}")
    print(f"Found:   {report['total']} findings ({report['raw_count']} before dedupe) | "
          f"critical {s['critical']}  high {s['high']}  medium {s['medium']}  "
          f"low {s['low']}  unknown {s['unknown']}\n")
    for f in report["findings"]:
        where = f["file"] or f["package"] or ""
        if f["line"]:
            where += f":{f['line']}"
        if f["commit"]:
            where += f" @{f['commit'][:7]}"
        tools = f["tool"] + (f" +{len(f['also_reported_by'])}" if f["also_reported_by"] else "")
        print(f"  {f['severity'].upper():9} {f['bug_class']:10} {tools:12} "
              f"{where[:32]:32} {f['title'][:60]}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Run security scanners on a target.")
    parser.add_argument("kind", nargs="?", choices=SCANNERS_BY_TARGET.keys(), help="path or image")
    parser.add_argument("target", nargs="?", help="folder path or image name")
    parser.add_argument("--check", action="store_true", help="show which scanners are installed")
    parser.add_argument("--json", metavar="FILE", help="also write the full report as JSON ('-' for stdout)")
    parser.add_argument("--semgrep-config", action="append", metavar="CONFIG",
                        help="Semgrep ruleset (repeatable); default: p/python p/dockerfile")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="seconds per tool")
    args = parser.parse_args()

    if args.check:
        for tool, path in installed_scanners("path").items():
            print(f"  {tool:9} {path or 'MISSING'}")
        return
    if not args.kind or not args.target:
        parser.error("give a scan type and a target, e.g.  path ./practice")

    try:
        report = scan_target(args.kind, args.target, semgrep_configs=args.semgrep_config,
                      timeout=args.timeout)
    except (ValueError, FileNotFoundError) as e:
        sys.exit(f"error: {e}")

    if args.json == "-":
        json.dump(report, sys.stdout, indent=2)
        return
    show_report(report)
    if args.json:
        Path(args.json).write_text(json.dumps(report, indent=2))
        print(f"\nFull report written to {args.json}")

if __name__ == "__main__":
    main()
