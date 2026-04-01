#!/usr/bin/env python3
"""
Dyana security scanner hook for Claude Code.

Intercepts package install commands (pip, npm, yarn, pnpm, uv, poetry),
runs them through Dyana's Docker+eBPF sandbox, and reports security
findings back to Claude before the install proceeds.

Install: copy to ~/.claude/hooks/dyana_scan.py
Config:  see settings.json for Claude Code hook configuration
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CACHE_DIR = Path.home() / ".cache" / "dyana-claude-code"
DEFAULT_CACHE_TTL = 86400  # 24 hours
DEFAULT_SCAN_TIMEOUT = 120  # seconds

# Copied from dyana/constants.py — these event names indicate security threats
SECURITY_EVENTS: set[str] = {
    "anti_debugging",
    "aslr_inspection",
    "bpf_attach",
    "cgroup_notify_on_release",
    "cgroup_release_agent",
    "core_pattern_modification",
    "default_loader_mod",
    "disk_mount",
    "docker_abuse",
    "dropped_executable",
    "dynamic_code_loading",
    "fileless_execution",
    "ftrace_hook",
    "hidden_file_created",
    "hidden_kernel_module",
    "hooked_syscall",
    "illegitimate_shell",
    "k8s_api_connection",
    "k8s_cert_theft",
    "kernel_module_loading",
    "ld_preload",
    "proc_fops_hooking",
    "proc_kcore_read",
    "proc_mem_access",
    "proc_mem_code_injection",
    "process_vm_write_inject",
    "ptrace_code_injection",
    "rcd_modification",
    "sched_debug_recon",
    "scheduled_task_mod",
    "stdio_over_socket",
    "sudoers_modification",
    "syscall_hooking",
    "system_request_key_mod",
}

SEVERITY_LABELS = {0: "none", 1: "low", 2: "moderate", 3: "high"}
SEVERITY_DENY = 3
SEVERITY_WARN = 1

# Domains expected during normal package installation
EXPECTED_DOMAINS = {
    "pypi.org",
    "files.pythonhosted.org",
    "pypi.python.org",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "registry.npmmirror.com",
}

# Flags that consume the next token (so we skip it too)
PIP_FLAGS_WITH_VALUE = {
    "--global-option",
    "--install-option",
    "--config-settings",
    "--index-url",
    "-i",
    "--extra-index-url",
    "--find-links",
    "-f",
    "--constraint",
    "-c",
    "--target",
    "-t",
    "--prefix",
    "--src",
    "--root",
}

# ---------------------------------------------------------------------------
# Command detection
# ---------------------------------------------------------------------------

# Patterns that indicate an individual-package install
PIP_INSTALL_RE = re.compile(
    r"(?:pip3?|python3?\s+-m\s+pip)\s+install\s+"
    r"|uv\s+pip\s+install\s+"
    r"|uv\s+add\s+"
    r"|poetry\s+add\s+"
)
NPM_INSTALL_RE = re.compile(
    r"(?:npm\s+(?:install|i)|yarn\s+add|pnpm\s+(?:add|install))\s+"
)

# Patterns to skip — bulk/lockfile installs with no individual package to scan
SKIP_RE = re.compile(
    r"pip3?\s+install\s+(?:-r\s+|-e\s+|--requirement\s+|\.\s*(?:$|&&|\|))"
    r"|npm\s+ci\b"
    r"|npm\s+install\s*(?:$|&&|\|)"
    r"|poetry\s+install\b"
    r"|uv\s+sync\b"
    r"|pnpm\s+install\s*(?:$|&&|\|)"
    r"|yarn\s+install\b"
    r"|yarn\s*(?:$|&&|\|)"
)


def _extract_packages(remainder: str, loader: str) -> list[tuple[str, str]]:
    """Extract (loader, package_name) pairs from the text after the install keyword."""
    try:
        tokens = shlex.split(remainder)
    except ValueError:
        tokens = remainder.split()

    packages: list[tuple[str, str]] = []
    skip_next = False

    for token in tokens:
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            if token in PIP_FLAGS_WITH_VALUE:
                skip_next = True
            continue

        # Strip version specifiers
        if loader == "pip":
            pkg = re.split(r"[><=!~;@\[]", token)[0].strip()
        else:
            # npm: handle @scope/package@version
            if token.startswith("@") and "/" in token:
                at_parts = token.split("@")
                pkg = f"@{at_parts[1]}" if len(at_parts) >= 2 else token
            else:
                pkg = token.split("@")[0].strip()

        if pkg and not pkg.startswith("-"):
            packages.append((loader, pkg))

    return packages


def detect_install(command: str) -> list[tuple[str, str]] | None:
    """Return list of (loader, package) tuples, or None if not an install command."""
    # Strip sudo prefix
    cmd = re.sub(r"^\s*sudo\s+", "", command).strip()

    # Fast rejection — avoid regex for the vast majority of commands
    lower = cmd.lower()
    if not any(kw in lower for kw in ("install", " add ", " i ")):
        return None

    # Skip bulk/lockfile installs
    if SKIP_RE.search(cmd):
        return None

    # Try pip-ecosystem patterns
    m = PIP_INSTALL_RE.search(cmd)
    if m:
        return _extract_packages(cmd[m.end() :], "pip") or None

    # Try npm-ecosystem patterns
    m = NPM_INSTALL_RE.search(cmd)
    if m:
        return _extract_packages(cmd[m.end() :], "npm") or None

    return None


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


def _cache_path(loader: str, package: str) -> Path:
    # Unpinned packages get a daily bucket so they're rescanned each day
    has_version = any(c in package for c in "=@<>!")
    if has_version:
        key = f"{loader}:{package}"
    else:
        key = f"{loader}:{package}:{time.strftime('%Y-%m-%d')}"
    h = hashlib.sha256(key.encode()).hexdigest()[:16]
    return CACHE_DIR / f"{loader}_{h}.json"


def cache_get(loader: str, package: str) -> dict | None:
    path = _cache_path(loader, package)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        ttl = int(os.environ.get("DYANA_CACHE_TTL", DEFAULT_CACHE_TTL))
        if time.time() - data.get("scanned_at", 0) > ttl:
            path.unlink(missing_ok=True)
            return None
        return data
    except (json.JSONDecodeError, KeyError, OSError):
        path.unlink(missing_ok=True)
        return None


def cache_set(loader: str, package: str, result: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path = _cache_path(loader, package)
    path.write_text(json.dumps(result))
    # Evict oldest entries if cache grows too large
    try:
        files = sorted(CACHE_DIR.glob("*.json"), key=lambda f: f.stat().st_mtime)
        if len(files) > 200:
            for f in files[:50]:
                f.unlink(missing_ok=True)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Preflight checks
# ---------------------------------------------------------------------------


def preflight_check() -> str | None:
    """Return an error message if dyana or docker are unavailable, else None."""
    try:
        r = subprocess.run(["dyana", "--help"], capture_output=True, timeout=10)
        if r.returncode != 0:
            return "dyana CLI returned non-zero"
    except FileNotFoundError:
        return "dyana is not installed or not on PATH"
    except subprocess.TimeoutExpired:
        return "dyana --help timed out"

    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=15)
        if r.returncode != 0:
            return "Docker is not running"
    except FileNotFoundError:
        return "docker is not installed"
    except subprocess.TimeoutExpired:
        return "docker info timed out"

    return None


# ---------------------------------------------------------------------------
# Dyana invocation
# ---------------------------------------------------------------------------


def run_dyana_scan(loader: str, package: str) -> dict | None:
    """Run dyana trace and return parsed trace dict, or None on failure."""
    timeout = int(os.environ.get("DYANA_SCAN_TIMEOUT", DEFAULT_SCAN_TIMEOUT))
    fd, trace_path = tempfile.mkstemp(suffix=".json", prefix="dyana-scan-")
    os.close(fd)

    try:
        cmd = [
            "dyana",
            "trace",
            "--loader",
            loader,
            "--package",
            package,
            "--output",
            trace_path,
            "--timeout",
            str(timeout),
            "--allow-network",
            "--no-gpu",
        ]
        subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 60,
        )
        with open(trace_path) as f:
            return json.load(f)
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    finally:
        try:
            os.unlink(trace_path)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Trace parsing
# ---------------------------------------------------------------------------


def _classify_network(connections: list[dict]) -> tuple[list[dict], list[dict]]:
    """Split connections into (expected, unexpected)."""
    known_ips: set[str] = set()
    expected: list[dict] = []
    unexpected: list[dict] = []

    # First pass: collect IPs resolved from known domains
    for conn in connections:
        if conn.get("family") == "DNS":
            domain = conn["endpoint"].replace("DNS: ", "").split(",")[0].strip()
            if any(d in domain for d in EXPECTED_DOMAINS):
                known_ips.update(conn.get("resolved", []))

    # Second pass: classify each connection
    for conn in connections:
        if conn.get("family") == "DNS":
            domain = conn["endpoint"].replace("DNS: ", "").split(",")[0].strip()
            if any(d in domain for d in EXPECTED_DOMAINS):
                expected.append(conn)
            else:
                unexpected.append(conn)
            continue

        endpoint = conn.get("endpoint", "")
        ip = endpoint.split(":")[0].strip("[]")
        if (
            ip in known_ips
            or ip.startswith("127.")
            or ip.startswith("10.")
            or ip.startswith("172.")
            or ip.startswith("192.168.")
            or ip == "::1"
        ):
            expected.append(conn)
        else:
            unexpected.append(conn)

    return expected, unexpected


def parse_trace(trace: dict) -> dict:
    """Extract security-relevant findings from a Dyana trace."""
    events = trace.get("events", [])

    # --- Security events ---
    security_findings: list[dict] = []
    max_severity = 0
    seen: set[str] = set()

    for event in events:
        if event.get("eventName") not in SECURITY_EVENTS:
            continue
        meta = event.get("metadata", {})
        props = meta.get("Properties", {})
        sig = props.get("signatureName", event["eventName"])
        if sig in seen:
            continue
        seen.add(sig)
        severity = props.get("Severity", 0)
        max_severity = max(max_severity, severity)
        security_findings.append(
            {
                "name": sig,
                "severity": severity,
                "category": props.get("Category", "misc"),
                "description": meta.get("Description", ""),
            }
        )

    # --- Network connections ---
    network: list[dict] = []
    seen_ep: set[str] = set()

    for event in events:
        ename = event.get("eventName", "")
        if ename == "security_socket_connect":
            remote = next((a["value"] for a in event.get("args", []) if a["name"] == "remote_addr"), None)
            if not isinstance(remote, dict):
                continue
            family = remote.get("sa_family", "")
            if family == "AF_INET":
                ep = f"{remote['sin_addr']}:{remote['sin_port']}"
            elif family == "AF_INET6":
                ep = f"[{remote['sin6_addr']}]:{remote['sin6_port']}"
            elif family == "AF_UNIX":
                ep = remote.get("sun_path", "?")
            else:
                continue
            key = f"{event.get('processName', '?')}->{ep}"
            if key not in seen_ep:
                seen_ep.add(key)
                network.append({"process": event.get("processName", "?"), "endpoint": ep, "family": family})

        elif ename == "net_packet_dns":
            dns = next((a["value"] for a in event.get("args", []) if a["name"] == "proto_dns"), None)
            if not dns:
                continue
            questions = [q["name"] for q in dns.get("questions", [])]
            resolved = [a.get("IP", "") for a in dns.get("answers", []) if a.get("IP")]
            key = f"dns:{'|'.join(questions)}"
            if key not in seen_ep:
                seen_ep.add(key)
                network.append(
                    {"process": event.get("processName", "?"), "endpoint": f"DNS: {', '.join(questions)}", "family": "DNS", "resolved": resolved}
                )

    # --- Process executions ---
    proc_count = sum(1 for e in events if e.get("eventName") == "sched_process_exec")

    # --- Run metadata ---
    run = trace.get("run", {})

    return {
        "security_findings": security_findings,
        "max_severity": max_severity,
        "network": network,
        "process_count": proc_count,
        "total_events": len(events),
        "run_errors": run.get("errors") or {},
        "exit_code": run.get("exit_code", 0),
    }


# ---------------------------------------------------------------------------
# Verdict + output
# ---------------------------------------------------------------------------


def build_result(package: str, loader: str, parsed: dict) -> dict:
    _, unexpected = _classify_network(parsed["network"])

    max_sev = parsed["max_severity"]
    if max_sev >= SEVERITY_DENY:
        verdict = "deny"
    elif max_sev >= SEVERITY_WARN or parsed["security_findings"] or unexpected:
        verdict = "warn"
    else:
        verdict = "clean"

    return {
        "package": package,
        "loader": loader,
        "scanned_at": time.time(),
        "verdict": verdict,
        "max_severity": max_sev,
        "security_findings": parsed["security_findings"],
        "unexpected_network": unexpected,
        "process_count": parsed["process_count"],
        "total_events": parsed["total_events"],
        "exit_code": parsed["exit_code"],
        "run_errors": parsed["run_errors"],
    }


def format_context(results: list[dict]) -> str:
    lines = ["[Dyana Security Scan Results]", ""]
    for r in results:
        tag = {"deny": "BLOCKED", "warn": "WARNING", "clean": "CLEAN"}[r["verdict"]]
        lines.append(f"Package: {r['package']} ({r['loader']}) -- {tag}")

        if r["security_findings"]:
            lines.append(f"  Security events ({len(r['security_findings'])}):")
            for f in r["security_findings"][:5]:
                sev = SEVERITY_LABELS.get(f["severity"], "?")
                lines.append(f"    - {f['name']} (severity: {sev}, category: {f['category']})")

        if r["unexpected_network"]:
            lines.append(f"  Unexpected network ({len(r['unexpected_network'])}):")
            for n in r["unexpected_network"][:5]:
                lines.append(f"    - {n['process']} -> {n['endpoint']}")

        if r["run_errors"]:
            errs = "; ".join(f"{k}: {v}" for k, v in r["run_errors"].items() if v)
            if errs:
                lines.append(f"  Errors: {errs}")

        if r["verdict"] == "clean":
            lines.append(f"  No security threats detected ({r['total_events']} events analyzed)")

        lines.append("")
    return "\n".join(lines)


def build_output(results: list[dict]) -> dict | None:
    """Build Claude Code hook output JSON. Returns None for silent allow."""
    worst = "clean"
    for r in results:
        if r["verdict"] == "deny":
            worst = "deny"
            break
        if r["verdict"] == "warn":
            worst = "warn"

    context = format_context(results)

    if worst == "deny":
        denied = [r["package"] for r in results if r["verdict"] == "deny"]
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": (
                    f"Dyana detected high-severity security threats in: {', '.join(denied)}. "
                    f"Installation blocked.\n\n{context}"
                ),
            }
        }

    if worst == "warn":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": context,
            }
        }

    # Clean — brief note
    pkgs = ", ".join(r["package"] for r in results)
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": f"[Dyana] Scanned {pkgs}: no security threats detected.",
        }
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    # Parse hook input
    try:
        hook_input = json.loads(sys.stdin.read())
    except (json.JSONDecodeError, IOError):
        sys.exit(0)

    if hook_input.get("tool_name") != "Bash":
        sys.exit(0)

    command = hook_input.get("tool_input", {}).get("command", "")
    if not command:
        sys.exit(0)

    # Detect install commands
    packages = detect_install(command)
    if not packages:
        sys.exit(0)

    # Preflight: check dyana + docker
    err = preflight_check()
    if err:
        json.dump(
            {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": f"[Dyana] Scan skipped: {err}"}},
            sys.stdout,
        )
        sys.exit(0)

    # Scan each package
    results: list[dict] = []
    for loader, package in packages:
        cached = cache_get(loader, package)
        if cached:
            results.append(cached)
            continue

        trace = run_dyana_scan(loader, package)
        if trace is None:
            results.append(
                {
                    "package": package,
                    "loader": loader,
                    "scanned_at": time.time(),
                    "verdict": "warn",
                    "max_severity": -1,
                    "security_findings": [],
                    "unexpected_network": [],
                    "process_count": 0,
                    "total_events": 0,
                    "exit_code": -1,
                    "run_errors": {"scan": "Dyana scan failed to complete"},
                }
            )
            continue

        parsed = parse_trace(trace)
        result = build_result(package, loader, parsed)
        results.append(result)
        cache_set(loader, package, result)

    # Emit verdict
    output = build_output(results)
    if output:
        json.dump(output, sys.stdout)
    sys.exit(0)


if __name__ == "__main__":
    main()
