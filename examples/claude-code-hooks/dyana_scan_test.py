#!/usr/bin/env python3
"""Tests for dyana_scan.py Claude Code hook."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from dyana_scan import (
    _classify_network,
    _extract_packages,
    build_output,
    build_result,
    cache_get,
    cache_set,
    detect_install,
    format_context,
    parse_trace,
)


# ---------------------------------------------------------------------------
# Command detection
# ---------------------------------------------------------------------------


class TestDetectInstall(unittest.TestCase):
    """Test that install commands are correctly detected and packages extracted."""

    # --- pip ecosystem ---

    def test_pip_install_single(self):
        self.assertEqual(detect_install("pip install requests"), [("pip", "requests")])

    def test_pip3_install(self):
        self.assertEqual(detect_install("pip3 install flask"), [("pip", "flask")])

    def test_pip_install_multiple(self):
        self.assertEqual(
            detect_install("pip install requests flask numpy"),
            [("pip", "requests"), ("pip", "flask"), ("pip", "numpy")],
        )

    def test_pip_install_version_pinned(self):
        self.assertEqual(detect_install("pip install requests==2.28.0"), [("pip", "requests")])

    def test_pip_install_version_range(self):
        self.assertEqual(detect_install("pip install 'requests>=2.0,<3.0'"), [("pip", "requests")])

    def test_pip_install_with_flags(self):
        self.assertEqual(detect_install("pip install --no-cache-dir requests"), [("pip", "requests")])

    def test_pip_install_index_url(self):
        self.assertEqual(
            detect_install("pip install --index-url https://pypi.example.com requests"),
            [("pip", "requests")],
        )

    def test_python_m_pip(self):
        self.assertEqual(detect_install("python -m pip install torch"), [("pip", "torch")])

    def test_python3_m_pip(self):
        self.assertEqual(detect_install("python3 -m pip install numpy"), [("pip", "numpy")])

    def test_sudo_pip(self):
        self.assertEqual(detect_install("sudo pip install requests"), [("pip", "requests")])

    def test_uv_pip_install(self):
        self.assertEqual(detect_install("uv pip install requests"), [("pip", "requests")])

    def test_uv_add(self):
        self.assertEqual(detect_install("uv add flask"), [("pip", "flask")])

    def test_poetry_add(self):
        self.assertEqual(detect_install("poetry add requests"), [("pip", "requests")])

    def test_chained_pip(self):
        self.assertEqual(detect_install("cd /app && pip install flask"), [("pip", "flask")])

    # --- npm ecosystem ---

    def test_npm_install(self):
        self.assertEqual(detect_install("npm install express"), [("npm", "express")])

    def test_npm_i(self):
        self.assertEqual(detect_install("npm i lodash"), [("npm", "lodash")])

    def test_yarn_add(self):
        self.assertEqual(detect_install("yarn add react"), [("npm", "react")])

    def test_pnpm_add(self):
        self.assertEqual(detect_install("pnpm add vue"), [("npm", "vue")])

    def test_pnpm_install_with_package(self):
        self.assertEqual(detect_install("pnpm install axios"), [("npm", "axios")])

    def test_npm_scoped_package(self):
        self.assertEqual(detect_install("npm install @angular/core"), [("npm", "@angular/core")])

    def test_npm_scoped_with_version(self):
        self.assertEqual(detect_install("npm install @angular/core@16.0.0"), [("npm", "@angular/core")])

    # --- skip patterns (should return None) ---

    def test_skip_plain_command(self):
        self.assertIsNone(detect_install("ls -la"))

    def test_skip_git(self):
        self.assertIsNone(detect_install("git status"))

    def test_skip_echo(self):
        self.assertIsNone(detect_install("echo hello"))

    def test_skip_pip_requirements(self):
        self.assertIsNone(detect_install("pip install -r requirements.txt"))

    def test_skip_pip_editable(self):
        self.assertIsNone(detect_install("pip install -e ."))

    def test_skip_pip_dot(self):
        self.assertIsNone(detect_install("pip install ."))

    def test_skip_npm_ci(self):
        self.assertIsNone(detect_install("npm ci"))

    def test_skip_bare_npm_install(self):
        self.assertIsNone(detect_install("npm install"))

    def test_skip_poetry_install(self):
        self.assertIsNone(detect_install("poetry install"))

    def test_skip_uv_sync(self):
        self.assertIsNone(detect_install("uv sync"))

    def test_skip_bare_yarn(self):
        self.assertIsNone(detect_install("yarn"))

    def test_skip_yarn_install(self):
        self.assertIsNone(detect_install("yarn install"))

    def test_skip_bare_pnpm_install(self):
        self.assertIsNone(detect_install("pnpm install"))


# ---------------------------------------------------------------------------
# Package extraction
# ---------------------------------------------------------------------------


class TestExtractPackages(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(_extract_packages("requests", "pip"), [("pip", "requests")])

    def test_with_version(self):
        self.assertEqual(_extract_packages("requests==2.28", "pip"), [("pip", "requests")])

    def test_multiple(self):
        self.assertEqual(
            _extract_packages("flask requests", "pip"),
            [("pip", "flask"), ("pip", "requests")],
        )

    def test_skip_flags(self):
        self.assertEqual(_extract_packages("--no-cache-dir requests", "pip"), [("pip", "requests")])

    def test_npm_scoped(self):
        self.assertEqual(_extract_packages("@scope/pkg", "npm"), [("npm", "@scope/pkg")])

    def test_npm_with_version(self):
        self.assertEqual(_extract_packages("express@4.0.0", "npm"), [("npm", "express")])


# ---------------------------------------------------------------------------
# Trace parsing
# ---------------------------------------------------------------------------


def _make_trace(events=None, errors=None, exit_code=0):
    """Helper to build a minimal trace dict."""
    return {
        "events": events or [],
        "run": {
            "errors": errors or {},
            "exit_code": exit_code,
        },
    }


def _make_event(name, args=None, metadata=None, process="python3"):
    """Helper to build a trace event."""
    event = {
        "eventName": name,
        "processName": process,
        "args": args or [],
    }
    if metadata:
        event["metadata"] = metadata
    return event


class TestParseTrace(unittest.TestCase):
    def test_empty_trace(self):
        result = parse_trace(_make_trace())
        self.assertEqual(result["total_events"], 0)
        self.assertEqual(result["security_findings"], [])
        self.assertEqual(result["max_severity"], 0)

    def test_security_event_detected(self):
        events = [
            _make_event(
                "stdio_over_socket",
                metadata={
                    "Description": "Redirected stdio to socket",
                    "Properties": {
                        "signatureName": "stdio_over_socket",
                        "Category": "execution",
                        "Severity": 3,
                    },
                },
            )
        ]
        result = parse_trace(_make_trace(events))
        self.assertEqual(len(result["security_findings"]), 1)
        self.assertEqual(result["max_severity"], 3)
        self.assertEqual(result["security_findings"][0]["name"], "stdio_over_socket")
        self.assertEqual(result["security_findings"][0]["severity"], 3)

    def test_security_events_deduped(self):
        events = [
            _make_event("ld_preload", metadata={"Properties": {"signatureName": "ld_preload", "Severity": 2, "Category": "persistence"}}),
            _make_event("ld_preload", metadata={"Properties": {"signatureName": "ld_preload", "Severity": 2, "Category": "persistence"}}),
        ]
        result = parse_trace(_make_trace(events))
        self.assertEqual(len(result["security_findings"]), 1)

    def test_network_socket_connect(self):
        events = [
            _make_event(
                "security_socket_connect",
                args=[{"name": "remote_addr", "value": {"sa_family": "AF_INET", "sin_addr": "1.2.3.4", "sin_port": 443}}],
                process="curl",
            )
        ]
        result = parse_trace(_make_trace(events))
        self.assertEqual(len(result["network"]), 1)
        self.assertEqual(result["network"][0]["endpoint"], "1.2.3.4:443")
        self.assertEqual(result["network"][0]["process"], "curl")

    def test_network_dns(self):
        events = [
            _make_event(
                "net_packet_dns",
                args=[
                    {
                        "name": "proto_dns",
                        "value": {
                            "questions": [{"name": "evil.example.com"}],
                            "answers": [{"IP": "6.6.6.6"}],
                        },
                    }
                ],
            )
        ]
        result = parse_trace(_make_trace(events))
        self.assertEqual(len(result["network"]), 1)
        self.assertIn("evil.example.com", result["network"][0]["endpoint"])

    def test_process_count(self):
        events = [
            _make_event("sched_process_exec"),
            _make_event("sched_process_exec"),
            _make_event("security_file_open"),
        ]
        result = parse_trace(_make_trace(events))
        self.assertEqual(result["process_count"], 2)

    def test_run_errors_propagated(self):
        result = parse_trace(_make_trace(errors={"timeout": "timed out"}, exit_code=1))
        self.assertEqual(result["run_errors"], {"timeout": "timed out"})
        self.assertEqual(result["exit_code"], 1)


# ---------------------------------------------------------------------------
# Network classification
# ---------------------------------------------------------------------------


class TestClassifyNetwork(unittest.TestCase):
    def test_expected_dns(self):
        conns = [{"process": "pip", "endpoint": "DNS: pypi.org", "family": "DNS", "resolved": ["151.101.0.223"]}]
        expected, unexpected = _classify_network(conns)
        self.assertEqual(len(expected), 1)
        self.assertEqual(len(unexpected), 0)

    def test_unexpected_dns(self):
        conns = [{"process": "python3", "endpoint": "DNS: evil-c2.example.com", "family": "DNS", "resolved": ["6.6.6.6"]}]
        expected, unexpected = _classify_network(conns)
        self.assertEqual(len(expected), 0)
        self.assertEqual(len(unexpected), 1)

    def test_known_ip_from_dns(self):
        conns = [
            {"process": "pip", "endpoint": "DNS: pypi.org", "family": "DNS", "resolved": ["151.101.0.223"]},
            {"process": "pip", "endpoint": "151.101.0.223:443", "family": "AF_INET"},
        ]
        expected, unexpected = _classify_network(conns)
        self.assertEqual(len(expected), 2)
        self.assertEqual(len(unexpected), 0)

    def test_unknown_ip(self):
        conns = [{"process": "python3", "endpoint": "185.0.0.1:4444", "family": "AF_INET"}]
        expected, unexpected = _classify_network(conns)
        self.assertEqual(len(expected), 0)
        self.assertEqual(len(unexpected), 1)

    def test_loopback_expected(self):
        conns = [{"process": "node", "endpoint": "127.0.0.1:53", "family": "AF_INET"}]
        expected, unexpected = _classify_network(conns)
        self.assertEqual(len(expected), 1)

    def test_private_ip_expected(self):
        for ip in ["10.0.0.1:80", "172.16.0.1:80", "192.168.1.1:80"]:
            conns = [{"process": "pip", "endpoint": ip, "family": "AF_INET"}]
            expected, unexpected = _classify_network(conns)
            self.assertEqual(len(expected), 1, f"Expected {ip} to be classified as expected")


# ---------------------------------------------------------------------------
# Verdict logic
# ---------------------------------------------------------------------------


class TestBuildResult(unittest.TestCase):
    def test_clean(self):
        parsed = {
            "security_findings": [],
            "max_severity": 0,
            "network": [],
            "process_count": 3,
            "total_events": 50,
            "run_errors": {},
            "exit_code": 0,
        }
        result = build_result("requests", "pip", parsed)
        self.assertEqual(result["verdict"], "clean")

    def test_deny_on_high_severity(self):
        parsed = {
            "security_findings": [{"name": "stdio_over_socket", "severity": 3, "category": "exec"}],
            "max_severity": 3,
            "network": [],
            "process_count": 5,
            "total_events": 100,
            "run_errors": {},
            "exit_code": 0,
        }
        result = build_result("evil-pkg", "pip", parsed)
        self.assertEqual(result["verdict"], "deny")

    def test_warn_on_moderate_severity(self):
        parsed = {
            "security_findings": [{"name": "hidden_file_created", "severity": 2, "category": "persistence"}],
            "max_severity": 2,
            "network": [],
            "process_count": 3,
            "total_events": 80,
            "run_errors": {},
            "exit_code": 0,
        }
        result = build_result("sketchy-pkg", "pip", parsed)
        self.assertEqual(result["verdict"], "warn")

    def test_warn_on_unexpected_network(self):
        parsed = {
            "security_findings": [],
            "max_severity": 0,
            "network": [
                {"process": "python3", "endpoint": "185.0.0.1:4444", "family": "AF_INET"},
            ],
            "process_count": 3,
            "total_events": 50,
            "run_errors": {},
            "exit_code": 0,
        }
        result = build_result("odd-pkg", "pip", parsed)
        self.assertEqual(result["verdict"], "warn")


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


class TestBuildOutput(unittest.TestCase):
    def test_deny_output(self):
        results = [
            {
                "package": "evil-pkg",
                "loader": "pip",
                "verdict": "deny",
                "max_severity": 3,
                "security_findings": [{"name": "stdio_over_socket", "severity": 3, "category": "execution"}],
                "unexpected_network": [],
                "process_count": 5,
                "total_events": 100,
                "exit_code": 0,
                "run_errors": {},
                "scanned_at": time.time(),
            }
        ]
        output = build_output(results)
        self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertIn("evil-pkg", output["hookSpecificOutput"]["permissionDecisionReason"])

    def test_warn_output(self):
        results = [
            {
                "package": "sketchy-pkg",
                "loader": "npm",
                "verdict": "warn",
                "max_severity": 1,
                "security_findings": [{"name": "dynamic_code_loading", "severity": 1, "category": "execution"}],
                "unexpected_network": [],
                "process_count": 3,
                "total_events": 60,
                "exit_code": 0,
                "run_errors": {},
                "scanned_at": time.time(),
            }
        ]
        output = build_output(results)
        self.assertNotIn("permissionDecision", output["hookSpecificOutput"])
        self.assertIn("WARNING", output["hookSpecificOutput"]["additionalContext"])

    def test_clean_output(self):
        results = [
            {
                "package": "requests",
                "loader": "pip",
                "verdict": "clean",
                "max_severity": 0,
                "security_findings": [],
                "unexpected_network": [],
                "process_count": 3,
                "total_events": 50,
                "exit_code": 0,
                "run_errors": {},
                "scanned_at": time.time(),
            }
        ]
        output = build_output(results)
        self.assertIn("no security threats", output["hookSpecificOutput"]["additionalContext"])


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


class TestCache(unittest.TestCase):
    def setUp(self):
        self._orig = os.environ.get("DYANA_CACHE_TTL")
        self._tmpdir = tempfile.mkdtemp()
        # Monkey-patch CACHE_DIR for tests
        import dyana_scan

        self._orig_dir = dyana_scan.CACHE_DIR
        dyana_scan.CACHE_DIR = __import__("pathlib").Path(self._tmpdir)

    def tearDown(self):
        import dyana_scan
        import shutil

        dyana_scan.CACHE_DIR = self._orig_dir
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        if self._orig is not None:
            os.environ["DYANA_CACHE_TTL"] = self._orig
        elif "DYANA_CACHE_TTL" in os.environ:
            del os.environ["DYANA_CACHE_TTL"]

    def test_cache_miss(self):
        self.assertIsNone(cache_get("pip", "nonexistent"))

    def test_cache_roundtrip(self):
        data = {"package": "requests", "scanned_at": time.time(), "verdict": "clean"}
        cache_set("pip", "requests", data)
        got = cache_get("pip", "requests")
        self.assertIsNotNone(got)
        self.assertEqual(got["package"], "requests")

    def test_cache_expired(self):
        data = {"package": "old", "scanned_at": time.time() - 100000, "verdict": "clean"}
        cache_set("pip", "old", data)
        self.assertIsNone(cache_get("pip", "old"))


# ---------------------------------------------------------------------------
# Integration: parse real trace files
# ---------------------------------------------------------------------------


class TestRealTraces(unittest.TestCase):
    """Test against actual Dyana trace files from the examples directory."""

    examples_dir = os.path.join(os.path.dirname(__file__), "..", "linux-exe-on-macos.json")

    def test_linux_exe_trace(self):
        path = os.path.join(os.path.dirname(__file__), "..", "linux-exe-on-macos.json")
        if not os.path.exists(path):
            self.skipTest("Example trace not found")

        with open(path) as f:
            trace = json.load(f)

        result = parse_trace(trace)
        self.assertGreater(result["total_events"], 0)
        self.assertGreater(result["process_count"], 0)
        self.assertIsInstance(result["security_findings"], list)
        self.assertIsInstance(result["network"], list)

    def test_llama_trace(self):
        path = os.path.join(os.path.dirname(__file__), "..", "llama-3.2-1b-linux.json")
        if not os.path.exists(path):
            self.skipTest("Example trace not found")

        with open(path) as f:
            trace = json.load(f)

        result = parse_trace(trace)
        self.assertGreater(result["total_events"], 100)


# ---------------------------------------------------------------------------
# Format output
# ---------------------------------------------------------------------------


class TestFormatContext(unittest.TestCase):
    def test_blocked_format(self):
        results = [
            {
                "package": "evil",
                "loader": "pip",
                "verdict": "deny",
                "max_severity": 3,
                "security_findings": [{"name": "ptrace_code_injection", "severity": 3, "category": "injection"}],
                "unexpected_network": [{"process": "python3", "endpoint": "1.2.3.4:4444"}],
                "run_errors": {},
                "total_events": 200,
                "exit_code": 0,
                "scanned_at": time.time(),
            }
        ]
        text = format_context(results)
        self.assertIn("BLOCKED", text)
        self.assertIn("ptrace_code_injection", text)
        self.assertIn("1.2.3.4:4444", text)

    def test_clean_format(self):
        results = [
            {
                "package": "requests",
                "loader": "pip",
                "verdict": "clean",
                "max_severity": 0,
                "security_findings": [],
                "unexpected_network": [],
                "run_errors": {},
                "total_events": 50,
                "exit_code": 0,
                "scanned_at": time.time(),
            }
        ]
        text = format_context(results)
        self.assertIn("CLEAN", text)
        self.assertIn("No security threats", text)


if __name__ == "__main__":
    unittest.main()
