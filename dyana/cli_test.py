import json
import re
import sys
import typing as t
from unittest.mock import MagicMock

# Mock cysimdjson before importing cli (not available on macOS ARM)
_mock_cysimdjson = MagicMock()  # noqa: E402


class _FakeJSONParser:
    def loads(self, raw: str) -> t.Any:
        return json.loads(raw)


_mock_cysimdjson.JSONParser = _FakeJSONParser
sys.modules.setdefault("cysimdjson", _mock_cysimdjson)

from typer.testing import CliRunner  # noqa: E402

from dyana.cli import cli  # noqa: E402

runner = CliRunner()

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _strip_ansi(text: str) -> str:
    return _ANSI_RE.sub("", text)


class TestCLIHelp:
    def test_help(self) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Blackbox profiler" in _strip_ansi(result.output)

    def test_trace_help(self) -> None:
        result = runner.invoke(cli, ["trace", "--help"])
        assert result.exit_code == 0
        output = _strip_ansi(result.output)
        assert "--loader" in output
        assert "--timeout" in output

    def test_summary_help(self) -> None:
        result = runner.invoke(cli, ["summary", "--help"])
        assert result.exit_code == 0
        assert "--trace-path" in _strip_ansi(result.output)

    def test_help_command_help(self) -> None:
        result = runner.invoke(cli, ["help", "--help"])
        assert result.exit_code == 0
        assert "LOADER" in _strip_ansi(result.output)

    def test_loaders_help(self) -> None:
        result = runner.invoke(cli, ["loaders", "--help"])
        assert result.exit_code == 0
        assert "--build" in _strip_ansi(result.output)


class TestSummaryCommand:
    def test_summary_with_modern_trace(self, tmp_path: t.Any) -> None:
        trace_data = {
            "started_at": "2024-01-01T00:00:00",
            "ended_at": "2024-01-01T00:01:00",
            "platform": "Linux-6.1.0-x86_64",
            "run": {
                "loader_name": "test-loader",
                "build_platform": None,
                "build_args": None,
                "arguments": None,
                "volumes": None,
                "errors": None,
                "warnings": None,
                "stdout": None,
                "stderr": None,
                "exit_code": None,
                "stages": [
                    {
                        "name": "start",
                        "timestamp": 0,
                        "ram": 1024,
                        "gpu": None,
                        "disk": 2048,
                        "network": {},
                        "imports": {},
                    },
                    {
                        "name": "end",
                        "timestamp": 1000,
                        "ram": 4096,
                        "gpu": None,
                        "disk": 4096,
                        "network": {},
                        "imports": {"torch": "/usr/lib/torch/__init__.py"},
                    },
                ],
                "extra": None,
            },
            "events": [],
        }
        trace_file = tmp_path / "trace.json"
        trace_file.write_text(json.dumps(trace_data))

        result = runner.invoke(cli, ["summary", "--trace-path", str(trace_file)])
        assert result.exit_code == 0
        assert "test-loader" in result.output
        assert "RAM Usage" in result.output
        assert "Disk Usage" in result.output

    def test_summary_with_legacy_trace(self, tmp_path: t.Any) -> None:
        trace_data = {
            "started_at": "2024-01-01T00:00:00",
            "ended_at": "2024-01-01T00:01:00",
            "platform": "Linux-6.1.0-x86_64",
            "run": {
                "loader_name": "test-loader",
                "build_platform": None,
                "build_args": None,
                "arguments": None,
                "volumes": None,
                "errors": None,
                "warnings": None,
                "stdout": None,
                "stderr": None,
                "exit_code": None,
                "ram": {"start": 1024, "end": 2048},
                "gpu": {},
                "disk": {"start": 2048, "end": 4096},
                "network": {},
                "extra": None,
            },
            "events": [],
        }
        trace_file = tmp_path / "trace.json"
        trace_file.write_text(json.dumps(trace_data))

        result = runner.invoke(cli, ["summary", "--trace-path", str(trace_file)])
        assert result.exit_code == 0
        assert "test-loader" in result.output
        assert "WARNING" in result.output

    def test_summary_missing_file(self) -> None:
        result = runner.invoke(cli, ["summary", "--trace-path", "/nonexistent/trace.json"])
        assert result.exit_code != 0
