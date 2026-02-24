import json
import re
import typing as t
from datetime import datetime
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from dyana.cli import cli
from dyana.loaders.base.dyana import Stage
from dyana.loaders.loader import Run
from dyana.tracer.tracee import Trace

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


def _noop_loader_init(self: t.Any, **kwargs: t.Any) -> None:
    self.name = kwargs.get("name", "automodel")
    self.settings = None
    self.container_id = None


def _noop_tracer_init(self: t.Any, loader: t.Any, **kwargs: t.Any) -> None:
    self.loader = loader


def _make_trace(loader_name: str = "automodel") -> Trace:
    return Trace(
        started_at=datetime(2024, 1, 1),
        ended_at=datetime(2024, 1, 1, 0, 1),
        platform="Linux-6.1.0-x86_64",
        run=Run(
            loader_name=loader_name,
            stages=[
                Stage(name="start", timestamp=0, ram=1024, disk=2048, network={}, imports={}),
                Stage(name="end", timestamp=1000, ram=4096, disk=4096, network={}, imports={}),
            ],
        ),
        events=[],
    )


class TestTraceCommand:
    @patch("dyana.cli.Tracer.__init__", _noop_tracer_init)
    @patch("dyana.cli.Tracer.run_trace", return_value=_make_trace())
    @patch("dyana.cli.Loader.__init__", _noop_loader_init)
    def test_trace_runs_and_saves(self, _mock_run: t.Any, tmp_path: t.Any) -> None:
        out = tmp_path / "trace.json"
        result = runner.invoke(cli, ["trace", "--loader", "automodel", "--output", str(out)])
        assert result.exit_code == 0, result.output
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["run"]["loader_name"] == "automodel"

    @patch("dyana.cli.Tracer.__init__", _noop_tracer_init)
    @patch(
        "dyana.cli.Tracer.run_trace",
        side_effect=RuntimeError(
            "could not select device driver '' with capabilities: [[gpu]]"
        ),
    )
    @patch("dyana.cli.Loader.__init__", _noop_loader_init)
    def test_trace_gpu_error(self, _mock_run: t.Any) -> None:
        result = runner.invoke(cli, ["trace"])
        assert result.exit_code == 1
        assert "--no-gpu" in _strip_ansi(result.output)

    @patch("dyana.cli.Tracer.__init__", _noop_tracer_init)
    @patch("dyana.cli.Tracer.run_trace", side_effect=RuntimeError("something broke"))
    @patch("dyana.cli.Loader.__init__", _noop_loader_init)
    def test_trace_generic_error(self, _mock_run: t.Any) -> None:
        result = runner.invoke(cli, ["trace"])
        assert result.exit_code == 1
        assert "something broke" in _strip_ansi(result.output)


class TestLoadersCommand:
    @patch("dyana.cli.Loader.__init__", _noop_loader_init)
    @patch("dyana.cli.pathlib.Path.iterdir")
    def test_loaders_lists_available(self, mock_iterdir: t.Any) -> None:
        fake_a = MagicMock()
        fake_a.is_dir.return_value = True
        fake_a.name = "automodel"
        fake_b = MagicMock()
        fake_b.is_dir.return_value = True
        fake_b.name = "__pycache__"
        fake_c = MagicMock()
        fake_c.is_dir.return_value = True
        fake_c.name = "base"
        mock_iterdir.return_value = [fake_a, fake_b, fake_c]

        result = runner.invoke(cli, ["loaders"])
        assert result.exit_code == 0
        assert "automodel" in _strip_ansi(result.output)


class TestHelpCommand:
    @patch("dyana.cli.view_loader_help")
    @patch("dyana.cli.Loader.__init__", _noop_loader_init)
    def test_help_shows_loader_info(self, mock_view: t.Any) -> None:
        mock_view.return_value = None
        result = runner.invoke(cli, ["help", "automodel"])
        assert result.exit_code == 0
        mock_view.assert_called_once()

    @patch("dyana.cli.Loader.__init__", side_effect=ValueError("not found"))
    def test_help_nonexistent_loader(self, _mock_init: t.Any) -> None:
        result = runner.invoke(cli, ["help", "nonexistent"])
        assert result.exit_code == 1
        assert "not found" in _strip_ansi(result.output)
