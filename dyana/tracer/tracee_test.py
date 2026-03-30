from datetime import datetime
from unittest.mock import MagicMock, patch

from dyana.constants import SECURITY_EVENTS
from dyana.tracer.tracee import Trace, Tracer


class TestTraceModel:
    def test_minimal(self) -> None:
        from dyana.loaders.loader import Run

        trace = Trace(
            started_at=datetime(2024, 1, 1),
            ended_at=datetime(2024, 1, 1, 0, 1),
            platform="Linux-6.1.0-x86_64",
            run=Run(loader_name="test"),
        )
        assert trace.events == []
        assert trace.tracee_version is None
        assert trace.dyana_version is None

    def test_with_events(self) -> None:
        from dyana.loaders.loader import Run

        trace = Trace(
            started_at=datetime(2024, 1, 1),
            ended_at=datetime(2024, 1, 1, 0, 1),
            platform="Linux",
            run=Run(),
            events=[{"eventName": "test", "timestamp": 1000}],
        )
        assert len(trace.events) == 1

    def test_serialization(self) -> None:
        from dyana.loaders.loader import Run

        trace = Trace(
            started_at=datetime(2024, 1, 1),
            ended_at=datetime(2024, 1, 1, 0, 1),
            platform="Linux",
            run=Run(loader_name="test"),
            dyana_version="0.1.4",
        )
        data = trace.model_dump()
        assert data["dyana_version"] == "0.1.4"
        assert data["platform"] == "Linux"


class TestTracerConstants:
    def test_security_events_not_empty(self) -> None:
        assert len(Tracer.SECURITY_EVENTS) > 0

    def test_security_events_match_constants(self) -> None:
        assert Tracer.SECURITY_EVENTS == SECURITY_EVENTS

    def test_default_events_includes_security(self) -> None:
        for event in Tracer.SECURITY_EVENTS:
            assert event in Tracer.DEFAULT_EVENTS

    def test_default_events_includes_base_events(self) -> None:
        assert "security_file_open" in Tracer.DEFAULT_EVENTS
        assert "sched_process_exec" in Tracer.DEFAULT_EVENTS
        assert "net_packet_dns" in Tracer.DEFAULT_EVENTS


class TestOnTracerEvent:
    def _make_tracer_for_parsing(self) -> Tracer:
        """Create a Tracer with minimal init for testing _on_tracer_event."""
        tracer = Tracer.__new__(Tracer)
        tracer.trace = []
        tracer.errors = []
        tracer.reader_error = None
        tracer.ready = False
        tracer.tracee_kernel_release = None
        return tracer

    def test_json_event(self) -> None:
        tracer = self._make_tracer_for_parsing()
        tracer._on_tracer_event('{"eventName": "test", "timestamp": 1000}\n')
        assert len(tracer.trace) == 1
        assert tracer.trace[0]["eventName"] == "test"

    def test_error_line(self) -> None:
        tracer = self._make_tracer_for_parsing()
        tracer._on_tracer_event("Error: something went wrong\n")
        assert tracer.reader_error == "something went wrong"

    def test_ready_signal(self) -> None:
        tracer = self._make_tracer_for_parsing()
        tracer._on_tracer_event('{"L": "DEBUG", "M": "is ready callback fired"}\n')
        assert tracer.ready is True

    def test_kernel_release(self) -> None:
        tracer = self._make_tracer_for_parsing()
        tracer._on_tracer_event('{"L": "DEBUG", "KERNEL_RELEASE": "6.1.0"}\n')
        assert tracer.tracee_kernel_release == "6.1.0"

    def test_empty_line(self) -> None:
        tracer = self._make_tracer_for_parsing()
        tracer._on_tracer_event("   \n")
        assert len(tracer.trace) == 0
        assert tracer.reader_error is None


class TestTracerRunTrace:
    def test_filters_events_and_merges_tracer_errors(self) -> None:
        from dyana.loaders.loader import Run

        tracer = Tracer.__new__(Tracer)
        tracer.errors = ["tracee failed once"]
        tracer.trace = [
            {"eventName": "sched_process_exec", "containerId": "ABC123"},
            {"eventName": "sched_process_exec", "containerId": "different"},
            {"eventName": "sched_process_exec", "containerId": None},
        ]
        tracer.tracee_version = "tracee:latest@sha256:deadbeef"
        tracer.tracee_kernel_release = "6.8.0"
        tracer.loader = MagicMock()
        tracer.loader.container_id = "abc123"
        tracer.loader.run.return_value = Run(loader_name="loader-under-test", errors={"loader": "boom"})

        with (
            patch.object(tracer, "_start") as mock_start,
            patch.object(tracer, "_stop") as mock_stop,
            patch("dyana.tracer.tracee.platform.platform", return_value="Linux-test"),
            patch("dyana.tracer.tracee.dyana.__version__", "0.1.4"),
        ):
            trace = tracer.run_trace(allow_network=True, allow_gpus=False, allow_volume_write=True)

        mock_start.assert_called_once_with()
        mock_stop.assert_called_once_with()
        tracer.loader.run.assert_called_once_with(True, False, True)
        assert trace.platform == "Linux-test"
        assert trace.tracee_version == "tracee:latest@sha256:deadbeef"
        assert trace.tracee_kernel_release == "6.8.0"
        assert trace.run.errors == {"loader": "boom", "tracer": "tracee failed once"}
        assert trace.events == [{"eventName": "sched_process_exec", "containerId": "ABC123"}]
