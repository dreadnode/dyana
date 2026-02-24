import sys
import typing as t
from unittest.mock import patch

from dyana.loaders.base.dyana import (
    GpuDeviceUsage,
    NetworkDeviceUsage,
    Profiler,
    Stage,
    capture_output,
    get_current_imports,
)


class TestProfiler:
    def setup_method(self) -> None:
        Profiler.instance = None

    def test_singleton(self) -> None:
        with patch("dyana.loaders.base.dyana.Stage.create") as mock_create:
            mock_create.return_value = Stage(name="start", timestamp=0, ram=0, disk=0, network={}, imports={})
            p = Profiler()
            assert Profiler.instance is p

    def test_on_stage(self) -> None:
        with patch("dyana.loaders.base.dyana.Stage.create") as mock_create:
            mock_create.return_value = Stage(name="test", timestamp=0, ram=0, disk=0, network={}, imports={})
            p = Profiler()
            p.on_stage("after_load")
            assert len(p._stages) == 2

    def test_track_error(self) -> None:
        with patch("dyana.loaders.base.dyana.Stage.create") as mock_create:
            mock_create.return_value = Stage(name="start", timestamp=0, ram=0, disk=0, network={}, imports={})
            p = Profiler()
            p.track_error("loader", "something broke")
            assert p._errors == {"loader": "something broke"}

    def test_track_warning(self) -> None:
        with patch("dyana.loaders.base.dyana.Stage.create") as mock_create:
            mock_create.return_value = Stage(name="start", timestamp=0, ram=0, disk=0, network={}, imports={})
            p = Profiler()
            p.track_warning("pip", "could not import")
            assert p._warnings == {"pip": "could not import"}

    def test_track_extra(self) -> None:
        with patch("dyana.loaders.base.dyana.Stage.create") as mock_create:
            mock_create.return_value = Stage(name="start", timestamp=0, ram=0, disk=0, network={}, imports={})
            p = Profiler()
            p.track_extra("imports", {"os": "/usr/lib"})
            assert p._extra == {"imports": {"os": "/usr/lib"}}

    def test_track(self) -> None:
        with patch("dyana.loaders.base.dyana.Stage.create") as mock_create:
            mock_create.return_value = Stage(name="start", timestamp=0, ram=0, disk=0, network={}, imports={})
            p = Profiler()
            p.track("custom_key", "custom_value")
            assert p._additionals == {"custom_key": "custom_value"}

    def test_as_dict(self) -> None:
        with patch("dyana.loaders.base.dyana.Stage.create") as mock_create:
            mock_create.return_value = Stage(name="start", timestamp=0, ram=0, disk=0, network={}, imports={})
            p = Profiler()
            p.track_error("err", "msg")
            result = p.as_dict()
            assert "stages" in result
            assert "errors" in result
            assert result["errors"] == {"err": "msg"}
            # as_dict adds an "end" stage
            assert len(result["stages"]) == 2

    def test_flush(self, capsys: t.Any) -> None:
        with patch("dyana.loaders.base.dyana.Stage.create") as mock_create:
            mock_create.return_value = Stage(name="start", timestamp=0, ram=0, disk=0, network={}, imports={})
            Profiler()
            Profiler.flush()
            captured = capsys.readouterr()
            assert "<DYANA_PROFILE>" in captured.out

    def test_flush_no_instance(self, capsys: t.Any) -> None:
        Profiler.instance = None
        Profiler.flush()
        captured = capsys.readouterr()
        assert captured.out == ""


class TestCaptureOutput:
    def test_captures_stdout(self) -> None:
        with capture_output() as (stdout, stderr):
            print("hello", end="")
        assert stdout.getvalue() == "hello"

    def test_captures_stderr(self) -> None:
        with capture_output() as (stdout, stderr):
            sys.stderr.write("error")
        assert stderr.getvalue() == "error"

    def test_restores_streams(self) -> None:
        old_stdout = sys.stdout
        old_stderr = sys.stderr
        with capture_output():
            pass
        assert sys.stdout is old_stdout
        assert sys.stderr is old_stderr


class TestGetCurrentImports:
    def test_returns_dict(self) -> None:
        result = get_current_imports()
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_contains_known_modules(self) -> None:
        result = get_current_imports()
        assert "sys" in result
        assert "os" in result


class TestStageCreate:
    def test_basic(self) -> None:
        with (
            patch("dyana.loaders.base.dyana.get_peak_rss", return_value=1024),
            patch("dyana.loaders.base.dyana.get_disk_usage", return_value=2048),
            patch("dyana.loaders.base.dyana.get_network_stats", return_value={"lo": NetworkDeviceUsage(rx=0, tx=0)}),
            patch("dyana.loaders.base.dyana.get_current_imports", return_value={"os": "/usr/lib/os.py"}),
        ):
            stage = Stage.create("test")
            assert stage.name == "test"
            assert stage.ram == 1024
            assert stage.disk == 2048
            assert stage.gpu is None

    def test_with_prev_imports(self) -> None:
        with (
            patch("dyana.loaders.base.dyana.get_peak_rss", return_value=1024),
            patch("dyana.loaders.base.dyana.get_disk_usage", return_value=2048),
            patch("dyana.loaders.base.dyana.get_network_stats", return_value={}),
            patch(
                "dyana.loaders.base.dyana.get_current_imports", return_value={"os": "/a", "sys": "/b", "new_mod": "/c"}
            ),
        ):
            stage = Stage.create("test", prev_imports={"os": "/a", "sys": "/b"})
            assert "new_mod" in stage.imports
            assert "os" not in stage.imports

    def test_with_gpu(self) -> None:
        gpu_usage = [GpuDeviceUsage(device_index=0, device_name="GPU0", total_memory=8192, free_memory=4096)]
        with (
            patch("dyana.loaders.base.dyana.get_peak_rss", return_value=1024),
            patch("dyana.loaders.base.dyana.get_disk_usage", return_value=2048),
            patch("dyana.loaders.base.dyana.get_network_stats", return_value={}),
            patch("dyana.loaders.base.dyana.get_current_imports", return_value={}),
            patch("dyana.loaders.base.dyana.get_gpu_usage", return_value=gpu_usage),
        ):
            stage = Stage.create("test", with_gpu=True)
            assert stage.gpu is not None
            assert len(stage.gpu) == 1
            assert stage.gpu[0].device_name == "GPU0"


class TestGpuDeviceUsage:
    def test_model(self) -> None:
        gpu = GpuDeviceUsage(device_index=0, device_name="RTX 3090", total_memory=24576, free_memory=20000)
        assert gpu.device_index == 0
        assert gpu.device_name == "RTX 3090"
        assert gpu.total_memory == 24576
        assert gpu.free_memory == 20000

    def test_serialization(self) -> None:
        gpu = GpuDeviceUsage(device_index=0, device_name="GPU", total_memory=1000, free_memory=500)
        data = gpu.model_dump()
        restored = GpuDeviceUsage.model_validate(data)
        assert restored == gpu


class TestNetworkDeviceUsage:
    def test_model(self) -> None:
        net = NetworkDeviceUsage(rx=1024, tx=512)
        assert net.rx == 1024
        assert net.tx == 512

    def test_serialization(self) -> None:
        net = NetworkDeviceUsage(rx=100, tx=200)
        data = net.model_dump()
        restored = NetworkDeviceUsage.model_validate(data)
        assert restored == net


class TestStageModel:
    def test_minimal(self) -> None:
        stage = Stage(name="test", timestamp=0, ram=1024, disk=2048, network={}, imports={})
        assert stage.name == "test"
        assert stage.gpu is None

    def test_with_all_fields(self) -> None:
        gpu = [GpuDeviceUsage(device_index=0, device_name="GPU", total_memory=1000, free_memory=500)]
        net = {"eth0": NetworkDeviceUsage(rx=100, tx=200)}
        stage = Stage(
            name="end",
            timestamp=12345,
            ram=2048,
            gpu=gpu,
            disk=4096,
            network=net,
            imports={"os": "/usr/lib/os.py"},
        )
        assert stage.gpu is not None
        assert len(stage.gpu) == 1
        assert "eth0" in stage.network

    def test_serialization_roundtrip(self) -> None:
        stage = Stage(name="test", timestamp=0, ram=1024, disk=2048, network={}, imports={"os": None})
        data = stage.model_dump()
        restored = Stage.model_validate(data)
        assert restored.name == "test"
        assert restored.imports == {"os": None}
