import typing as t
from unittest.mock import patch

from dyana.view_legacy import (
    view_legacy_disk_usage,
    view_legacy_extra,
    view_legacy_gpus,
    view_legacy_network_usage,
    view_legacy_ram,
)


class TestViewLegacyRam:
    def test_basic(self) -> None:
        run: dict[str, t.Any] = {"ram": {"start": 1024, "end": 2048}}
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_ram(run)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "RAM Usage" in output
            assert "start" in output
            assert "end" in output

    def test_empty_ram(self) -> None:
        run: dict[str, t.Any] = {"ram": {}}
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_ram(run)
            mock_print.assert_not_called()

    def test_none_ram(self) -> None:
        run: dict[str, t.Any] = {"ram": None}
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_ram(run)
            mock_print.assert_not_called()


class TestViewLegacyGpus:
    def test_no_gpu(self) -> None:
        run: dict[str, t.Any] = {"gpu": {}}
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_gpus(run)
            mock_print.assert_not_called()

    def test_with_gpu_change(self) -> None:
        run: dict[str, t.Any] = {
            "gpu": {
                "start": [{"device_name": "GPU0", "total_memory": 8192, "free_memory": 8000}],
                "end": [{"device_name": "GPU0", "total_memory": 8192, "free_memory": 4000}],
            }
        }
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_gpus(run)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "GPU Usage" in output


class TestViewLegacyDiskUsage:
    def test_basic(self) -> None:
        run: dict[str, t.Any] = {"disk": {"start": 1024, "end": 2048}}
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_disk_usage(run)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "Disk Usage" in output

    def test_no_disk(self) -> None:
        run: dict[str, t.Any] = {}
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_disk_usage(run)
            mock_print.assert_not_called()


class TestViewLegacyNetworkUsage:
    def test_with_activity(self) -> None:
        run: dict[str, t.Any] = {
            "network": {
                "start": {"eth0": {"rx": 0, "tx": 0}},
                "end": {"eth0": {"rx": 1024, "tx": 512}},
            }
        }
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_network_usage(run)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "Network Usage" in output
            assert "eth0" in output

    def test_no_activity(self) -> None:
        run: dict[str, t.Any] = {
            "network": {
                "start": {"eth0": {"rx": 0, "tx": 0}},
                "end": {"eth0": {"rx": 0, "tx": 0}},
            }
        }
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_network_usage(run)
            mock_print.assert_not_called()

    def test_no_network(self) -> None:
        run: dict[str, t.Any] = {}
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_network_usage(run)
            mock_print.assert_not_called()


class TestViewLegacyExtra:
    def test_imports(self) -> None:
        run: dict[str, t.Any] = {
            "extra": {
                "imports": {"os.path": "/usr/lib/os/path.py", "sys": "/usr/lib/sys.py"},
            }
        }
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_extra(run)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "Top Level Imports" in output

    def test_unknown_extra(self) -> None:
        run: dict[str, t.Any] = {"extra": {"unknown_key": "value"}}
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_extra(run)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "Other Records" in output
            assert "unknown_key" in output

    def test_no_extra(self) -> None:
        run: dict[str, t.Any] = {}
        with patch("dyana.view_legacy.rich_print") as mock_print:
            view_legacy_extra(run)
            mock_print.assert_not_called()
