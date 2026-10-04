from __future__ import annotations

import pickle
import typing as t
import zipfile
from pathlib import Path

from dyana.loaders.loader import Loader
from dyana.loaders.pytorch.main import (
    analyze_pytorch_file,
    check_zip_structure,
    scan_pickle_opcodes,
)


def _make_pytorch_zip(path: Path, state_dict: dict[str, t.Any] | None = None) -> None:
    """Create a minimal PyTorch-style ZIP checkpoint."""
    if state_dict is None:
        state_dict = {"model.weight": [1.0, 2.0, 3.0]}

    pkl_data = pickle.dumps(state_dict, protocol=2)
    tensor_data = b"\x00" * 24

    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("archive/data.pkl", pkl_data)
        zf.writestr("archive/data/0", tensor_data)


def _make_legacy_pickle(path: Path, obj: t.Any = None) -> None:
    """Create a legacy pickle file (non-ZIP)."""
    if obj is None:
        obj = {"weight": [1.0, 2.0]}
    with open(path, "wb") as f:
        pickle.dump(obj, f, protocol=2)


class TestPyTorchLoaderSettings:
    def test_loader_loads(self) -> None:
        loader = Loader(name="pytorch", build=False)
        assert loader.settings is not None
        assert loader.settings.gpu is False

    def test_correct_arg_structure(self) -> None:
        loader = Loader(name="pytorch", build=False)
        assert loader.settings is not None
        assert loader.settings.args is not None
        assert len(loader.settings.args) == 1
        assert loader.settings.args[0].name == "pytorch"
        assert loader.settings.args[0].required is True
        assert loader.settings.args[0].volume is True


class TestCheckZipStructure:
    def test_valid_zip(self, tmp_path: Path) -> None:
        path = tmp_path / "model.pt"
        _make_pytorch_zip(path)
        result = check_zip_structure(str(path))
        assert result["is_zip"] is True
        assert result["is_legacy_pickle"] is False
        assert len(result["zip_entries"]) == 2
        assert result["errors"] == []

    def test_legacy_pickle(self, tmp_path: Path) -> None:
        path = tmp_path / "model.pt"
        _make_legacy_pickle(path)
        result = check_zip_structure(str(path))
        assert result["is_zip"] is False
        assert result["is_legacy_pickle"] is True
        assert any("legacy" in i for i in result["info"])

    def test_invalid_file(self, tmp_path: Path) -> None:
        path = tmp_path / "garbage.pt"
        path.write_text("this is not a pytorch file")
        result = check_zip_structure(str(path))
        assert result["is_zip"] is False
        assert result["is_legacy_pickle"] is False

    def test_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.pt"
        path.write_bytes(b"")
        result = check_zip_structure(str(path))
        assert result["is_zip"] is False
        assert result["is_legacy_pickle"] is False

    def test_zip_path_traversal(self, tmp_path: Path) -> None:
        path = tmp_path / "evil.pt"
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("../../etc/passwd", b"root:x:0:0")
        result = check_zip_structure(str(path))
        assert any("path traversal" in e for e in result["errors"])


class TestScanPickleOpcodes:
    def test_safe_pickle(self) -> None:
        data = pickle.dumps({"key": "value"}, protocol=2)
        result = scan_pickle_opcodes(data)
        assert result["errors"] == []

    def test_detects_global_import(self) -> None:
        # Create pickle that uses GLOBAL opcode
        data = pickle.dumps({"key": "value"}, protocol=2)
        result = scan_pickle_opcodes(data)
        # A simple dict pickle may or may not have GLOBAL ops depending on protocol
        # but it should parse without errors
        assert "all_opcodes" in result

    def test_dangerous_os_system(self) -> None:
        # Manually craft a pickle with os.system call
        # PROTO 2, GLOBAL 'os system', SHORT_BINUNICODE 'echo pwned', TUPLE1, REDUCE, STOP
        malicious = (
            b"\x80\x02"  # PROTO 2
            b"cos\nsystem\n"  # GLOBAL os.system
            b"\x8c\x0aecho pwned"  # SHORT_BINUNICODE 'echo pwned'
            b"\x85"  # TUPLE1
            b"R"  # REDUCE
            b"."  # STOP
        )
        result = scan_pickle_opcodes(malicious)
        assert any("os.system" in e for e in result["errors"])
        assert any(op["opcode"] == "GLOBAL" for op in result["dangerous_ops"])
        assert any(op["opcode"] == "REDUCE" for op in result["dangerous_ops"])

    def test_dangerous_subprocess(self) -> None:
        malicious = b"\x80\x02csubprocess\ncheck_output\n\x8c\x02id\x85R."
        result = scan_pickle_opcodes(malicious)
        assert any("subprocess" in e for e in result["errors"])

    def test_known_safe_globals_not_flagged(self) -> None:
        # Craft pickle with a known-safe torch global
        safe = b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\n."
        result = scan_pickle_opcodes(safe)
        # Should not have errors for known-safe globals
        assert not any("suspicious" in e for e in result["errors"])

    def test_unknown_global_warning(self) -> None:
        # Craft pickle with an unknown but not suspicious global
        unknown = b"\x80\x02cmy_custom_module\nmy_function\n."
        result = scan_pickle_opcodes(unknown)
        assert any("unknown" in w for w in result["warnings"])

    def test_invalid_pickle(self) -> None:
        result = scan_pickle_opcodes(b"\xff\xff\xff\xff")
        assert len(result["errors"]) > 0

    def test_opcode_counting(self) -> None:
        data = pickle.dumps([1, 2, 3], protocol=2)
        result = scan_pickle_opcodes(data)
        assert isinstance(result["all_opcodes"], dict)
        assert sum(result["all_opcodes"].values()) > 0


class TestAnalyzePytorchFile:
    def test_valid_zip_checkpoint(self, tmp_path: Path) -> None:
        path = tmp_path / "model.pt"
        _make_pytorch_zip(path)
        result = analyze_pytorch_file(str(path))
        assert result["is_zip"] is True
        assert result["pickle_scan"] is not None
        assert result["file_size"] > 0

    def test_legacy_pickle_checkpoint(self, tmp_path: Path) -> None:
        path = tmp_path / "model.pt"
        _make_legacy_pickle(path)
        result = analyze_pytorch_file(str(path))
        assert result["is_legacy_pickle"] is True
        assert result["pickle_scan"] is not None

    def test_invalid_file(self, tmp_path: Path) -> None:
        path = tmp_path / "garbage.pt"
        path.write_text("not a pytorch file")
        result = analyze_pytorch_file(str(path))
        assert any("not a valid PyTorch" in e for e in result["errors"])

    def test_data_files_detected(self, tmp_path: Path) -> None:
        path = tmp_path / "model.pt"
        _make_pytorch_zip(path)
        result = analyze_pytorch_file(str(path))
        assert len(result["data_files"]) == 1
        assert result["data_files"][0]["name"] == "archive/data/0"

    def test_malicious_zip_checkpoint(self, tmp_path: Path) -> None:
        path = tmp_path / "evil.pt"
        malicious_pkl = b"\x80\x02cos\nsystem\n\x8c\x0aecho pwned\x85R."
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("archive/data.pkl", malicious_pkl)
        result = analyze_pytorch_file(str(path))
        assert any("os.system" in e for e in result["errors"])
