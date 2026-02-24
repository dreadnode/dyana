import pytest

from dyana.loaders.loader import Loader, Run


class TestRunModel:
    def test_defaults(self) -> None:
        run = Run()
        assert run.loader_name is None
        assert run.stages is None
        assert run.errors is None
        assert run.exit_code is None

    def test_with_values(self) -> None:
        run = Run(
            loader_name="test",
            build_platform="linux/amd64",
            arguments=["--model", "gpt2"],
            exit_code=0,
        )
        assert run.loader_name == "test"
        assert run.arguments == ["--model", "gpt2"]

    def test_serialization_roundtrip(self) -> None:
        run = Run(loader_name="test", errors={"loader": "error"})
        json_str = run.model_dump_json()
        restored = Run.model_validate_json(json_str)
        assert restored.loader_name == "test"
        assert restored.errors == {"loader": "error"}


class TestLoaderValidation:
    def test_path_traversal_slash(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            Loader(name="../../etc/passwd", build=False)

    def test_path_traversal_dotdot(self) -> None:
        with pytest.raises(ValueError, match="path traversal"):
            Loader(name="foo..bar/../baz", build=False)

    def test_nonexistent_loader(self) -> None:
        with pytest.raises(ValueError, match="does not exist"):
            Loader(name="nonexistent_loader_xyz", build=False)


class TestCreateErroredRun:
    def test_structure(self) -> None:
        loader = Loader.__new__(Loader)
        loader.name = "test-loader"
        loader.platform = None
        loader.build_args = None
        loader.args = None

        run = loader._create_errored_run("timeout", "timeout reached")
        assert run.loader_name == "test-loader"
        assert run.errors == {"timeout": "timeout reached"}
        assert run.arguments is None
