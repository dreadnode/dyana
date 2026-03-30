import pytest

from dyana.loaders.loader import Loader, Run
from dyana.loaders.settings import LoaderSettings, ParsedArgument, Volume


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


class _FakeThread:
    def __init__(self, on_start: object | None = None) -> None:
        self._on_start = on_start
        self.daemon = False

    def start(self) -> None:
        if callable(self._on_start):
            self._on_start()


class _FakeContainer:
    def __init__(self, statuses: list[str]) -> None:
        self.id = "abc123"
        self._statuses = statuses
        self.status = statuses[0]
        self.killed = False

    def reload(self) -> None:
        if len(self._statuses) > 1:
            self._statuses.pop(0)
            self.status = self._statuses[0]

    def kill(self) -> None:
        self.killed = True


class TestLoaderRun:
    def _make_loader(self, tmp_path: pytest.TempPathFactory) -> Loader:
        loader = Loader.__new__(Loader)
        loader.name = "test-loader"
        loader.image = "image-id"
        loader.platform = "linux/amd64"
        loader.build_args = {"MODEL": "demo"}
        loader.timeout = 5
        loader.output = ""
        loader.container = None
        loader.container_id = None
        loader.reader_thread = None
        loader.mem_limit = "256m"
        loader.save = ["artifact.bin"]
        loader.need_artifacts = False
        loader.save_to = tmp_path / "artifacts"
        loader.settings = LoaderSettings(
            description="test loader",
            network=True,
            gpu=False,
            volumes=[Volume(host="~/shared", guest="/shared")],
        )
        loader.args = [
            ParsedArgument(name="model", value=str(tmp_path / "ModelDir"), volume=True),
            ParsedArgument(name="flag", value="value"),
        ]
        return loader

    def test_run_parses_profile_and_merges_extra_stdout(self, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
        loader = self._make_loader(tmp_path)
        model_dir = tmp_path / "ModelDir"
        model_dir.mkdir()
        save_dir = loader.save_to
        shared_dir = tmp_path / "shared"
        shared_dir.mkdir()

        container = _FakeContainer(["created", "exited"])

        def _set_output() -> None:
            loader.output = (
                "boot log\n"
                "<DYANA_PROFILE>"
                '{"stdout":"inner stdout","stderr":"warn","exit_code":0,"stages":[],"errors":{},"warnings":{},"extra":{}}'
            )

        monkeypatch.setattr("dyana.loaders.loader.threading.Thread", lambda target: _FakeThread(on_start=_set_output))
        monkeypatch.setattr("dyana.loaders.loader.time.sleep", lambda _: None)
        monkeypatch.setattr("dyana.loaders.loader.docker.run_detached", lambda *args, **kwargs: container)
        monkeypatch.setattr("dyana.loaders.loader.os.path.expanduser", lambda path: str(shared_dir) if path == "~/shared" else path)

        run = loader.run(allow_network=False, allow_gpus=True, allow_volume_write=False)

        assert run.loader_name == "test-loader"
        assert run.build_platform == "linux/amd64"
        assert run.build_args == {"MODEL": "demo"}
        assert run.arguments == ["--model", "/modeldir", "--flag", "value"]
        assert run.volumes == {
            str(model_dir.resolve()): "/modeldir",
            str(save_dir): "/artifacts",
            str(shared_dir): "/shared",
        }
        assert run.stdout == "inner stdoutboot log\n"
        assert run.stderr == "warn"
        assert loader.container_id == "abc123"

    def test_run_times_out_and_kills_container(self, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
        from datetime import datetime

        loader = self._make_loader(tmp_path)
        loader.timeout = 0
        loader.save = None
        loader.need_artifacts = False
        loader.settings = LoaderSettings(description="test loader", network=False, gpu=True)
        loader.args = None
        container = _FakeContainer(["running", "running"])

        class _FakeDateTime:
            values = [
                datetime(2024, 1, 1, 0, 0, 0),
                datetime(2024, 1, 1, 0, 0, 2),
            ]

            @classmethod
            def now(cls) -> datetime:
                return cls.values.pop(0)

        monkeypatch.setattr("dyana.loaders.loader.threading.Thread", lambda target: _FakeThread())
        monkeypatch.setattr("dyana.loaders.loader.time.sleep", lambda _: None)
        monkeypatch.setattr("dyana.loaders.loader.docker.run_detached", lambda *args, **kwargs: container)
        monkeypatch.setattr("dyana.loaders.loader.datetime", _FakeDateTime)

        run = loader.run()

        assert run.errors == {"timeout": "timeout reached, killing container"}
        assert container.killed is True

    def test_run_handles_container_error(self, tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
        import docker as docker_pkg

        loader = self._make_loader(tmp_path)
        loader.save = None
        loader.need_artifacts = False

        error = docker_pkg.errors.ContainerError(
            container="container",
            exit_status=7,
            command="run",
            image="image",
            stderr=b"container failed",
        )
        monkeypatch.setattr("dyana.loaders.loader.docker.run_detached", lambda *args, **kwargs: (_ for _ in ()).throw(error))

        run = loader.run()

        assert run.errors == {"container_execution_error": "container failed"}
