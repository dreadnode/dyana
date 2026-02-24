from unittest.mock import MagicMock, patch

import pytest

from dyana.docker import (
    _ensure_docker_client,
    _get_client,
    build,
    pull,
    run_detached,
    run_privileged_detached,
    sanitized_agent_name,
)


class TestSanitizedAgentName:
    def test_lowercase(self) -> None:
        assert sanitized_agent_name("MyModel") == "mymodel"

    def test_special_chars_removed(self) -> None:
        assert sanitized_agent_name("my@model!v2") == "mymodelv2"

    def test_spaces_to_hyphens(self) -> None:
        assert sanitized_agent_name("my model name") == "my-model-name"

    def test_multiple_hyphens_collapsed(self) -> None:
        assert sanitized_agent_name("my---model") == "my-model"

    def test_leading_trailing_hyphens_stripped(self) -> None:
        assert sanitized_agent_name("-my-model-") == "my-model"

    def test_empty_string(self) -> None:
        assert sanitized_agent_name("") == ""

    def test_underscores_preserved(self) -> None:
        assert sanitized_agent_name("my_model") == "my_model"

    def test_mixed(self) -> None:
        assert sanitized_agent_name("  Hello World! v2.0  ") == "hello-world-v20"


class TestGetClient:
    def test_lazy_initialization(self) -> None:
        import dyana.docker as docker_mod

        # Reset state
        docker_mod._client = None
        docker_mod._client_initialized = False

        with patch("dyana.docker.docker") as mock_docker:
            mock_client = MagicMock()
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            result = _get_client()
            assert result is mock_client
            mock_docker.from_env.assert_called_once()

        # Reset state for other tests
        docker_mod._client = None
        docker_mod._client_initialized = False

    def test_cached_after_first_call(self) -> None:
        import dyana.docker as docker_mod

        docker_mod._client = None
        docker_mod._client_initialized = False

        with patch("dyana.docker.docker") as mock_docker:
            mock_client = MagicMock()
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            _get_client()
            _get_client()
            mock_docker.from_env.assert_called_once()

        docker_mod._client = None
        docker_mod._client_initialized = False

    def test_returns_none_when_docker_unavailable(self) -> None:
        import dyana.docker as docker_mod

        docker_mod._client = None
        docker_mod._client_initialized = False

        with (
            patch("dyana.docker.docker") as mock_docker,
            patch("dyana.docker.os.path.exists", return_value=False),
        ):
            mock_docker.from_env.side_effect = Exception("no docker")
            mock_docker.errors.DockerException = Exception

            result = _get_client()
            assert result is None

        docker_mod._client = None
        docker_mod._client_initialized = False


class TestEnsureDockerClient:
    def test_raises_when_no_client(self) -> None:
        with patch("dyana.docker._get_client", return_value=None):
            with pytest.raises(Exception, match="docker is not"):
                _ensure_docker_client()

    def test_returns_client(self) -> None:
        mock_client = MagicMock()
        with patch("dyana.docker._get_client", return_value=mock_client):
            result = _ensure_docker_client()
            assert result is mock_client


class TestBuild:
    def test_build_error(self, mock_docker_client: MagicMock) -> None:
        mock_docker_client.api.build.return_value = [{"error": "build failed"}]
        with pytest.raises(Exception, match="build failed"):
            build("/tmp/test", "test-image")

    def test_build_no_id(self, mock_docker_client: MagicMock) -> None:
        mock_docker_client.api.build.return_value = [{"stream": "Step 1/1"}]
        with pytest.raises(Exception, match="Failed to build image"):
            build("/tmp/test", "test-image")

    def test_build_success(self, mock_docker_client: MagicMock) -> None:
        mock_image = MagicMock()
        mock_docker_client.api.build.return_value = [{"aux": {"ID": "sha256:abc123"}}]
        mock_docker_client.images.get.return_value = mock_image

        result = build("/tmp/test", "test-image")
        assert result is mock_image
        mock_docker_client.images.get.assert_called_once_with("sha256:abc123")

    def test_build_sanitizes_name(self, mock_docker_client: MagicMock) -> None:
        mock_docker_client.api.build.return_value = [{"aux": {"ID": "sha256:abc123"}}]
        mock_docker_client.images.get.return_value = MagicMock()

        build("/tmp/test", "My Model!")
        call_kwargs = mock_docker_client.api.build.call_args
        assert call_kwargs.kwargs["tag"] == "my-model"


class TestPull:
    def test_pull(self, mock_docker_client: MagicMock) -> None:
        mock_image = MagicMock()
        mock_docker_client.images.pull.return_value = mock_image

        result = pull("test-image:latest")
        assert result is mock_image
        mock_docker_client.images.pull.assert_called_once_with("test-image:latest")


class TestRunDetached:
    def test_network_disabled_by_default(self, mock_docker_client: MagicMock) -> None:
        mock_docker_client.containers.run.return_value = MagicMock()
        run_detached("img", ["cmd"], {})
        call_kwargs = mock_docker_client.containers.run.call_args.kwargs
        assert call_kwargs["network_mode"] == "none"

    def test_network_enabled(self, mock_docker_client: MagicMock) -> None:
        mock_docker_client.containers.run.return_value = MagicMock()
        run_detached("img", ["cmd"], {}, allow_network=True)
        call_kwargs = mock_docker_client.containers.run.call_args.kwargs
        assert call_kwargs["network_mode"] == "bridge"

    def test_security_opts(self, mock_docker_client: MagicMock) -> None:
        mock_docker_client.containers.run.return_value = MagicMock()
        run_detached("img", ["cmd"], {})
        call_kwargs = mock_docker_client.containers.run.call_args.kwargs
        assert "no-new-privileges" in call_kwargs["security_opt"]
        assert call_kwargs["cap_drop"] == ["ALL"]

    def test_volumes_readonly_by_default(self, mock_docker_client: MagicMock) -> None:
        mock_docker_client.containers.run.return_value = MagicMock()
        run_detached("img", ["cmd"], {"/host/path": "/container/path"})
        call_kwargs = mock_docker_client.containers.run.call_args.kwargs
        assert call_kwargs["volumes"]["/host/path"]["mode"] == "ro"

    def test_artifacts_volume_writable(self, mock_docker_client: MagicMock) -> None:
        mock_docker_client.containers.run.return_value = MagicMock()
        run_detached("img", ["cmd"], {"/host/path": "/artifacts"})
        call_kwargs = mock_docker_client.containers.run.call_args.kwargs
        assert call_kwargs["volumes"]["/host/path"]["mode"] == "rw"


class TestRunPrivilegedDetached:
    def test_privileged_flag(self, mock_docker_client: MagicMock) -> None:
        mock_docker_client.containers.run.return_value = MagicMock()
        run_privileged_detached("img", ["cmd"], {})
        call_kwargs = mock_docker_client.containers.run.call_args.kwargs
        assert call_kwargs["privileged"] is True
        assert call_kwargs["pid_mode"] == "host"
