import pytest

from dyana.loaders.settings import LoaderArgument, LoaderSettings, ParsedArgument


def test_parse_build_args() -> None:
    settings = LoaderSettings(description="test loader", build_args={"model": "MODEL_ARG", "version": "VERSION_ARG"})

    args = ["--model", "gpt2", "--version", "1.0"]
    build_args = settings.parse_build_args(args)

    assert build_args == {"MODEL_ARG": "gpt2", "VERSION_ARG": "1.0"}


def test_parse_build_args_with_equals() -> None:
    settings = LoaderSettings(description="test loader", build_args={"model": "MODEL_ARG"})

    args = ["--model=gpt2"]
    build_args = settings.parse_build_args(args)

    assert build_args == {"MODEL_ARG": "gpt2"}


def test_parse_args() -> None:
    settings = LoaderSettings(
        description="test loader",
        args=[
            LoaderArgument(name="model", description="Model to use"),
            LoaderArgument(name="data", description="Data path", volume=True),
        ],
    )

    args = ["--model", "gpt2", "--data", "/path/to/data"]
    parsed_args = settings.parse_args(args) or []

    assert len(parsed_args) == 2
    assert parsed_args[0] == ParsedArgument(name="model", value="gpt2", volume=False)
    assert parsed_args[1] == ParsedArgument(name="data", value="/path/to/data", volume=True)


def test_parse_args_with_default() -> None:
    settings = LoaderSettings(
        description="test loader", args=[LoaderArgument(name="model", description="Model to use", default="gpt2")]
    )

    args: list[str] = []
    parsed_args = settings.parse_args(args) or []

    assert len(parsed_args) == 1
    assert parsed_args[0] == ParsedArgument(name="model", value="gpt2", volume=False)


def test_parse_args_missing_required() -> None:
    settings = LoaderSettings(
        description="test loader", args=[LoaderArgument(name="model", description="Model to use", required=True)]
    )

    args: list[str] = []
    with pytest.raises(ValueError, match="Argument --model is required"):
        settings.parse_args(args)


def test_parse_build_args_no_settings() -> None:
    settings = LoaderSettings(description="test loader")
    result = settings.parse_build_args(["--model", "gpt2"])
    assert result is None


def test_parse_build_args_partial_match() -> None:
    settings = LoaderSettings(description="test loader", build_args={"model": "MODEL_ARG", "version": "VERSION_ARG"})
    args = ["--model", "gpt2"]
    result = settings.parse_build_args(args)
    assert result == {"MODEL_ARG": "gpt2"}


def test_parse_build_args_no_match() -> None:
    settings = LoaderSettings(description="test loader", build_args={"model": "MODEL_ARG"})
    args = ["--other", "value"]
    result = settings.parse_build_args(args)
    assert result == {}


def test_parse_args_with_volume() -> None:
    settings = LoaderSettings(
        description="test loader",
        args=[LoaderArgument(name="data", description="Data path", volume=True, required=False)],
    )
    args = ["--data", "/path/to/data"]
    parsed = settings.parse_args(args) or []
    assert len(parsed) == 1
    assert parsed[0].volume is True


def test_parse_args_with_artifact() -> None:
    settings = LoaderSettings(
        description="test loader",
        args=[LoaderArgument(name="output", description="Output path", artifact=True, required=False)],
    )
    args = ["--output", "/path/to/output"]
    parsed = settings.parse_args(args) or []
    assert len(parsed) == 1
    assert parsed[0].artifact is True


def test_parse_args_mixed_required_optional() -> None:
    settings = LoaderSettings(
        description="test loader",
        args=[
            LoaderArgument(name="model", description="Required model", required=True),
            LoaderArgument(name="batch", description="Optional batch", required=False, default="32"),
        ],
    )
    args = ["--model", "gpt2"]
    parsed = settings.parse_args(args) or []
    assert len(parsed) == 2
    assert parsed[0].value == "gpt2"
    assert parsed[1].value == "32"


def test_parse_arg_name_from_flag_only() -> None:
    settings = LoaderSettings(description="test loader")
    result = settings._parse_arg_name_from("verbose", ["--verbose"])
    assert result == "--verbose"


def test_parse_arg_name_from_not_found() -> None:
    settings = LoaderSettings(description="test loader")
    result = settings._parse_arg_name_from("missing", ["--other", "value"])
    assert result is None


def test_loader_settings_model_validation() -> None:
    settings = LoaderSettings(
        description="Test",
        network=True,
        gpu=True,
        build_args={"key": "value"},
    )
    assert settings.network is True
    assert settings.gpu is True


def test_loader_argument_defaults() -> None:
    arg = LoaderArgument(name="test", description="Test arg")
    assert arg.required is True
    assert arg.volume is False
    assert arg.artifact is False
    assert arg.default is None


def test_example_model() -> None:
    from dyana.loaders.settings import Example

    example = Example(description="Run model", command="dyana trace --loader automodel -- --model gpt2")
    assert example.description == "Run model"


def test_volume_model() -> None:
    from dyana.loaders.settings import Volume

    vol = Volume(host="~/.cache", guest="/cache")
    assert vol.host == "~/.cache"
    assert vol.guest == "/cache"
