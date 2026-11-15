from pydantic import BaseModel


class LoaderArgument(BaseModel):
    name: str
    description: str
    default: str | None = None
    required: bool = True
    volume: bool = False
    artifact: bool = False


class ParsedArgument(BaseModel):
    name: str
    value: str
    volume: bool = False
    artifact: bool = False


class Example(BaseModel):
    description: str
    command: str


class Volume(BaseModel):
    host: str
    guest: str


class LoaderSettings(BaseModel):
    description: str
    build_args: dict[str, str] | None = None
    args: list[LoaderArgument] | None = None
    network: bool | None = False
    gpu: bool = False
    volumes: list[Volume] | None = None
    examples: list[Example] | None = None

    def _parse_arg_name_from(self, name: str, args: list[str]) -> str | None:
        found_pre = False
        arg_name = f"--{name}"
        for arg in args:
            if arg == arg_name:
                found_pre = True
                continue

            elif found_pre:
                return arg

            elif arg.startswith(f"{arg_name}="):
                return arg.split("=", 1)[1]

        return arg_name if found_pre else None

    def parse_build_args(self, args: list[str]) -> dict[str, str] | None:
        build_args: dict[str, str] | None = None
        if self.build_args:
            build_args = {}
            for arg_name, build_arg_name in self.build_args.items():
                value = self._parse_arg_name_from(arg_name, args)
                if value is not None:
                    build_args[build_arg_name] = value

        return build_args

    def parse_args(self, args: list[str]) -> list[ParsedArgument] | None:
        parsed_args: list[ParsedArgument] | None = None
        if self.args:
            parsed_args = []
            for arg in self.args:
                value = self._parse_arg_name_from(arg.name, args)
                if value is not None:
                    parsed_args.append(
                        ParsedArgument(name=arg.name, value=value, volume=arg.volume, artifact=arg.artifact)
                    )
                elif arg.default:
                    parsed_args.append(
                        ParsedArgument(name=arg.name, value=arg.default, volume=arg.volume, artifact=arg.artifact)
                    )
                elif arg.required:
                    raise ValueError(f"Argument --{arg.name} is required")

        return parsed_args
