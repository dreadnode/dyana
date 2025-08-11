import os
import pathlib
import shutil
import threading
import time
import typing as t
from datetime import datetime

import docker as docker_pkg
from pydantic import BaseModel
from pydantic_yaml import parse_yaml_raw_as
from rich import print as rich_print

import dyana.docker as docker
import dyana.loaders as loaders
from dyana.loaders.base.dyana import Stage
from dyana.loaders.settings import LoaderSettings, ParsedArgument


class Run(BaseModel):
    loader_name: str | None = None
    build_platform: str | None = None
    build_args: dict[str, str] | None = None
    arguments: list[str] | None = None
    volumes: dict[str, str] | None = None
    errors: dict[str, str] | None = None
    warnings: dict[str, str] | None = None
    # process output and exit code
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    # profiling stages
    stages: list[Stage] | None = None
    # extra data
    extra: dict[str, t.Any] | None = None


class Loader:
    def __init__(
        self,
        name: str,
        timeout: int = 600,
        build: bool = True,
        platform: str | None = None,
        args: list[str] | None = None,
        save: list[str] | None = None,
        save_to: pathlib.Path = pathlib.Path("./artifacts"),
        verbose: bool = False,
        mem_limit: str = "100m",
    ):
        # make sure that name does not include a path traversal
        if "/" in name or ".." in name:
            raise ValueError("Loader name cannot include a path traversal")

        self.image_name = name
        self.timeout = timeout

        self.base_paths_to_copy = [
            os.path.join(loaders.__path__[0], "base/dyana.py"),
            os.path.join(loaders.__path__[0], "base/dyana-requirements.txt"),
            os.path.join(loaders.__path__[0], "base/dyana-requirements-gpu.txt"),
        ]

        # check in the loaders package first
        self.path = os.path.join(loaders.__path__[0], name)
        if not os.path.exists(self.path):
            # if an external loader has been specified
            if os.path.exists(name):
                self.path = name

        self.settings_path = os.path.join(self.path, "settings.yml")
        self.dockerfile = os.path.join(self.path, "Dockerfile")

        self.reader_thread: threading.Thread | None = None
        self.container: docker_pkg.models.containers.Container | None = None
        self.container_id: str | None = None
        self.output: str = ""
        self.platform = platform
        self.settings: LoaderSettings | None = None
        self.build_args: dict[str, str] | None = None
        self.args: list[ParsedArgument] | None = None
        self.save: list[str] | None = save
        self.save_to: pathlib.Path = save_to.resolve().absolute()
        self.need_artifacts: bool = False
        self.mem_limit = mem_limit

        if os.path.exists(self.settings_path):
            with open(self.settings_path) as f:
                self.settings = parse_yaml_raw_as(LoaderSettings, f.read())
                if args:
                    self.build_args = self.settings.parse_build_args(args)
                    self.args = self.settings.parse_args(args)
                    self.need_artifacts = any(arg.artifact for arg in self.args) if self.args else False
        else:
            self.settings = None

        if not os.path.exists(self.path):
            raise ValueError(f"Loader {name} does not exist, use [bold]dyana loaders[/] to see the available loaders")
        elif not os.path.isfile(self.dockerfile):
            raise ValueError(f"Loader {name} does not contain a Dockerfile")

        self.name = name
        self.image_name = f"dyana-{name}-loader"

        if build:
            if self.settings and self.settings.args:
                for arg in self.settings.args:
                    if arg.required and not self.args:
                        raise ValueError(f"Argument --{arg.name} is required")

            rich_print(f":whale: [bold]loader[/]: initializing loader [bold]{name}[/]")
            # copy the base dyana.py to the loader directory
            # TODO: ideally the file name should be randomized in order to avoid low-hanging fruits in terms
            # of sandbox detection techniques
            for path in self.base_paths_to_copy:
                shutil.copy(path, os.path.join(self.path, os.path.basename(path)))

            self.image = docker.build(
                self.path, self.image_name, platform=self.platform, build_args=self.build_args, verbose=verbose
            )
            if self.platform:
                rich_print(
                    f":whale: [bold]loader[/]: using image [green]{self.image.tags[0]}[/] [dim]({self.image.id})[/] ({self.platform})"
                )
            # else:
            # print(f":whale: [bold]loader[/]: using image [green]{self.image.tags[0]}[/] [dim]({self.image.id})[/]")

    def _reader_thread(self) -> None:
        if not self.container:
            raise Exception("Container not created")

        # attach to the container's logs with stream=True to get a generator
        logs = self.container.logs(stream=True, follow=True, stdout=True, stderr=True)

        # loop while the container is running
        while self.container.status in ["created", "running"]:
            # https://github.com/docker/docker-py/issues/2913
            for char in logs:
                try:
                    char = char.decode("utf-8")
                except UnicodeDecodeError:
                    char = char.decode("utf-8", errors="replace")

                self.output += char

            try:
                # refresh container status
                self.container.reload()
            except Exception:
                # container is deleted
                break

    def _create_errored_run(self, error_key: str, error_message: str) -> Run:
        run = Run()
        run.loader_name = self.name
        run.build_platform = self.platform
        run.build_args = self.build_args
        run.arguments = [arg.value for arg in self.args] if self.args else None
        run.errors = {error_key: error_message}
        return run

    def run(self, allow_network: bool = False, allow_gpus: bool = True, allow_volume_write: bool = False) -> Run:
        volumes = {}
        arguments = []

        if self.args:
            for arg in self.args:
                the_arg = f"--{arg.name}"
                arguments.append(the_arg)

                # check if the argument is a volume
                if arg.volume:
                    volume_path = pathlib.Path(arg.value).resolve().absolute()
                    # NOTE: we need to preserve the folder name since AutoModel will use it to
                    # determine the model type, make it lowercase for matching
                    volume_name = volume_path.name.lower()
                    volume = f"/{volume_name}"
                    volumes[str(volume_path)] = volume

                    arguments.append(volume)
                elif arg.value != the_arg:
                    arguments.append(arg.value)

        if self.settings and self.settings.network:
            allow_network = True
            rich_print(":popcorn: [bold]loader[/]: [yellow]required bridged network access[/]")

        elif allow_network:
            rich_print(":popcorn: [bold]loader[/]: [yellow]warning: allowing bridged network access to the container[/]")

        if allow_volume_write:
            rich_print(":popcorn: [bold]loader[/]: [yellow]warning: allowing volume write to the container[/]")

        if arguments:
            rich_print(f":popcorn: [bold]loader[/]: executing with arguments [dim]{arguments}[/] ...")
        else:
            rich_print(":popcorn: [bold]loader[/]: executing ...")

        try:
            self.output = ""
            environment = {}
            if self.save or self.need_artifacts:
                if self.save:
                    environment["DYANA_SAVE"] = ",".join(self.save)

                volumes[str(self.save_to)] = "/artifacts"
                if not os.path.exists(self.save_to):
                    os.makedirs(self.save_to)

                rich_print(f":popcorn: [bold]loader[/]: saving artifacts to [dim]{self.save_to}[/]")

            if self.settings and self.settings.volumes:
                for vol in self.settings.volumes:
                    host = os.path.expanduser(vol.host)
                    if os.path.exists(host):
                        volumes[host] = vol.guest
                        rich_print(f":popcorn: [bold]loader[/]: mounting volume [dim]{host}[/] to [dim]{vol.guest}[/]")

            self.container = docker.run_detached(
                self.image,
                arguments,
                volumes,
                environment=environment,
                allow_network=allow_network,
                allow_gpus=allow_gpus and (self.settings.gpu if self.settings else True),
                allow_volume_write=allow_volume_write,
                mem_limit=self.mem_limit,
            )
            self.container_id = self.container.id
            self.reader_thread = threading.Thread(target=self._reader_thread)
            self.reader_thread.start()

            started_at = datetime.now()
            while self.container.status in ["created", "running", "removing"]:
                time.sleep(1.0)
                try:
                    # refresh container status
                    self.container.reload()
                except Exception:
                    # container is deleted
                    break

                if (datetime.now() - started_at).total_seconds() > self.timeout:
                    self.container.kill()
                    rich_print(":popcorn: [bold]loader[/]: [red]timeout reached, killing container[/]")
                    return self._create_errored_run("timeout", "timeout reached, killing container")

            # loaders could generate all sorts of output before flushing the JSON profile
            # so we use a prefix to identify and separate them.
            extra_output: str | None = None
            idx = self.output.find("<DYANA_PROFILE>")
            extra_output = self.output[:idx]
            self.output = self.output[idx + len("<DYANA_PROFILE>") :]

            try:
                run = Run.model_validate_json(self.output)
                run.loader_name = self.name
                run.build_platform = self.platform
                run.build_args = self.build_args
                run.arguments = arguments
                run.volumes = volumes

                if extra_output:
                    if run.stdout:
                        run.stdout += extra_output
                    else:
                        run.stdout = extra_output
                return run
            except Exception as e:
                rich_print(f"Validation error: {e}")
                rich_print(f"Invalid JSON: [bold red]{self.output}[/]")
                raise e

        except docker_pkg.errors.ContainerError as ce:
            rich_print(f"\nContainer failed with exit code {ce.exit_status}")
            rich_print("\nContainer output:")
            rich_print(ce.stderr.decode("utf-8"))
            return self._create_errored_run("container_execution_error", ce.stderr.decode("utf-8"))
