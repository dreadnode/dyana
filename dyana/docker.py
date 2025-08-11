import os
import pathlib
import re
import shutil

import docker
from docker.models.images import Image
from rich import print as rich_print

DOCKER_SOCKET_PATH = "/var/run/docker.sock"
DOCKER_SOCKET_EXISTS = os.path.exists(DOCKER_SOCKET_PATH)
COLIMA_SOCKET_PATH = os.path.expanduser("~/.colima/docker.sock")
COLIMA_SOCKET_EXISTS = os.path.exists(COLIMA_SOCKET_PATH)


try:
    client = docker.from_env()
except docker.errors.DockerException:
    # check if Colima exists
    if COLIMA_SOCKET_EXISTS:
        # https://github.com/abiosoft/colima/issues/468
        try:
            client = docker.DockerClient(base_url="unix://" + COLIMA_SOCKET_PATH)
            rich_print(f":whale: [bold]docker[/]: found {COLIMA_SOCKET_PATH}, using colima runtime")
        except docker.errors.DockerException:
            client = None
    else:
        client = None


def _raise_docker_exception() -> None:
    msg: str = ""
    docker_in_path: bool = shutil.which("docker") is not None
    if not DOCKER_SOCKET_EXISTS and not docker_in_path:
        msg = "docker is not installed"
    else:
        # the docker binary is in $PATH and/or the socket exists
        msg = "docker is not running"

    raise Exception(msg)


def _ensure_docker_client() -> None:
    if client is None:
        _raise_docker_exception()


def sanitized_agent_name(name: str) -> str:
    """
    Sanitizes an agent name to be used as a Docker repository name.
    """

    # convert to lowercase
    name = name.lower()
    # replace non-alphanumeric characters with hyphens
    name = re.sub(r"[^\w\s-]", "", name)
    # replace one or more whitespace characters with a single hyphen
    name = re.sub(r"[-\s]+", "-", name)
    # remove leading or trailing hyphens
    name = name.strip("-")

    return name


def build(
    directory: str | pathlib.Path,
    name: str,
    platform: str | None = None,
    build_args: dict[str, str] | None = None,
    force_rebuild: bool = False,
    verbose: bool = False,
) -> Image:
    _ensure_docker_client()

    norm_name = sanitized_agent_name(name)
    if norm_name != name:
        rich_print(f"[yellow]Warning:[/] sanitized agent name from '{name}' to '{norm_name}'")
        name = norm_name

    id: str | None = None
    for item in client.api.build(
        path=str(directory),
        tag=name,
        decode=True,
        nocache=force_rebuild,
        pull=force_rebuild,
        buildargs=build_args,
        platform=platform,
        # remove intermediate containers
        rm=True,
    ):
        if "error" in item:
            rich_print()
            raise Exception(item["error"])
        elif "stream" in item:
            if verbose:
                rich_print("[dim]" + item["stream"].strip() + "[/]")
        elif "aux" in item:
            id = item["aux"].get("ID")

    if id is None:
        raise Exception("Failed to build image")

    return client.images.get(id)


def pull(image: str) -> Image:
    if client is None:
        raise Exception("Docker not available")

    return client.images.pull(image)


def run_detached(
    image: str,
    command: list[str],
    volumes: dict[str, str],
    environment: dict[str, str] | None = None,
    allow_network: bool = False,
    allow_gpus: bool = True,
    allow_volume_write: bool = False,
    mem_limit: str = "100m",
) -> docker.models.containers.Container:
    _ensure_docker_client()

    # by default network is disabled
    network_mode = "bridge" if allow_network else "none"

    # by default volumes are read-only
    mounts = {
        host: {"bind": guest, "mode": "rw" if guest == "/artifacts" or allow_volume_write else "ro"}
        for host, guest in volumes.items()
    }

    # this allows us to log dns requests even if the container is in network mode "none"
    dns = ["127.0.0.1"] if not allow_network else None

    # enable GPUs
    device_requests = [docker.types.DeviceRequest(device_ids=["all"], capabilities=[["gpu"]])] if allow_gpus else None

    # TODO: implement new command line arguments for limits such as : cpu_quota=400000,
    return client.containers.run(
        image,
        command=command,
        volumes=mounts,
        environment=environment,
        network_mode=network_mode,
        dns=dns,
        # automatically remove the container after it exits
        remove=True,
        # allocate a pseudo-TTY
        tty=False,
        # keep STDIN open
        stdin_open=True,
        stdout=True,
        stderr=True,
        # detach
        detach=True,
        device_requests=device_requests,
        security_opt=[
            "no-new-privileges",
            "seccomp=unconfined",
        ],
        cap_drop=["ALL"],
        tmpfs={"/tmp": f"size={mem_limit},noexec"},
        # Set overall memory limit for the container
        mem_limit=mem_limit,
        # https://www.ibm.com/docs/en/wmlce/1.6.2?topic=frameworks-getting-started-pytorch#d15286e680
        pids_limit=16384,
        ulimits=[
            docker.types.Ulimit(name="nofile", soft=1024, hard=1024),
            docker.types.Ulimit(name="nproc", soft=100, hard=100),
        ],
        ipc_mode="none",
    )


def run_privileged_detached(
    image: str,
    command: list[str],
    volumes: dict[str, str],
    entrypoint: str | None = None,
    environment: dict[str, str] | None = None,
) -> docker.models.containers.Container:
    _ensure_docker_client()

    return client.containers.run(
        image,
        command=command,
        volumes={host: {"bind": guest, "mode": "rw"} for host, guest in volumes.items()},
        network_mode="none",
        pid_mode="host",
        cgroupns="host",
        privileged=True,
        entrypoint=entrypoint,
        environment=environment,
        # automatically remove the container after it exits
        remove=True,
        # allocate a pseudo-TTY
        tty=True,
        # keep STDIN open
        stdin_open=True,
        stdout=True,
        stderr=True,
        detach=True,
    )
