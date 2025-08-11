import json
import pathlib
import platform
import threading
import time
import typing as t
from datetime import datetime

import docker as docker_pkg
from pydantic import BaseModel
from rich import print as rich_print

import dyana
import dyana.docker as docker
from dyana.loaders.loader import Loader, Run


class Trace(BaseModel):
    started_at: datetime
    ended_at: datetime
    platform: str
    tracee_version: str | None = None
    tracee_kernel_release: str | None = None
    dyana_version: str | None = None
    run: Run
    events: list[t.Any] = []


class Tracer:
    DOCKER_IMAGE = "aquasec/tracee:latest"

    SECURITY_EVENTS: list[str] = [
        # cd tracee/signatures/go && grep -r "EventName:" --exclude="*_test.go" * | cut -d'"' -f2 | sort -u
        "anti_debugging",
        "aslr_inspection",
        "cgroup_notify_on_release",
        "cgroup_release_agent",
        "core_pattern_modification",
        "default_loader_mod",
        "disk_mount",
        "docker_abuse",
        "dropped_executable",
        "dynamic_code_loading",
        "fileless_execution",
        "hidden_file_created",
        "illegitimate_shell",
        "k8s_api_connection",
        "k8s_cert_theft",
        # Error: invalid event to trace: k8s_service_account_token
        # "k8s_service_account_token",
        "kernel_module_loading",
        "ld_preload",
        "proc_fops_hooking",
        "proc_kcore_read",
        "proc_mem_access",
        "proc_mem_code_injection",
        "process_vm_write_inject",
        "ptrace_code_injection",
        "rcd_modification",
        "sched_debug_recon",
        "scheduled_task_mod",
        "stdio_over_socket",
        "sudoers_modification",
        "syscall_hooking",
        "system_request_key_mod",
        # non signature related but still security related
        "hidden_kernel_module",
        "bpf_attach",
        "ftrace_hook",
        "hooked_syscall",
    ]

    DEFAULT_EVENTS: list[str] = [
        "security_file_open",
        "sched_process_exec",
        "security_socket_*",
        "net_packet_dns",
    ] + SECURITY_EVENTS

    def __init__(self, loader: Loader, policy: pathlib.Path | None = None):
        rich_print(":eye_in_speech_bubble:  [bold]tracer[/]: initializing ...")

        docker.pull(Tracer.DOCKER_IMAGE)

        self.loader = loader
        self.errors: list[str] = []
        self.trace: list[t.Any] = []
        self.args = [
            "--output",
            "json",
            # enable debug logging to know when tracee is ready
            "--log",
            "debug",
        ]

        # check for a custom policy file or folder
        self.policy = policy.resolve().absolute() if policy else None
        self.policy_volume: str | None = None
        if policy:
            rich_print(f":eye_in_speech_bubble:  [bold]tracer[/]: using custom policy [yellow]{policy}[/]")
            self.policy_volume = f"/{policy.name}"
            self.args.append("--policy")
            self.args.append(self.policy_volume)
        else:
            # NOTE: policy and --scope / --events are mutually exclusive

            # only trace events that are part of a new container
            self.args.append("--scope")
            self.args.append("container=new")
            for event in Tracer.DEFAULT_EVENTS:
                self.args.append("--events")
                self.args.append(event)

        self.reader_error: str | None = None
        self.reader_thread: threading.Thread | None = None
        self.container: docker_pkg.models.containers.Container | None = None
        self.tracee_kernel_release: str | None = None
        self.tracee_version: str | None = None
        self.ready = False

    def _reader_thread(self) -> None:
        if not self.container:
            raise Exception("Container not created")

        # attach to the container's logs with stream=True to get a generator
        logs = self.container.logs(stream=True, follow=True)
        line = ""

        # loop while the container is running
        while self.container.status in ["created", "running"]:
            # https://github.com/docker/docker-py/issues/2913
            for char in logs:
                try:
                    if not isinstance(char, str):
                        char = char.decode("utf-8")
                except UnicodeDecodeError:
                    char = char.decode("utf-8", errors="replace")

                line += char
                if char == "\n":
                    self._on_tracer_event(line)
                    line = ""
            try:
                # refresh container status
                self.container.reload()
            except Exception:
                # container is deleted
                break

    def _on_tracer_event(self, line: str) -> None:
        line = line.strip()
        if not line:
            return

        if not line.startswith("{"):
            if line.startswith("Error:"):
                self.reader_error = line.replace("Error:", "").strip()
            else:
                rich_print(f"[dim]{line}[/]")
            return

        message = json.loads(line)

        if "L" in message:
            if message["L"] == "DEBUG":
                # these are debug messages, do not collect them
                if "is ready callback" in line:
                    self.ready = True
                elif "KERNEL_RELEASE" in message:
                    self.tracee_kernel_release = message["KERNEL_RELEASE"]
            else:
                # other messages
                # print(f":eye_in_speech_bubble:  [bold]tracer[/]: {message['M'].strip()}")
                pass

        elif "level" in message:
            # other messages
            if message["level"] in ["fatal", "error"]:
                err = message["error"].strip()
                rich_print(f":exclamation: [bold red]tracer error:[/]: {err}")
                self.errors.append(err)
            else:
                msg = message["msg"].strip()
                rich_print(f":eye_in_speech_bubble:  [bold]tracer[/]: {msg}")
        else:
            # actual events
            self.trace.append(message)

    def _start(self) -> None:
        self.errors.clear()
        self.trace.clear()

        # TODO: investigate these errors:
        # 👁️‍🗨️  tracer: KConfig: could not check enabled kconfig features
        # 👁️‍🗨️  tracer: KConfig: assuming kconfig values, might have unexpected behavior

        volumes = {"/etc/os-release": "/etc/os-release-host", "/var/run/docker.sock": "/var/run/docker.sock"}
        if self.policy and self.policy_volume:
            volumes[str(self.policy)] = self.policy_volume

        # start tracee in a detached container
        self.container = docker.run_privileged_detached(
            Tracer.DOCKER_IMAGE,
            self.args,
            volumes=volumes,
            # override the entrypoint so we can pass our own arguments
            entrypoint="/tracee/tracee",
            environment={"LIBBPFGO_OSRELEASE_FILE": "/etc/os-release-host"},
        )
        self.tracee_version = self.container.image.attrs["RepoDigests"][0]

        # start reading tracee output in a separate thread
        self.reader_error = None
        self.reader_thread = threading.Thread(target=self._reader_thread)
        self.reader_thread.daemon = True
        self.reader_thread.start()

        # tracee takes a few seconds to warm up and trace events
        while not self.ready:
            time.sleep(1)
            if self.reader_error:
                raise Exception(self.reader_error)

    def _stop(self) -> None:
        if self.container:
            rich_print(":eye_in_speech_bubble:  [bold]tracer[/]: stopping ...")
            self.container.stop()

    def run_trace(
        self, allow_network: bool = False, allow_gpus: bool = True, allow_volume_write: bool = False
    ) -> Trace:
        self._start()

        rich_print(":eye_in_speech_bubble:  [bold]tracer[/]: started ...")

        started_at = datetime.now()
        run = self.loader.run(allow_network, allow_gpus, allow_volume_write)
        ended_at = datetime.now()

        self._stop()

        if self.errors:
            if not run.errors:
                run.errors = {}
            run.errors["tracer"] = ", ".join(self.errors)

        return Trace(
            platform=platform.platform(),
            started_at=started_at,
            ended_at=ended_at,
            dyana_version=dyana.__version__,
            tracee_version=self.tracee_version,
            tracee_kernel_release=self.tracee_kernel_release,
            # filter out any events from containers different than the one we created
            events=[
                event
                for event in self.trace
                if (event["containerId"] or "").lower() == (self.loader.container_id or "").lower()
            ],
            run=run,
        )
