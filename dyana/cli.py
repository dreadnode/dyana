import pathlib
import platform as platform_pkg

# NOTE: json is too slow
import cysimdjson
import typer
from rich import box
from rich import print as rich_print
from rich.table import Table

import dyana.loaders as loaders_pkg
from dyana.loaders.loader import Loader
from dyana.tracer.tracee import Tracer
from dyana.view import (
    view_disk_events,
    view_disk_usage,
    view_gpus,
    view_header,
    view_imports,
    view_loader_help,
    view_network_events,
    view_network_usage,
    view_process_executions,
    view_ram,
    view_security_events,
)
from dyana.view_legacy import (
    view_legacy_disk_usage,
    view_legacy_extra,
    view_legacy_gpus,
    view_legacy_network_usage,
    view_legacy_ram,
)

cli = typer.Typer(
    no_args_is_help=True,
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Blackbox profiler.",
)


@cli.command(
    help="Show the available loaders.",
)
def loaders(
    build: bool = typer.Option(help="Build the loaders containers if needed.", default=False),
) -> None:
    loaders_path = loaders_pkg.__path__[0]
    loaders: list[Loader] = []
    for entry in pathlib.Path(loaders_path).iterdir():
        if entry.is_dir() and not entry.name.startswith("__") and entry.name != "base":
            loaders.append(Loader(name=entry.name, build=build, timeout=10))

    table = Table(box=box.ROUNDED)
    table.add_column("Name", style="cyan")
    table.add_column("Description")

    for loader in sorted(loaders, key=lambda x: x.name):
        table.add_row(
            loader.name,
            loader.settings.description if loader.settings else "",
        )

    rich_print(table)


@cli.command(
    help="Show the help menu for a specific loader.",
)
def help(
    loader: str = typer.Argument(help="Loader to get help for."),
    markdown: bool = typer.Option(help="Generate markdown output.", default=False),
) -> None:
    try:
        view_loader_help(Loader(name=loader, build=False), markdown)

    except Exception as e:
        rich_print(f":cross_mark: [red]{e}[/]")
        exit(1)


@cli.command(
    help="Profiles the target file via the selected loader.",
    # we need to allow extra arguments because the loader might have its own arguments
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
)
def trace(
    ctx: typer.Context,
    loader: str = typer.Option(help="Loader to use.", default="automodel"),
    platform: str | None = typer.Option(help="Platform to use.", default=None),
    output: pathlib.Path = typer.Option(help="Path to the output file.", default="trace.json"),
    save: list[str] = typer.Option(help="List of file artifacts to save.", default=[]),
    save_to: pathlib.Path = typer.Option(help="Path to the directory to save the artifacts to.", default="./artifacts"),
    policy: pathlib.Path | None = typer.Option(
        help="Path to a policy or directory with custom tracee policies.", default=None
    ),
    timeout: int = typer.Option(help="Execution timeout in seconds.", default=60),
    no_gpu: bool = typer.Option(help="Do not use GPUs.", default=False),
    allow_network: bool = typer.Option(help="Allow network access to the model container.", default=False),
    allow_volume_write: bool = typer.Option(help="Mount volumes as read-write.", default=False),
    mem_limit: str = typer.Option(help="Memory limit for /tmp directory (e.g. '100m', '1g').", default="100m"),
    verbose: bool = typer.Option(help="Verbose mode.", default=False),
) -> None:
    try:
        # disable GPU on non-Linux systems
        if not no_gpu and platform_pkg.system() != "Linux":
            no_gpu = True

        # check if policy is either a file or a directory
        if policy and not policy.exists():
            raise typer.BadParameter(f"policy file or directory not found: {policy}")

        the_loader = Loader(
            name=loader,
            timeout=timeout,
            platform=platform,
            args=ctx.args,
            verbose=verbose,
            save=save,
            save_to=save_to,
            mem_limit=mem_limit,
        )
        the_tracer = Tracer(the_loader, policy=policy)

        trace = the_tracer.run_trace(allow_network, not no_gpu, allow_volume_write)

        rich_print(f":card_file_box:  saving {len(trace.events)} events to {output}\n")

        with open(output, "w") as f:
            f.write(trace.model_dump_json())

        summary(output)
    except Exception as e:
        serr = str(e)
        if "could not select device driver" in serr and "capabilities: [[gpu]]" in serr:
            rich_print(":cross_mark: [bold][red]error:[/] [red]GPUs are not available on this system, run with --no-gpu.[/]")
        else:
            rich_print(f":cross_mark: [bold][red]error:[/] [red]{e}[/]")

        if verbose:
            raise
        else:
            exit(1)


@cli.command(help="Show a summary of the trace.")
def summary(trace_path: pathlib.Path = typer.Option(help="Path to the trace file.", default="trace.json")) -> None:
    with open(trace_path) as f:
        raw = f.read()
        # the standard json parser is too slow for this
        parser = cysimdjson.JSONParser()
        trace = parser.loads(raw)

    is_legacy: bool = "stages" not in trace["run"]

    view_header(trace, is_legacy)

    if is_legacy:
        view_legacy_ram(trace["run"])
        view_legacy_gpus(trace["run"])
        view_legacy_disk_usage(trace["run"])
    else:
        view_ram(trace["run"]["stages"])
        view_gpus(trace["run"]["stages"])
        view_disk_usage(trace["run"]["stages"])

    view_process_executions(trace)

    if is_legacy:
        view_legacy_network_usage(trace["run"])
    else:
        view_network_usage(trace["run"]["stages"])

    view_network_events(trace)
    view_disk_events(trace)
    view_security_events(trace)

    if is_legacy:
        view_legacy_extra(trace["run"])
    else:
        view_imports(trace["run"]["stages"])
