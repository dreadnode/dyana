import typing as t

from rich import print as rich_print


# https://stackoverflow.com/questions/1094841/get-a-human-readable-version-of-a-file-size
def sizeof_fmt(num: float, suffix: str = "B") -> str:
    for unit in ("", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "Zi"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}{suffix}"
        num /= 1024.0
    return f"{num:.1f}Yi{suffix}"


def delta_fmt(before: int, after: int) -> str:
    delta = after - before
    fmt = sizeof_fmt(after)
    if delta > 0:
        delta_fmt = sizeof_fmt(delta)
        fmt += f" :red_triangle_pointed_up: [red]{delta_fmt}[/]"
    return fmt


def view_legacy_ram(run: dict[str, t.Any]) -> None:
    ram = run["ram"]
    if ram:
        rich_print("[bold yellow]RAM Usage:[/]")
        ram_stages = list(ram.keys())
        prev_stage = None
        for stage in ram_stages:
            if prev_stage is None:
                rich_print(f"  * {stage} : {sizeof_fmt(ram[stage])}")
            else:
                rich_print(f"  * {stage} : {delta_fmt(ram[prev_stage], ram[stage])}")
            prev_stage = stage

        rich_print()


def view_legacy_gpus(run: dict[str, t.Any]) -> None:
    if run["gpu"]:
        gpu_stages = list(run["gpu"].keys())
        first_gpu_stage = gpu_stages[0]
        num_gpus = len(run["gpu"][first_gpu_stage])
        if num_gpus:
            # check for any change in memory usage for GPUs
            changes = []
            for i in range(num_gpus):
                prev = None
                change = False
                for stage in gpu_stages:
                    if prev is not None:
                        if run["gpu"][stage][i]["free_memory"] != prev:
                            change = True
                            break
                    prev = run["gpu"][stage][i]["free_memory"]
                changes.append(change)

            if any(changes):
                rich_print("[bold green]GPU Usage:[/]")
                for i in range(num_gpus):
                    if not changes[i]:
                        continue

                    dev_name = run["gpu"][first_gpu_stage][i]["device_name"]
                    dev_total = run["gpu"][first_gpu_stage][i]["total_memory"]

                    rich_print(f"  [green]{dev_name}[/] [dim]|[/] {sizeof_fmt(dev_total)}")

                    prev_stage = None
                    for stage in gpu_stages:
                        used = run["gpu"][stage][i]["total_memory"] - run["gpu"][stage][i]["free_memory"]
                        if prev_stage is None:
                            rich_print(f"  * {stage} : {sizeof_fmt(used)}")
                        else:
                            rich_print(f"  * {stage} : {delta_fmt(prev_stage, used)}")
                        prev_stage = used

                    rich_print()


def view_legacy_disk_usage(run: dict[str, t.Any]) -> None:
    if "disk" in run and run["disk"]:
        rich_print("[bold yellow]Disk Usage:[/]")
        disk = run["disk"]
        disk_stages = list(disk.keys())
        prev_stage = None
        for stage in disk_stages:
            if prev_stage is None:
                rich_print(f"  * {stage} : {sizeof_fmt(disk[stage])}")
            else:
                rich_print(f"  * {stage} : {delta_fmt(disk[prev_stage], disk[stage])}")
            prev_stage = stage

        rich_print()


def view_legacy_network_usage(run: dict[str, t.Any]) -> None:
    has_network_usage = "network" in run and run["network"]
    if has_network_usage:
        network = run["network"]
        stages = list(network.keys())
        interfaces = list(network[stages[0]].keys())
        any_change = False

        for interface in interfaces:
            for stage in stages:
                if network[stage][interface]["rx"] > 0 or network[stage][interface]["tx"] > 0:
                    any_change = True
                    break

        if any_change:
            rich_print("[bold yellow]Network Usage:[/]")

            for interface in interfaces:
                # Check if there were any network changes across stages
                had_network_activity = False
                for stage in stages:
                    if network[stage][interface]["rx"] > 0 or network[stage][interface]["tx"] > 0:
                        had_network_activity = True
                        break

                if not had_network_activity:
                    continue

                rich_print(f"  [bold]{interface}[/]")
                prev_stage = None
                for stage in stages:
                    if prev_stage is None:
                        rx_fmt = sizeof_fmt(network[stage][interface]["rx"])
                        tx_fmt = sizeof_fmt(network[stage][interface]["tx"])
                        rich_print(f"    {stage} : rx={rx_fmt} tx={tx_fmt}")
                    else:
                        rx_fmt = delta_fmt(network[prev_stage][interface]["rx"], network[stage][interface]["rx"])
                        tx_fmt = delta_fmt(network[prev_stage][interface]["tx"], network[stage][interface]["tx"])
                        rich_print(f"    {stage} : rx={rx_fmt} tx={tx_fmt}")
                    prev_stage = stage

                rich_print()


def count_package_prefixes(path_dict: dict[str, str], level: int = 2) -> dict[str, int]:
    from collections import defaultdict

    prefix_counter: defaultdict[str, int] = defaultdict(int)

    for package_path in path_dict.keys():
        parts = package_path.split(".")
        if len(parts) >= level:
            prefix = ".".join(parts[:level])
        else:
            prefix = parts[0]

        prefix_counter[prefix] += 1

    return dict(prefix_counter)


def view_legacy_extra_imports(key: str, value: t.Any) -> None:
    if value:
        rich_print("[bold yellow]Top Level Imports:[/] ")
        as_dict = dict(value.items())
        as_counters = count_package_prefixes(as_dict, level=1)
        for package, count in sorted(as_counters.items(), key=lambda x: x[1], reverse=True):
            if count > 1:
                rich_print(f"  * [green]{package}[/][dim].*[/]: {count}")
            else:
                rich_print(f"  * [green]{package}[/]")
        rich_print()


def view_legacy_extra(run: dict[str, t.Any]) -> None:
    unknown = []
    if "extra" in run and run["extra"]:
        for k, v in run["extra"].items():
            fn_name = f"view_legacy_extra_{k}"
            if fn_name in globals():
                globals()[fn_name](k, v)
            else:
                unknown.append(k)

    if unknown:
        rich_print("[bold yellow]Other Records:[/]")
        for k in unknown:
            rich_print(f"  * {k}")
        rich_print()
