from collections import defaultdict


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
        delta_fmt_str = sizeof_fmt(delta)
        fmt += f" :red_triangle_pointed_up: [red]{delta_fmt_str}[/]"
    return fmt


def count_package_prefixes(path_dict: dict[str, str], level: int = 2) -> dict[str, int]:
    prefix_counter: defaultdict[str, int] = defaultdict(int)

    for package_path in path_dict.keys():
        parts = package_path.split(".")
        if len(parts) >= level:
            prefix = ".".join(parts[:level])
        else:
            prefix = parts[0]

        prefix_counter[prefix] += 1

    return dict(prefix_counter)
