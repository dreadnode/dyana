# Dyana Security Scanner for Claude Code

Automatically scan packages for supply chain threats before they're installed during AI-assisted coding sessions.

When Claude (or any AI coding assistant using Claude Code) runs `pip install`, `npm install`, or similar commands, this hook intercepts the call, runs the package through Dyana's Docker+eBPF sandbox, and reports security findings before the installation proceeds.

## Prerequisites

- Python 3.10+
- Docker running (Linux, or Docker Desktop on macOS/Windows)
- [Dyana](https://pypi.org/project/dyana/) installed: `pip install dyana`
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) CLI

## Installation

1. Copy the hook script:

```bash
mkdir -p ~/.claude/hooks
cp dyana_scan.py ~/.claude/hooks/dyana_scan.py
chmod +x ~/.claude/hooks/dyana_scan.py
```

2. Add the hook to your Claude Code settings. Merge the contents of `settings.json` into your settings file:

- **Global** (all projects): `~/.claude/settings.json`
- **Per-project** (shared): `.claude/settings.json`
- **Per-project** (local): `.claude/settings.local.json`

If you already have hooks configured, add the Dyana hook entry to your existing `PreToolUse` array.

3. Verify in Claude Code:

```
/hooks
```

You should see the Dyana scanner listed under `PreToolUse`.

## How It Works

```
Claude runs: pip install some-package
       |
       v
PreToolUse hook intercepts Bash command
       |
       v
dyana_scan.py detects it's a package install
       |
       v
Runs: dyana trace --loader pip --package some-package
       |
       v
Parses trace JSON for security events, network activity, processes
       |
       v
Verdict:
  - High severity security events -> BLOCK install, explain why
  - Low/moderate events           -> WARN, Claude assesses findings
  - Clean                         -> ALLOW, brief confirmation
  - Dyana/Docker unavailable      -> ALLOW, note scan was skipped
```

## Supported Package Managers

| Manager | Commands detected |
|---------|-------------------|
| pip     | `pip install`, `pip3 install`, `python -m pip install` |
| uv      | `uv pip install`, `uv add` |
| poetry  | `poetry add` |
| npm     | `npm install`, `npm i` |
| yarn    | `yarn add` |
| pnpm    | `pnpm add`, `pnpm install` |

Bulk/lockfile installs are **skipped** by design (`pip install -r`, `npm ci`, `poetry install`, `uv sync`, bare `yarn`/`npm install`). These install from lockfiles where packages are already pinned.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `DYANA_CACHE_TTL` | `86400` (24h) | How long cached scan results are valid (seconds) |
| `DYANA_SCAN_TIMEOUT` | `120` | Dyana per-package scan timeout (seconds) |

The hook timeout in `settings.json` (default 300s) should be larger than `DYANA_SCAN_TIMEOUT` to allow for Docker image builds on first run.

## Cache

Scan results are cached in `~/.cache/dyana-claude-code/` to avoid rescanning known packages.

- **Pinned packages** (e.g. `requests==2.31.0`) are cached until TTL expires
- **Unpinned packages** (e.g. `requests`) are rescanned once per day
- **Automatic eviction** when cache exceeds 200 entries

Clear the cache:

```bash
rm -rf ~/.cache/dyana-claude-code/
```

## Limitations

- **First scan is slower** due to Docker image builds (~30-60s). Subsequent scans reuse cached Docker layers.
- **Requires Docker** with eBPF support. Linux hosts work natively. macOS requires Docker Desktop or Colima with a Linux VM.
- **Bulk installs skipped** — `pip install -r requirements.txt` doesn't trigger scans. Individual `pip install <package>` commands do.
- **Network required** — Dyana needs to actually download and install the package inside the sandbox to observe its behavior.

## Troubleshooting

**"Scan skipped: dyana is not installed"**
Install Dyana: `pip install dyana`

**"Scan skipped: Docker is not running"**
Start Docker Desktop or the Docker daemon.

**Scans timing out**
Increase the timeout: `export DYANA_SCAN_TIMEOUT=300`

**False positives / want to re-scan**
Clear the cache: `rm -rf ~/.cache/dyana-claude-code/`

**Testing the hook manually**
```bash
echo '{"tool_name":"Bash","tool_input":{"command":"pip install requests"}}' | python3 ~/.claude/hooks/dyana_scan.py
```
