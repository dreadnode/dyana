import typing as t
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def sample_run_dict() -> dict[str, t.Any]:
    return {
        "loader_name": "test-loader",
        "build_platform": None,
        "build_args": None,
        "arguments": None,
        "volumes": None,
        "errors": None,
        "warnings": None,
        "stdout": None,
        "stderr": None,
        "exit_code": None,
        "stages": None,
        "extra": None,
    }


@pytest.fixture
def sample_trace_dict(sample_run_dict: dict[str, t.Any]) -> dict[str, t.Any]:
    return {
        "started_at": "2024-01-01T00:00:00",
        "ended_at": "2024-01-01T00:01:00",
        "platform": "Linux-6.1.0-x86_64",
        "tracee_version": None,
        "tracee_kernel_release": None,
        "dyana_version": "0.1.4",
        "run": sample_run_dict,
        "events": [],
    }


@pytest.fixture
def sample_trace_with_events(sample_run_dict: dict[str, t.Any]) -> dict[str, t.Any]:
    return {
        "started_at": "2024-01-01T00:00:00",
        "ended_at": "2024-01-01T00:01:00",
        "platform": "Linux-6.1.0-x86_64",
        "tracee_version": None,
        "tracee_kernel_release": None,
        "dyana_version": "0.1.4",
        "run": sample_run_dict,
        "events": [
            {
                "eventName": "sched_process_exec",
                "timestamp": 1000,
                "processId": 1,
                "parentProcessId": 0,
                "processName": "python",
                "syscall": "execve",
                "containerId": "abc123",
                "args": [
                    {"name": "cmdpath", "value": "/usr/bin/python"},
                    {"name": "argv", "value": ["python", "main.py"]},
                ],
            },
            {
                "eventName": "security_file_open",
                "timestamp": 2000,
                "processId": 1,
                "processName": "python",
                "containerId": "abc123",
                "args": [
                    {"name": "syscall_pathname", "value": "/app/main.py"},
                    {"name": "pathname", "value": "/app/main.py"},
                ],
            },
            {
                "eventName": "security_socket_connect",
                "timestamp": 3000,
                "processId": 1,
                "processName": "python",
                "syscall": "connect",
                "containerId": "abc123",
                "args": [
                    {
                        "name": "remote_addr",
                        "value": {
                            "sa_family": "AF_INET",
                            "sin_addr": "93.184.216.34",
                            "sin_port": 443,
                        },
                    },
                ],
            },
            {
                "eventName": "net_packet_dns",
                "timestamp": 2500,
                "processId": 1,
                "processName": "python",
                "containerId": "abc123",
                "args": [
                    {
                        "name": "proto_dns",
                        "value": {
                            "questions": [{"name": "example.com"}],
                            "answers": [{"name": "example.com", "IP": "93.184.216.34"}],
                        },
                    },
                ],
            },
        ],
    }


@pytest.fixture
def mock_docker_client() -> t.Generator[MagicMock, None, None]:
    mock_client = MagicMock()
    with patch("dyana.docker._get_client", return_value=mock_client):
        yield mock_client
