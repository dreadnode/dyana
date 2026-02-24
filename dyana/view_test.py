import typing as t
from unittest.mock import patch

from dyana.view import (
    severity_fmt,
    view_disk_events,
    view_disk_usage,
    view_header,
    view_network_events,
    view_process_executions,
    view_ram,
    view_security_events,
)


class TestSeverityFmt:
    def test_high(self) -> None:
        assert "high severity" in severity_fmt(3)
        assert "red" in severity_fmt(3)

    def test_very_high(self) -> None:
        assert "high severity" in severity_fmt(5)

    def test_moderate(self) -> None:
        assert "moderate severity" in severity_fmt(2)
        assert "yellow" in severity_fmt(2)

    def test_low(self) -> None:
        assert "low severity" in severity_fmt(1)
        assert "green" in severity_fmt(1)

    def test_no_severity(self) -> None:
        assert "no severity" in severity_fmt(0)

    def test_negative(self) -> None:
        assert "no severity" in severity_fmt(-1)


class TestViewHeader:
    def test_basic_header(self, sample_trace_dict: dict[str, t.Any], capsys: t.Any) -> None:
        with patch("dyana.view.rich_print") as mock_print:
            view_header(sample_trace_dict, is_legacy=False)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "test-loader" in output
            assert "Linux" in output

    def test_legacy_warning(self, sample_trace_dict: dict[str, t.Any]) -> None:
        with patch("dyana.view.rich_print") as mock_print:
            view_header(sample_trace_dict, is_legacy=True)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "WARNING" in output
            assert "legacy" in output

    def test_errors_displayed(self, sample_trace_dict: dict[str, t.Any]) -> None:
        sample_trace_dict["run"]["errors"] = {"loader": "something broke"}
        with patch("dyana.view.rich_print") as mock_print:
            view_header(sample_trace_dict, is_legacy=False)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "something broke" in output

    def test_warnings_displayed(self, sample_trace_dict: dict[str, t.Any]) -> None:
        sample_trace_dict["run"]["warnings"] = {"pip": "could not find import"}
        with patch("dyana.view.rich_print") as mock_print:
            view_header(sample_trace_dict, is_legacy=False)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "could not find import" in output

    def test_stdout_displayed(self, sample_trace_dict: dict[str, t.Any]) -> None:
        sample_trace_dict["run"]["stdout"] = "hello world"
        with patch("dyana.view.rich_print") as mock_print:
            view_header(sample_trace_dict, is_legacy=False)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "hello world" in output

    def test_stderr_displayed(self, sample_trace_dict: dict[str, t.Any]) -> None:
        sample_trace_dict["run"]["stderr"] = "error output"
        with patch("dyana.view.rich_print") as mock_print:
            view_header(sample_trace_dict, is_legacy=False)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "error output" in output

    def test_build_args_displayed(self, sample_trace_dict: dict[str, t.Any]) -> None:
        sample_trace_dict["run"]["build_args"] = {"MODEL": "gpt2"}
        with patch("dyana.view.rich_print") as mock_print:
            view_header(sample_trace_dict, is_legacy=False)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "MODEL=gpt2" in output


class TestViewRam:
    def test_single_stage(self) -> None:
        stages = [{"name": "start", "ram": 1024}]
        with patch("dyana.view.rich_print") as mock_print:
            view_ram(stages)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "start" in output
            assert "1.0KiB" in output

    def test_multiple_stages_with_delta(self) -> None:
        stages = [
            {"name": "start", "ram": 1024},
            {"name": "end", "ram": 2048},
        ]
        with patch("dyana.view.rich_print") as mock_print:
            view_ram(stages)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "start" in output
            assert "end" in output


class TestViewProcessExecutions:
    def test_with_events(self, sample_trace_with_events: dict[str, t.Any]) -> None:
        with patch("dyana.view.rich_print") as mock_print:
            view_process_executions(sample_trace_with_events)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "Process Executions" in output
            assert "python" in output

    def test_empty_events(self) -> None:
        trace: dict[str, t.Any] = {"events": []}
        with patch("dyana.view.rich_print") as mock_print:
            view_process_executions(trace)
            mock_print.assert_not_called()

    def test_tree_building(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "sched_process_exec",
                    "timestamp": 1000,
                    "processId": 1,
                    "parentProcessId": 0,
                    "processName": "bash",
                    "syscall": "execve",
                    "args": [
                        {"name": "cmdpath", "value": "/bin/bash"},
                        {"name": "argv", "value": ["bash"]},
                    ],
                },
                {
                    "eventName": "sched_process_exec",
                    "timestamp": 2000,
                    "processId": 2,
                    "parentProcessId": 1,
                    "processName": "python",
                    "syscall": "execve",
                    "args": [
                        {"name": "cmdpath", "value": "/usr/bin/python"},
                        {"name": "argv", "value": ["python", "main.py"]},
                    ],
                },
            ],
        }
        with patch("dyana.view.rich_print"):
            view_process_executions(trace)


class TestViewNetworkEvents:
    def test_af_inet(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "security_socket_connect",
                    "timestamp": 1000,
                    "processId": 1,
                    "processName": "curl",
                    "syscall": "connect",
                    "args": [
                        {
                            "name": "remote_addr",
                            "value": {"sa_family": "AF_INET", "sin_addr": "1.2.3.4", "sin_port": 80},
                        }
                    ],
                }
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_network_events(trace)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "1.2.3.4:80" in output

    def test_af_inet6(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "security_socket_connect",
                    "timestamp": 1000,
                    "processId": 1,
                    "processName": "curl",
                    "syscall": "connect",
                    "args": [
                        {
                            "name": "remote_addr",
                            "value": {"sa_family": "AF_INET6", "sin6_addr": "::1", "sin6_port": 443},
                        }
                    ],
                }
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_network_events(trace)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "[::1]:443" in output

    def test_af_unix(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "security_socket_connect",
                    "timestamp": 1000,
                    "processId": 1,
                    "processName": "app",
                    "syscall": "connect",
                    "args": [
                        {
                            "name": "remote_addr",
                            "value": {"sa_family": "AF_UNIX", "sun_path": "/var/run/app.sock"},
                        }
                    ],
                }
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_network_events(trace)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "/var/run/app.sock" in output

    def test_dns_query(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "net_packet_dns",
                    "timestamp": 1000,
                    "processId": 1,
                    "processName": "curl",
                    "args": [
                        {
                            "name": "proto_dns",
                            "value": {
                                "questions": [{"name": "example.com"}],
                                "answers": [],
                            },
                        }
                    ],
                }
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_network_events(trace)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "example.com" in output
            assert "question=" in output

    def test_dns_answer(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "net_packet_dns",
                    "timestamp": 1000,
                    "processId": 1,
                    "processName": "curl",
                    "args": [
                        {
                            "name": "proto_dns",
                            "value": {
                                "questions": [{"name": "example.com"}],
                                "answers": [{"name": "example.com", "IP": "1.2.3.4"}],
                            },
                        }
                    ],
                }
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_network_events(trace)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "answer=" in output
            assert "1.2.3.4" in output

    def test_dedup(self) -> None:
        event = {
            "eventName": "security_socket_connect",
            "timestamp": 1000,
            "processId": 1,
            "processName": "curl",
            "syscall": "connect",
            "args": [
                {"name": "remote_addr", "value": {"sa_family": "AF_INET", "sin_addr": "1.2.3.4", "sin_port": 80}}
            ],
        }
        trace: dict[str, t.Any] = {"events": [event, {**event, "timestamp": 2000}]}
        with patch("dyana.view.rich_print") as mock_print:
            view_network_events(trace)
            # Header + one unique line + trailing newline = 3 calls
            assert mock_print.call_count == 3

    def test_empty(self) -> None:
        trace: dict[str, t.Any] = {"events": []}
        with patch("dyana.view.rich_print") as mock_print:
            view_network_events(trace)
            mock_print.assert_not_called()


class TestViewDiskEvents:
    def test_basic(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "security_file_open",
                    "args": [
                        {"name": "syscall_pathname", "value": "/app/data.txt"},
                        {"name": "pathname", "value": "/app/data.txt"},
                    ],
                }
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_disk_events(trace)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "/app/data.txt" in output

    def test_special_paths_aggregated(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "security_file_open",
                    "args": [
                        {"name": "syscall_pathname", "value": "/usr/lib/libpython.so"},
                        {"name": "pathname", "value": "/usr/lib/libpython.so"},
                    ],
                },
                {
                    "eventName": "security_file_open",
                    "args": [
                        {"name": "syscall_pathname", "value": "/usr/lib/libc.so"},
                        {"name": "pathname", "value": "/usr/lib/libc.so"},
                    ],
                },
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_disk_events(trace)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "2 accesses to /usr/lib/" in output

    def test_empty(self) -> None:
        trace: dict[str, t.Any] = {"events": []}
        with patch("dyana.view.rich_print") as mock_print:
            view_disk_events(trace)
            mock_print.assert_not_called()

    def test_fallback_pathname(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "security_file_open",
                    "args": [
                        {"name": "syscall_pathname", "value": ""},
                        {"name": "pathname", "value": "/app/fallback.txt"},
                    ],
                }
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_disk_events(trace)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "/app/fallback.txt" in output


class TestViewSecurityEvents:
    def test_with_metadata(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "anti_debugging",
                    "metadata": {
                        "Properties": {
                            "signatureName": "Anti-Debugging",
                            "Category": "defense-evasion",
                            "Severity": 3,
                        }
                    },
                }
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_security_events(trace)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "Anti-Debugging" in output
            assert "defense-evasion" in output
            assert "high severity" in output

    def test_without_metadata(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {
                    "eventName": "anti_debugging",
                }
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_security_events(trace)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "anti_debugging" in output
            assert "misc" in output

    def test_empty(self) -> None:
        trace: dict[str, t.Any] = {"events": []}
        with patch("dyana.view.rich_print") as mock_print:
            view_security_events(trace)
            mock_print.assert_not_called()

    def test_non_security_events_ignored(self) -> None:
        trace: dict[str, t.Any] = {
            "events": [
                {"eventName": "security_file_open"},
                {"eventName": "sched_process_exec"},
            ]
        }
        with patch("dyana.view.rich_print") as mock_print:
            view_security_events(trace)
            mock_print.assert_not_called()


class TestViewDiskUsage:
    def test_basic(self) -> None:
        stages = [
            {"name": "start", "disk": 1024},
            {"name": "end", "disk": 2048},
        ]
        with patch("dyana.view.rich_print") as mock_print:
            view_disk_usage(stages)
            output = " ".join(str(c) for c in mock_print.call_args_list)
            assert "Disk Usage" in output
            assert "start" in output
            assert "end" in output
