import typing as t
from unittest.mock import MagicMock, patch

from dyana.loaders.gguf.main import (
    DANGEROUS_CALL_NAMES,
    DANGEROUS_DUNDER_ATTRS,
    DANGEROUS_FILTER_NAMES,
    MALICIOUS_PATTERNS,
    OBFUSCATION_PATTERNS,
    SUSPICIOUS_PATTERNS,
    _analyze_ast,
    analyze_chat_template,
)
from dyana.loaders.loader import Loader


class TestGGUFLoaderSettings:
    def test_loader_loads(self) -> None:
        loader = Loader(name="gguf", build=False)
        assert loader.name == "gguf"

    def test_gpu_disabled(self) -> None:
        loader = Loader(name="gguf", build=False)
        assert loader.settings is not None
        assert loader.settings.gpu is False

    def test_arg_structure(self) -> None:
        loader = Loader(name="gguf", build=False)
        assert loader.settings is not None
        assert loader.settings.args is not None
        assert len(loader.settings.args) == 1
        assert loader.settings.args[0].name == "gguf"
        assert loader.settings.args[0].required is True
        assert loader.settings.args[0].volume is True


class TestAnalyzeChatTemplate:
    """Tests for the combined regex + AST analysis."""

    def test_clean_template(self) -> None:
        template = "{% for message in messages %}{{ message.role }}: {{ message.content }}\n{% endfor %}"
        findings = analyze_chat_template(template)
        assert len(findings["errors"]) == 0
        assert len(findings["warnings"]) == 0

    def test_malicious_class_access(self) -> None:
        template = "{{ ''.__class__.__mro__[1].__subclasses__() }}"
        findings = analyze_chat_template(template)
        assert len(findings["errors"]) > 0
        assert any("__class__" in e for e in findings["errors"])

    def test_malicious_attr_filter(self) -> None:
        template = "{{ request|attr('application') }}"
        findings = analyze_chat_template(template)
        assert len(findings["errors"]) > 0
        assert any("attr filter" in e for e in findings["errors"])

    def test_malicious_import(self) -> None:
        template = "{% set x = import os %}"
        findings = analyze_chat_template(template)
        assert any("Import statement" in e for e in findings["errors"])

    def test_malicious_eval(self) -> None:
        template = "{{ eval('os.system(\"id\")') }}"
        findings = analyze_chat_template(template)
        assert any("eval()" in e for e in findings["errors"])

    def test_malicious_exec(self) -> None:
        template = "{{ exec('import os') }}"
        findings = analyze_chat_template(template)
        assert any("exec()" in e for e in findings["errors"])

    def test_malicious_subprocess(self) -> None:
        template = "{{ subprocess.check_output('id') }}"
        findings = analyze_chat_template(template)
        assert any("Subprocess" in e for e in findings["errors"])

    def test_malicious_os_access(self) -> None:
        template = "{{ os.system('id') }}"
        findings = analyze_chat_template(template)
        assert any("OS module" in e for e in findings["errors"])

    def test_obfuscation_base64(self) -> None:
        template = "{{ base64.b64decode('aW1wb3J0IG9z') }}"
        findings = analyze_chat_template(template)
        assert len(findings["warnings"]) > 0
        assert any("Base64" in w for w in findings["warnings"])

    def test_obfuscation_hex_escape(self) -> None:
        template = r"{{ '\x6f\x73' }}"
        findings = analyze_chat_template(template)
        assert any("Hex escape" in w for w in findings["warnings"])

    def test_obfuscation_unicode_escape(self) -> None:
        template = r"{{ '\u006f\u0073' }}"
        findings = analyze_chat_template(template)
        assert any("Unicode escape" in w for w in findings["warnings"])

    def test_obfuscation_chr(self) -> None:
        template = "{{ chr(111) + chr(115) }}"
        findings = analyze_chat_template(template)
        assert any("chr()" in w for w in findings["warnings"])

    def test_obfuscation_string_concat(self) -> None:
        template = "{{ 'os' + '.system' }}"
        findings = analyze_chat_template(template)
        assert any("String concatenation" in w for w in findings["warnings"])

    def test_suspicious_conditional(self) -> None:
        template = "{% if user.role == 'admin' %}secret{% endif %}"
        findings = analyze_chat_template(template)
        assert len(findings["info"]) > 0
        assert any("Conditional" in i for i in findings["info"])

    def test_suspicious_loop(self) -> None:
        template = "{% for i in range(100) %}{{ i }}{% endfor %}"
        findings = analyze_chat_template(template)
        assert any("Loop" in i for i in findings["info"])

    def test_sandbox_validation_failure(self) -> None:
        mock_env = MagicMock()
        mock_env.parse.side_effect = Exception("Unexpected end of template")
        mock_sandbox_cls = MagicMock(return_value=mock_env)
        mock_sandbox = MagicMock()
        mock_sandbox.SandboxedEnvironment = mock_sandbox_cls
        mock_jinja2 = MagicMock()
        mock_jinja2.sandbox = mock_sandbox

        with patch.dict("sys.modules", {"jinja2": mock_jinja2, "jinja2.sandbox": mock_sandbox}):
            template = "{% if true %} no end"
            findings = analyze_chat_template(template)
            assert any("Sandbox validation failed" in e for e in findings["errors"])

    def test_pattern_lists_not_empty(self) -> None:
        assert len(MALICIOUS_PATTERNS) > 0
        assert len(OBFUSCATION_PATTERNS) > 0
        assert len(SUSPICIOUS_PATTERNS) > 0
        assert len(DANGEROUS_DUNDER_ATTRS) > 0
        assert len(DANGEROUS_FILTER_NAMES) > 0
        assert len(DANGEROUS_CALL_NAMES) > 0

    def test_multiple_findings(self) -> None:
        template = "{{ ''.__class__.__base__.__subclasses__() }}{{ eval('x') }}"
        findings = analyze_chat_template(template)
        assert len(findings["errors"]) >= 3


class TestAnalyzeAST:
    """Tests for AST-based analysis specifically, using mocked jinja2."""

    def _mock_jinja2(self) -> tuple[MagicMock, MagicMock, type, type, type, type, type]:
        """Create mock jinja2 modules that simulate real AST node types."""
        mock_nodes = MagicMock()
        mock_sandbox = MagicMock()

        class FakeNode:
            pass

        class FakeGetattr(FakeNode):
            def __init__(self, attr: str, node: t.Any = None) -> None:
                self.attr = attr
                self.node = node

        class FakeCall(FakeNode):
            def __init__(self, callee: t.Any) -> None:
                self.node = callee

        class FakeName(FakeNode):
            def __init__(self, name: str) -> None:
                self.name = name

        class FakeFilter(FakeNode):
            def __init__(self, name: str) -> None:
                self.name = name

        mock_nodes.Node = FakeNode
        mock_nodes.Getattr = FakeGetattr
        mock_nodes.Call = FakeCall
        mock_nodes.Name = FakeName
        mock_nodes.Filter = FakeFilter

        return mock_nodes, mock_sandbox, FakeNode, FakeGetattr, FakeCall, FakeName, FakeFilter

    def test_ast_detects_dunder_access(self) -> None:
        mock_nodes, mock_sandbox, FakeNode, FakeGetattr, FakeCall, FakeName, FakeFilter = self._mock_jinja2()

        getattr_node = FakeGetattr("__class__")
        mock_ast = MagicMock()
        mock_ast.find_all.return_value = [getattr_node]

        mock_env = MagicMock()
        mock_env.parse.return_value = mock_ast
        mock_sandbox.SandboxedEnvironment.return_value = mock_env
        mock_jinja2 = MagicMock()
        mock_jinja2.nodes = mock_nodes
        mock_jinja2.sandbox = mock_sandbox

        with patch.dict(
            "sys.modules", {"jinja2": mock_jinja2, "jinja2.nodes": mock_nodes, "jinja2.sandbox": mock_sandbox}
        ):
            findings = _analyze_ast("{{ x.__class__ }}")
            assert any("__class__" in e for e in findings["errors"])

    def test_ast_detects_dangerous_call(self) -> None:
        mock_nodes, mock_sandbox, FakeNode, FakeGetattr, FakeCall, FakeName, FakeFilter = self._mock_jinja2()

        name_node = FakeName("eval")
        call_node = FakeCall(name_node)
        mock_ast = MagicMock()
        mock_ast.find_all.return_value = [call_node]

        mock_env = MagicMock()
        mock_env.parse.return_value = mock_ast
        mock_sandbox.SandboxedEnvironment.return_value = mock_env
        mock_jinja2 = MagicMock()
        mock_jinja2.nodes = mock_nodes
        mock_jinja2.sandbox = mock_sandbox

        with patch.dict(
            "sys.modules", {"jinja2": mock_jinja2, "jinja2.nodes": mock_nodes, "jinja2.sandbox": mock_sandbox}
        ):
            findings = _analyze_ast("{{ eval('x') }}")
            assert any("eval()" in e for e in findings["errors"])

    def test_ast_detects_dangerous_method_call(self) -> None:
        mock_nodes, mock_sandbox, FakeNode, FakeGetattr, FakeCall, FakeName, FakeFilter = self._mock_jinja2()

        method_node = FakeGetattr("exec")
        call_node = FakeCall(method_node)
        mock_ast = MagicMock()
        mock_ast.find_all.return_value = [call_node]

        mock_env = MagicMock()
        mock_env.parse.return_value = mock_ast
        mock_sandbox.SandboxedEnvironment.return_value = mock_env
        mock_jinja2 = MagicMock()
        mock_jinja2.nodes = mock_nodes
        mock_jinja2.sandbox = mock_sandbox

        with patch.dict(
            "sys.modules", {"jinja2": mock_jinja2, "jinja2.nodes": mock_nodes, "jinja2.sandbox": mock_sandbox}
        ):
            findings = _analyze_ast("{{ foo.exec('x') }}")
            assert any("exec()" in e for e in findings["errors"])

    def test_ast_detects_dangerous_filter(self) -> None:
        mock_nodes, mock_sandbox, FakeNode, FakeGetattr, FakeCall, FakeName, FakeFilter = self._mock_jinja2()

        filter_node = FakeFilter("attr")
        mock_ast = MagicMock()
        mock_ast.find_all.return_value = [filter_node]

        mock_env = MagicMock()
        mock_env.parse.return_value = mock_ast
        mock_sandbox.SandboxedEnvironment.return_value = mock_env
        mock_jinja2 = MagicMock()
        mock_jinja2.nodes = mock_nodes
        mock_jinja2.sandbox = mock_sandbox

        with patch.dict(
            "sys.modules", {"jinja2": mock_jinja2, "jinja2.nodes": mock_nodes, "jinja2.sandbox": mock_sandbox}
        ):
            findings = _analyze_ast("{{ x|attr('y') }}")
            assert any("|attr" in w for w in findings["warnings"])

    def test_ast_warns_on_unknown_dunder(self) -> None:
        mock_nodes, mock_sandbox, FakeNode, FakeGetattr, FakeCall, FakeName, FakeFilter = self._mock_jinja2()

        getattr_node = FakeGetattr("__custom_dunder__")
        mock_ast = MagicMock()
        mock_ast.find_all.return_value = [getattr_node]

        mock_env = MagicMock()
        mock_env.parse.return_value = mock_ast
        mock_sandbox.SandboxedEnvironment.return_value = mock_env
        mock_jinja2 = MagicMock()
        mock_jinja2.nodes = mock_nodes
        mock_jinja2.sandbox = mock_sandbox

        with patch.dict(
            "sys.modules", {"jinja2": mock_jinja2, "jinja2.nodes": mock_nodes, "jinja2.sandbox": mock_sandbox}
        ):
            findings = _analyze_ast("{{ x.__custom_dunder__ }}")
            # Known dangerous dunders go to errors, unknown dunders to warnings
            assert any("__custom_dunder__" in w for w in findings["warnings"])
            assert len(findings["errors"]) == 0

    def test_ast_clean_template(self) -> None:
        mock_nodes, mock_sandbox, FakeNode, FakeGetattr, FakeCall, FakeName, FakeFilter = self._mock_jinja2()

        mock_ast = MagicMock()
        mock_ast.find_all.return_value = []

        mock_env = MagicMock()
        mock_env.parse.return_value = mock_ast
        mock_sandbox.SandboxedEnvironment.return_value = mock_env
        mock_jinja2 = MagicMock()
        mock_jinja2.nodes = mock_nodes
        mock_jinja2.sandbox = mock_sandbox

        with patch.dict(
            "sys.modules", {"jinja2": mock_jinja2, "jinja2.nodes": mock_nodes, "jinja2.sandbox": mock_sandbox}
        ):
            findings = _analyze_ast("{{ message.content }}")
            assert len(findings["errors"]) == 0
            assert len(findings["warnings"]) == 0
            assert len(findings["info"]) == 0

    def test_ast_no_jinja2_returns_empty(self) -> None:
        # When jinja2 is not available, AST analysis should return empty findings
        findings = _analyze_ast("{{ anything }}")
        assert findings == {"errors": [], "warnings": [], "info": []}
