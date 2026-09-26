"""sitemap.py — AST scan to find every log/print call site in a Python package."""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

# ---------------------------------------------------------------------------
# Receiver names that count as loggers (per architecture doc §3.6)
# ---------------------------------------------------------------------------

_LOGGER_NAMES = frozenset({"logging", "log", "logger", "_logger", "LOGGER"})
_LOG_METHODS = frozenset({
    "debug", "info", "warning", "warn", "error", "critical",
    "exception", "log",
})


def _is_logger_receiver(name: str) -> bool:
    """Return True if name is a recognised logger variable."""
    return name in _LOGGER_NAMES or name.lower().endswith("logger")


@dataclass
class LogSite:
    """A log or print call site discovered via AST analysis."""

    file: str   # relative to the scanned root
    line: int
    call: str   # the call text / method name


# ---------------------------------------------------------------------------
# AST visitor
# ---------------------------------------------------------------------------


class _LogSiteVisitor(ast.NodeVisitor):
    """Visit Call nodes and record recognised log/print call sites."""

    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.sites: list[LogSite] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        """Check whether this call node is a log or print call."""
        func = node.func

        # Case 1: print(...)  — bare name
        if isinstance(func, ast.Name) and func.id == "print":
            self.sites.append(LogSite(
                file=self.rel_path,
                line=node.lineno,
                call="print",
            ))

        # Case 2: receiver.method(...)
        elif isinstance(func, ast.Attribute):
            method = func.attr
            if method in _LOG_METHODS:
                # Get the receiver name
                receiver = func.value
                if isinstance(receiver, ast.Name):
                    receiver_name = receiver.id
                    if _is_logger_receiver(receiver_name) or receiver_name == "logging":
                        self.sites.append(LogSite(
                            file=self.rel_path,
                            line=node.lineno,
                            call=f"{receiver_name}.{method}",
                        ))

        # Recurse into sub-expressions
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def find_log_sites(root: Path) -> list[LogSite]:
    """Walk root for .py files and return all log/print call sites."""
    sites: list[LogSite] = []
    for py_file in sorted(root.rglob("*.py")):
        try:
            source = py_file.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=str(py_file))
        except SyntaxError:
            continue
        rel_path = py_file.relative_to(root).as_posix()
        visitor = _LogSiteVisitor(rel_path)
        visitor.visit(tree)
        sites.extend(visitor.sites)
    return sites


def unwitnessed(
    sites: list[LogSite],
    executed: set[tuple[str, int]],
) -> list[LogSite]:
    """Return sites whose (file, line) pair was not in the executed set."""
    return [s for s in sites if (s.file, s.line) not in executed]
