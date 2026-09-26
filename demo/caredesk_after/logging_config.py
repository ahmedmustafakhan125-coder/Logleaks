"""logging_config.py — root-level shim for the LogLeak G6 safety-net probe.

The probe script does:
    from logging_config import configure_logging

This file re-exports configure_logging() from the real implementation so that
the probe works whether it imports from the package root or from the caredesk
sub-package.
"""
from caredesk.logging_config import configure_logging  # noqa: F401
