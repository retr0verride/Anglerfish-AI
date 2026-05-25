"""Anglerfish AI — AI-powered SSH honeypot.

This package implements the runtime components of the Anglerfish AI honeypot:
configuration, the native SSH lure, the LLM bridge that drives the fake
shell, the threat-scoring engine, the dashboard, the persistent session
store, the credential intelligence store, and the first-boot wizard. Each
subsystem is shipped as a sub-package of :mod:`anglerfish`.

The package follows a hard separation between data validation (Pydantic
models in :mod:`anglerfish.config` and :mod:`anglerfish.models`) and runtime
services. All public types are typed and exported with explicit ``__all__``
lists; ``mypy --strict`` is the source of truth for the public surface.
"""

from __future__ import annotations

__version__ = "0.1.0"

__all__ = ["__version__"]
