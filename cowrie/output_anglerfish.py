"""Cowrie output-plugin stub that re-exports the Anglerfish implementation.

Place this file at ``/opt/cowrie/src/cowrie/output/anglerfish.py`` (or
configure Cowrie's plugin path to point at this directory). Cowrie's
plugin discovery imports the module and instantiates an ``Output`` class
from it.

The real implementation lives in :mod:`anglerfish.integration.cowrie`.
Keeping the Cowrie-side file shallow means upgrading Anglerfish does
not require touching Cowrie's tree.
"""

from __future__ import annotations

from anglerfish.integration.cowrie import build_plugin

Output = build_plugin()
