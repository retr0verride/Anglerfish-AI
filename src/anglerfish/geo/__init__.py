"""Geographic and ASN enrichment, backed by MaxMind GeoLite2.

Public surface:

* :class:`GeoLookup` — async wrapper. Construct once at startup, share
  across sessions, close on shutdown.
* :func:`fetch_geolite_databases` — sync helper invoked by the
  ``anglerfish geo update`` CLI to refresh the on-disk databases.
"""

from __future__ import annotations

from anglerfish.geo.fetch import FetchError, FetchResult, fetch_geolite_databases
from anglerfish.geo.lookup import GeoLookup

__all__ = ["FetchError", "FetchResult", "GeoLookup", "fetch_geolite_databases"]
