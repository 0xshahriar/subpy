"""Passive subdomain sources.

Importing this package registers every built-in source with the
:data:`subpy.sources.base.SOURCE_REGISTRY`, so ``get_sources()`` always
sees the full set.
"""

from . import (
    crawl,  # noqa: F401,E402
    ct,  # noqa: F401,E402
    datasets,  # noqa: F401,E402
)
from .base import (  # noqa: F401
    SOURCE_REGISTRY,
    PassiveSource,
    SourceContext,
    SourceResult,
    belongs_to,
    clean_hostname,
    get_sources,
    list_sources,
    register,
)
from .http import HttpClient, HttpError  # noqa: F401,E402

__all__ = [
    "PassiveSource",
    "SOURCE_REGISTRY",
    "SourceContext",
    "SourceResult",
    "belongs_to",
    "clean_hostname",
    "get_sources",
    "list_sources",
    "register",
    "HttpClient",
    "HttpError",
]
