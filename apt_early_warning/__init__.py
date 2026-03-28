"""Package bootstrap for APT Early Warning."""

from __future__ import annotations

import os
from pathlib import Path

# Avoid matplotlib cache warnings in restricted environments.
_mpl_cache = Path("/tmp/matplotlib")
_mpl_cache.mkdir(parents=True, exist_ok=True)
os.environ.setdefault("MPLCONFIGDIR", str(_mpl_cache))
