"""Make the vendored ML package and the bridge importable during tests.

The integrated repo vendors the ML package under ``ml/`` and keeps the bridge at
the repo root, so we add both to ``sys.path`` regardless of the pytest CWD:

    <repo>/            -> `import bridge`
    <repo>/ml/         -> `import mirage`
"""

from __future__ import annotations

import pathlib
import sys

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_ML_ROOT = _REPO_ROOT / "ml"

for _p in (_REPO_ROOT, _ML_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))
