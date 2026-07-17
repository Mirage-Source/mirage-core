from __future__ import annotations

import sys
from pathlib import Path

# bridge/ is a sibling package to ml/ (not pip-installed, no pyproject of its
# own) -- add the repo root to sys.path so tests can `import bridge.enrich`
# directly, same layout CI checks out (ml-tests.yml triggers on both ml/**
# and bridge/** but only installs the ml/ package).
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
