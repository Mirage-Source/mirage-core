"""
File names and text I/O for the published dataset.

Data files are gzip-compressed because GitHub rejects any pushed file over
100 MB, and sessions.json alone passed that at 110 MB in September 2026.
Compression is chosen by the ".gz" suffix, so readers can still open the plain
files in versions published before the switch.
"""

import gzip
import io
from pathlib import Path

SESSIONS_CSV = "sessions.csv.gz"
SESSIONS_JSON = "sessions.json.gz"
COMMANDS_JSONL = "commands.jsonl.gz"


def open_text(path: Path, mode: str, **kwargs):
    """open() in text mode, gzip-compressed when the path ends in .gz.

    mtime=0 keeps the gzip header free of a timestamp, so the same data
    compresses to the same bytes and git stores it once.
    """
    if Path(path).suffix != ".gz":
        return open(path, mode, encoding="utf-8", **kwargs)
    binary = gzip.GzipFile(filename=path, mode=mode.replace("t", "") + "b", mtime=0)
    return io.TextIOWrapper(binary, encoding="utf-8", **kwargs)
