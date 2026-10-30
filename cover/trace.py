"""Append-only JSONL trace writer (DP5). Events are validated against models.TraceEvent before writing."""
import datetime, json
from pathlib import Path
from .models import TraceEvent


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class TraceWriter:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.f = self.path.open("a", encoding="utf-8")

    def emit(self, **kw):
        ev = TraceEvent(timestamp_utc=now(), **kw)
        self.f.write(ev.model_dump_json() + "\n")
        self.f.flush()
        return ev

    def close(self):
        self.f.close()


def append_jsonl(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, default=str) + "\n")


def read_jsonl(path):
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
