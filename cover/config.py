"""Frozen configuration and file fingerprints."""
import hashlib, json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config" / "cover.json"
PROMPT_DIR = ROOT / "prompts"


def load_config(path=CONFIG_PATH):
    return json.loads(Path(path).read_text(encoding="utf-8"))


CONFIG = load_config()
RULES = CONFIG["rules"]


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def prompt_text(name):
    return (PROMPT_DIR / name).read_text(encoding="utf-8")


def prompt_hashes():
    return {p.name: sha256_file(p) for p in sorted(PROMPT_DIR.glob("*.md"))}
