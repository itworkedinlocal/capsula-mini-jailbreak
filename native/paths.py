"""Shared paths for developer-only native builds; outputs never enter Git."""
import os
from pathlib import Path

NATIVE = Path(__file__).resolve().parent
ROOT = NATIVE.parent
STOCK = ROOT / 'resources/stock-root'
BUILD = ROOT / '.cache/native'
SOURCES = ROOT / '.cache/sources'
TOOLS = ROOT / '.cache/tools'
ZIG = Path(os.environ.get('ZIG', str(TOOLS / 'zig-x86_64-linux-0.15.2/zig'))).resolve()
