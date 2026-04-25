"""脚本态常量定义。"""

from __future__ import annotations

import re

DEFAULT_SCRIPT_TERMINAL: tuple[str, ...] = ("tmux", "splitw", "-h")
HEX_POINTER_RE = re.compile(rb"0x[0-9a-fA-F]+")

