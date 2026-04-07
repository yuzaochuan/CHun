"""历史脚本兼容层。

旧脚本仍可继续使用 `from my_tools import MyTool, BlindFmtTool`，
实际实现已经迁移到 `src/chun`。
"""

from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if SRC_DIR.exists():
    sys.path.insert(0, str(SRC_DIR))

from chun import Blind as BlindFmtTool, MyTool, Tool as UnifiedPwn  # noqa: E402

__all__ = ["MyTool", "UnifiedPwn", "BlindFmtTool"]
