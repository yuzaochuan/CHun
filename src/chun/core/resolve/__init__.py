"""Resolve 服务导出。"""

from .dynelf import DynELFResolver
from .service import ResolveService

__all__ = ["DynELFResolver", "ResolveService"]
