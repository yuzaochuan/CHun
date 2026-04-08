"""HTTP transport。"""

from __future__ import annotations

from typing import Any, Callable

from ..core.errors import MissingDependencyError, TransportConfigError
from ..core.models import TargetSpec, TransportSpec
from .base import BaseTransport


class HttpxTransport(BaseTransport):
    """基于 httpx.Client 的 request/response transport。"""

    def __init__(self, target: TargetSpec, spec: TransportSpec) -> None:
        super().__init__(target, spec)
        self._client: Any = None

    def _open(self) -> None:
        if self.target.base_url is None:
            raise TransportConfigError("HttpxTransport 需要 target.base_url。")

        client_factory = self.spec.metadata.get("client_factory")
        if client_factory is not None:
            self._client = self._build_from_factory(client_factory)
            return

        try:
            import httpx
        except Exception as exc:  # pragma: no cover
            raise MissingDependencyError(
                "HttpxTransport 需要 httpx，请安装：pip install httpx"
            ) from exc

        self._client = httpx.Client(
            base_url=self.target.base_url,
            headers=dict(self.spec.headers),
            follow_redirects=self.spec.follow_redirects,
            verify=self.spec.verify,
            timeout=self.spec.timeout,
        )

    def _build_from_factory(self, client_factory: object) -> Any:
        if not callable(client_factory):
            raise TransportConfigError("client_factory 必须是可调用对象。")
        return client_factory(self.target, self.spec)

    def _close(self) -> None:
        if self._client is not None and hasattr(self._client, "close"):
            self._client.close()
        self._client = None

    @property
    def raw(self) -> Any:
        return self._client

    def request(self, method: str, path: str = "", **kwargs: Any) -> Any:
        self._require_open()
        return self._client.request(method, path, **kwargs)


__all__ = ["HttpxTransport"]
