"""本机模拟服务（无任何网络 IO）。

每个 LocalService 持有自己的 service_id，出示令牌时以该身份调用
TokenService，用于在样例与测试中表达“服务 A 拿着受众为 A 的令牌
去交换服务 B 的新令牌”这一调用语义。
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import TokenError
from .service import TokenService


@dataclass
class LocalService:
    service_id: str
    tenant: str
    service: TokenService

    def exchange(
        self,
        *,
        parent_token: str,
        target: str,
        requested_scopes: list[str],
        request_id: str,
        requested_expiry: int | None = None,
    ) -> dict:
        # 调用身份固定为该模拟服务自身；service 层再校验它等于父令牌 aud。
        return self.service.exchange(
            parent_token=parent_token,
            caller=self.service_id,
            target=target,
            requested_scopes=requested_scopes,
            requested_expiry=requested_expiry,
            request_id=request_id,
        )

    def verify(self, token: str) -> dict:
        return self.service.verify_online(token, caller=self.service_id)

    def safe_exchange(self, **kwargs) -> dict:
        """捕获 TokenError，返回统一的拒绝字典（CLI/测试证据用）。"""
        try:
            result = self.exchange(**kwargs)
            result["status"] = "ok"
            return result
        except TokenError as exc:
            out = exc.to_dict()
            out["status"] = "rejected"
            return out

    def safe_verify(self, token: str) -> dict:
        try:
            result = self.verify(token)
            result["status"] = "ok"
            return result
        except TokenError as exc:
            out = exc.to_dict()
            out["status"] = "rejected"
            return out
