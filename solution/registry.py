"""受信注册表：租户、签名密钥、服务与预注册交换边。

注册表是本地 JSON 文件（样例见 samples/registry.json），属于受信配置：
- 密钥只能通过 (tenant, kid) 在这里解析，令牌头永远不能指定密钥地址；
- 交换边按 (tenant, caller -> target) 精确匹配，且边自身带 scope 上限；
- 边的两端必须是同一租户内已注册的服务，加载时即做完整性校验。
"""

from __future__ import annotations

import json
from pathlib import Path

from .encoding import b64url_decode
from .errors import ErrorCode, TokenError


class Registry:
    def __init__(self, data: dict, *, source: str | None = None):
        self._source = source
        self._tenants: dict[str, dict] = {}
        # service_id -> tenant
        self._service_tenant: dict[str, str] = {}
        # (tenant, caller, target) -> {"scopes": tuple[str, ...]}
        self._edges: dict[tuple[str, str, str], dict] = {}
        self._load(data)

    # ------------------------------------------------------------------ #
    @classmethod
    def load(cls, path: str | Path) -> "Registry":
        p = Path(path)
        with p.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        return cls(data, source=str(p))

    def _load(self, data: dict) -> None:
        if not isinstance(data, dict) or not isinstance(data.get("tenants"), dict):
            raise ValueError("注册表顶层必须含 tenants 对象")
        for tenant_id, tenant in data["tenants"].items():
            if not isinstance(tenant_id, str) or not tenant_id:
                raise ValueError("租户 ID 必须是非空字符串")
            keys = {}
            for key in tenant.get("keys", []):
                kid = key.get("kid")
                if not kid or kid in keys:
                    raise ValueError(f"租户 {tenant_id} 的 kid 缺失或重复: {kid!r}")
                # 密钥种子以无填充 base64url 存放，加载期即解码为字节。
                keys[kid] = b64url_decode(key["material_b64url"], what=f"密钥 {kid}")
            services = {}
            for svc_id, svc in tenant.get("services", {}).items():
                if not svc_id:
                    raise ValueError(f"租户 {tenant_id} 存在空服务 ID")
                if svc_id in self._service_tenant:
                    raise ValueError(f"服务 ID 全局重复: {svc_id}")
                services[svc_id] = dict(svc or {})
                self._service_tenant[svc_id] = tenant_id
            if not keys:
                raise ValueError(f"租户 {tenant_id} 至少需要一个签名密钥")
            self._tenants[tenant_id] = {"keys": keys, "services": services}

        for edge in data.get("edges", []):
            tenant_id, caller, target = edge["tenant"], edge["from"], edge["to"]
            if tenant_id not in self._tenants:
                raise ValueError(f"交换边引用未知租户: {tenant_id}")
            tenant = self._tenants[tenant_id]
            if caller not in tenant["services"] or target not in tenant["services"]:
                raise ValueError(
                    f"交换边 {caller}->{target} 引用了租户 {tenant_id} 内未注册的服务"
                )
            scopes = edge.get("scopes", [])
            if not scopes or any(not isinstance(s, str) or not s for s in scopes):
                raise ValueError(f"交换边 {caller}->{target} 的 scopes 必须是非空字符串列表")
            triple = (tenant_id, caller, target)
            if triple in self._edges:
                raise ValueError(f"交换边重复注册: {triple}")
            self._edges[triple] = {"scopes": tuple(sorted(set(scopes)))}

    # ------------------------------------------------------------------ #
    # 查询
    # ------------------------------------------------------------------ #
    def tenant_exists(self, tenant: str) -> bool:
        return tenant in self._tenants

    def get_key(self, tenant: str, kid: str) -> bytes:
        tenant_data = self._tenants.get(tenant)
        if tenant_data is None:
            raise TokenError(
                ErrorCode.UNKNOWN_TENANT,
                f"租户 {tenant!r} 不在受信注册表",
                {"tenant": tenant},
            )
        key = tenant_data["keys"].get(kid)
        if key is None:
            raise TokenError(
                ErrorCode.UNKNOWN_KEY,
                f"租户 {tenant!r} 下不存在 kid={kid!r}",
                {"tenant": tenant, "kid": kid},
            )
        return key

    def service_tenant(self, service: str) -> str | None:
        return self._service_tenant.get(service)

    def require_service(self, service: str) -> str:
        tenant = self._service_tenant.get(service)
        if tenant is None:
            raise TokenError(
                ErrorCode.UNKNOWN_SERVICE,
                f"服务 {service!r} 未在受信注册表注册",
                {"service": service},
            )
        return tenant

    def edge(self, tenant: str, caller: str, target: str) -> dict:
        edge = self._edges.get((tenant, caller, target))
        if edge is None:
            raise TokenError(
                ErrorCode.EDGE_NOT_ALLOWED,
                f"交换边 {caller} -> {target} 未在租户 {tenant} 预注册",
                {"tenant": tenant, "caller": caller, "target": target},
            )
        return edge

    @property
    def source(self) -> str | None:
        return self._source
