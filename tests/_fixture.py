"""测试公共夹具：在临时目录构造注册表、SQLite 与服务。"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from solution.encoding import b64url_encode
from solution.registry import Registry
from solution.service import TokenService
from solution.store import Store
from solution.timeutil import Clock, IdGenerator

FROZEN_NOW = 1_700_000_000
SEED = b"unit-test-fixed-seed"


def build_registry_data() -> dict:
    return {
        "version": 1,
        "tenants": {
            "t-acme": {
                "keys": [
                    {"kid": "k1", "material_b64url": b64url_encode(b"acme-secret-key-32-bytes-padding!!")}
                ],
                "services": {
                    "acme-idp": {},
                    "acme-gateway": {},
                    "acme-orders": {},
                    "acme-billing": {},
                    "acme-inventory": {},
                },
            },
            "t-globex": {
                # 同 kid 不同密钥，覆盖跨租户同 kid。
                "keys": [
                    {"kid": "k1", "material_b64url": b64url_encode(b"globex-secret-key-32-bytes-padding")}
                ],
                "services": {
                    "globex-idp": {},
                    "globex-gateway": {},
                    "globex-orders": {},
                },
            },
            "t-chain": {
                "keys": [
                    {"kid": "k1", "material_b64url": b64url_encode(b"chain-secret-key-32-bytes-paddingxx")}
                ],
                "services": {f"chain-svc-{i}": {} for i in range(6)},
            },
        },
        "edges": [
            {"tenant": "t-acme", "from": "acme-gateway", "to": "acme-orders",
             "scopes": ["orders:read", "orders:write", "billing:read"]},
            {"tenant": "t-acme", "from": "acme-orders", "to": "acme-billing",
             "scopes": ["billing:read"]},
            {"tenant": "t-globex", "from": "globex-gateway", "to": "globex-orders",
             "scopes": ["orders:read"]},
            *[
                {"tenant": "t-chain", "from": f"chain-svc-{i}",
                 "to": f"chain-svc-{i + 1}", "scopes": ["data:read"]}
                for i in range(5)
            ],
        ],
    }


class ServiceFixture(unittest.TestCase):
    """每个测试类获得独立临时目录与全新数据库。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.registry_path = self.tmp / "registry.json"
        import json
        self.registry_path.write_text(
            json.dumps(build_registry_data(), ensure_ascii=False), encoding="utf-8"
        )
        self.registry = Registry.load(self.registry_path)
        self.db_path = self.tmp / "exchanger.db"
        self.store = Store(self.db_path)
        self.clock = Clock(fixed=FROZEN_NOW)
        self.ids = IdGenerator(SEED)
        self.service = TokenService(self.registry, self.store, self.clock, self.ids)

    def tearDown(self) -> None:
        self.store.close()
        self._tmp.cleanup()

    # -- 便捷构造 ------------------------------------------------------- #
    def mint_root(self, **overrides):
        params = dict(
            tenant="t-acme",
            kid="k1",
            issuer="acme-idp",
            subject="user-7788",
            audience="acme-gateway",
            scopes=["orders:read", "orders:write", "billing:read"],
            ttl_seconds=3600,
        )
        params.update(overrides)
        return self.service.mint(**params)

    def hop1(self, root_result=None, *, request_id="req-h1"):
        root_result = root_result or self.mint_root()
        return self.service.exchange(
            parent_token=root_result["token"],
            caller="acme-gateway",
            target="acme-orders",
            requested_scopes=["billing:read", "orders:read"],
            request_id=request_id,
        )

    def hop2(self, hop1_result=None, *, request_id="req-h2"):
        hop1_result = hop1_result or self.hop1()
        return self.service.exchange(
            parent_token=hop1_result["token"],
            caller="acme-orders",
            target="acme-billing",
            requested_scopes=["billing:read"],
            request_id=request_id,
        )
