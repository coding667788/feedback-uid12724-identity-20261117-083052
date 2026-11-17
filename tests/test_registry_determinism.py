"""注册表完整性与确定性重放测试。"""

from __future__ import annotations

import json

from solution.errors import ErrorCode, TokenError
from solution.timeutil import IdGenerator
from solution.registry import Registry

from tests._fixture import ServiceFixture, build_registry_data


class TestRegistryValidation(ServiceFixture):
    def test_unknown_tenant_key_service_edge(self):
        with self.assertRaises(TokenError) as ctx:
            self.registry.get_key("t-nope", "k1")
        self.assertEqual(ctx.exception.code, ErrorCode.UNKNOWN_TENANT)

        with self.assertRaises(TokenError) as ctx:
            self.registry.get_key("t-acme", "k-nope")
        self.assertEqual(ctx.exception.code, ErrorCode.UNKNOWN_KEY)

        self.assertEqual(self.registry.require_service("acme-orders"), "t-acme")
        with self.assertRaises(TokenError) as ctx:
            self.registry.require_service("nope-svc")
        self.assertEqual(ctx.exception.code, ErrorCode.UNKNOWN_SERVICE)

        with self.assertRaises(TokenError) as ctx:
            self.registry.edge("t-acme", "acme-orders", "acme-inventory")
        self.assertEqual(ctx.exception.code, ErrorCode.EDGE_NOT_ALLOWED)

    def test_same_kid_resolves_to_distinct_keys(self):
        self.assertNotEqual(
            self.registry.get_key("t-acme", "k1"),
            self.registry.get_key("t-globex", "k1"),
        )

    def test_registry_rejects_broken_references(self):
        cases = [
            # 边引用未知租户
            {"tenants": build_registry_data()["tenants"],
             "edges": [{"tenant": "t-x", "from": "a", "to": "b", "scopes": ["s"]}]},
            # 边引用未注册服务
            {"tenants": build_registry_data()["tenants"],
             "edges": [{"tenant": "t-acme", "from": "acme-idp",
                        "to": "ghost", "scopes": ["s"]}]},
        ]
        for data in cases:
            path = self.tmp / "bad-registry.json"
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(ValueError):
                Registry.load(path)

    def test_duplicate_kid_rejected(self):
        data = build_registry_data()
        data["tenants"]["t-acme"]["keys"].append(
            dict(data["tenants"]["t-acme"]["keys"][0])
        )
        path = self.tmp / "dup-kid.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaises(ValueError):
            Registry.load(path)


class TestDeterminism(ServiceFixture):
    def test_id_generator_is_seeded_and_replayable(self):
        a = IdGenerator(b"same-seed")
        b = IdGenerator(b"same-seed")
        seq_a = [a.jti() for _ in range(5)]
        seq_b = [b.jti() for _ in range(5)]
        self.assertEqual(seq_a, seq_b)

        c = IdGenerator(b"different-seed")
        self.assertNotEqual(seq_a[0], c.jti())

    def test_full_run_replay_produces_identical_jtis(self):
        from solution.store import Store
        from solution.service import TokenService
        from solution.timeutil import Clock
        from tests._fixture import FROZEN_NOW, SEED

        def run_once(db_name):
            store = Store(self.tmp / db_name)
            svc = TokenService(
                self.registry, store, Clock(fixed=FROZEN_NOW), IdGenerator(SEED)
            )
            root = svc.mint(
                tenant="t-acme", kid="k1", issuer="acme-idp",
                subject="u", audience="acme-gateway",
                scopes=["orders:read", "billing:read"], ttl_seconds=3600,
            )
            h1 = svc.exchange(
                parent_token=root["token"], caller="acme-gateway",
                target="acme-orders",
                requested_scopes=["orders:read", "billing:read"],
                request_id="req-det-1",
            )
            h2 = svc.exchange(
                parent_token=h1["token"], caller="acme-orders",
                target="acme-billing", requested_scopes=["billing:read"],
                request_id="req-det-2",
            )
            store.close()
            return root, h1, h2

        run_a = run_once("det-a.db")
        run_b = run_once("det-b.db")
        for a, b in zip(run_a, run_b):
            self.assertEqual(a["jti"], b["jti"])
            self.assertEqual(a["token"], b["token"])


if __name__ == "__main__":
    unittest.main()
