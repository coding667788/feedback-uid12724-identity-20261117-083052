"""交换安全规则测试：受众绑定、混淆代理、scope、过期、委托链、跨租户。"""

from __future__ import annotations

from solution import craft as craft_mod
from solution.errors import ErrorCode, TokenError
from solution.token import decode_token

from tests._fixture import FROZEN_NOW, ServiceFixture


class TestLegalTwoHopChain(ServiceFixture):
    def test_mint_root_shape(self):
        root = self.mint_root()
        header, payload, _, _ = decode_token(root["token"])
        self.assertEqual(header["tenant"], "t-acme")
        self.assertEqual(header["kid"], "k1")
        self.assertEqual(payload["act"], [])
        self.assertEqual(payload["aud"], "acme-gateway")
        self.assertEqual(payload["sub"], "user-7788")
        self.assertEqual(payload["jti"], payload["root"])
        self.assertEqual(payload["exp"], FROZEN_NOW + 3600)

    def test_two_hop_chain_delegation_invariants(self):
        root = self.mint_root()
        h1 = self.hop1(root)
        h2 = self.hop2(h1)

        # subject 与 root jti 全程不变。
        self.assertEqual(h1["payload"]["sub"], root["payload"]["sub"])
        self.assertEqual(h2["payload"]["sub"], root["payload"]["sub"])
        self.assertEqual(h1["root_jti"], root["jti"])
        self.assertEqual(h2["root_jti"], root["jti"])

        # actor_chain 逐跳追加调用服务。
        self.assertEqual(h1["payload"]["act"], ["acme-gateway"])
        self.assertEqual(h2["payload"]["act"], ["acme-gateway", "acme-orders"])
        self.assertEqual(h1["depth"], 1)
        self.assertEqual(h2["depth"], 2)

        # 受众逐跳重绑定，发行方是上一跳调用者。
        self.assertEqual(h1["payload"]["aud"], "acme-orders")
        self.assertEqual(h2["payload"]["aud"], "acme-billing")
        self.assertEqual(h2["payload"]["iss"], "acme-orders")

        # scope 只缩小。
        self.assertEqual(set(h1["payload"]["scp"]), {"orders:read", "billing:read"})
        self.assertEqual(h2["payload"]["scp"], ["billing:read"])

        # 每一跳都能被正确受众在线验证。
        v1 = self.service.verify_online(h1["token"], caller="acme-orders")
        v2 = self.service.verify_online(h2["token"], caller="acme-billing")
        self.assertTrue(v1["valid"] and v2["valid"])

    def test_hop_token_rejected_for_wrong_audience_presenter(self):
        h1 = self.hop1()
        # billing 不是 h1 的受众，出示即拒绝。
        with self.assertRaises(TokenError) as ctx:
            self.service.verify_online(h1["token"], caller="acme-billing")
        self.assertEqual(ctx.exception.code, ErrorCode.AUDIENCE_MISMATCH)
        self.assertEqual(ctx.exception.evidence["aud"], "acme-orders")


class TestConfusedDeputy(ServiceFixture):
    def test_non_audience_caller_cannot_exchange(self):
        root = self.mint_root()
        # billing 持有的不是受众为 billing 的令牌（根受众是 gateway）。
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=root["token"],
                caller="acme-billing",
                target="acme-orders",
                requested_scopes=["orders:read"],
                request_id="req-attack-1",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.AUDIENCE_MISMATCH)

    def test_unregistered_edge_rejected(self):
        h1 = self.hop1()
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=h1["token"],
                caller="acme-orders",
                target="acme-inventory",  # 服务存在，但边不存在
                requested_scopes=["orders:read"],
                request_id="req-attack-2",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.EDGE_NOT_ALLOWED)
        self.assertEqual(ctx.exception.evidence["target"], "acme-inventory")

    def test_unknown_service_rejected(self):
        root = self.mint_root()
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=root["token"],
                caller="acme-gateway",
                target="ghost-service",
                requested_scopes=["orders:read"],
                request_id="req-attack-3",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.UNKNOWN_SERVICE)


class TestScopeRules(ServiceFixture):
    def test_scope_escalation_against_parent(self):
        h1 = self.hop1()  # 已不含 orders:write
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=h1["token"],
                caller="acme-orders",
                target="acme-billing",
                requested_scopes=["billing:read", "orders:write"],
                request_id="req-scope-1",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.SCOPE_ESCALATION)
        self.assertEqual(ctx.exception.evidence["added"], ["orders:write"])

    def test_edge_scope_ceiling_enforced(self):
        root = self.mint_root()
        # gateway->orders 边允许 orders:write，但这里请求一个双方都没有的 scope
        # 先验证父级拦截；再验证边级拦截：
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=root["token"],
                caller="acme-gateway",
                target="acme-orders",
                requested_scopes=["root-admin"],  # 父令牌没有
                request_id="req-scope-2",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.SCOPE_ESCALATION)

        # 父令牌有 billing:read，但 orders->billing 边只允许 billing:read；
        # 构造父令牌含 orders:read 的 hop1，再请求边不允许的 scope。
        h1 = self.hop1()
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=h1["token"],
                caller="acme-orders",
                target="acme-billing",
                requested_scopes=["billing:read", "orders:read"],  # 边不允许 orders:read
                request_id="req-scope-3",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.SCOPE_ESCALATION)
        self.assertEqual(ctx.exception.evidence["added"], ["orders:read"])

    def test_empty_and_non_string_scopes_rejected(self):
        root = self.mint_root()
        for bad in ([], [""]):
            with self.assertRaises(TokenError) as ctx:
                self.service.exchange(
                    parent_token=root["token"],
                    caller="acme-gateway",
                    target="acme-orders",
                    requested_scopes=bad,
                    request_id="req-scope-bad",
                )
            self.assertEqual(ctx.exception.code, ErrorCode.INVALID_CLAIM)


class TestExpiryRules(ServiceFixture):
    def test_expiry_cannot_be_extended(self):
        h1 = self.hop1()
        parent_exp = h1["payload"]["exp"]
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=h1["token"],
                caller="acme-orders",
                target="acme-billing",
                requested_scopes=["billing:read"],
                requested_expiry=parent_exp + 1,
                request_id="req-exp-1",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.EXPIRY_EXTENDED)

    def test_shorter_expiry_allowed_and_default_inherits(self):
        h1 = self.hop1()
        shorter = self.service.exchange(
            parent_token=h1["token"],
            caller="acme-orders",
            target="acme-billing",
            requested_scopes=["billing:read"],
            requested_expiry=h1["payload"]["exp"] - 60,
            request_id="req-exp-2",
        )
        self.assertEqual(shorter["payload"]["exp"], h1["payload"]["exp"] - 60)

        # 不给 requested_expiry 时默认沿用父 exp。
        h1b = self.hop1(self.mint_root(), request_id="req-h1b")
        inherited = self.service.exchange(
            parent_token=h1b["token"],
            caller="acme-orders",
            target="acme-billing",
            requested_scopes=["billing:read"],
            request_id="req-exp-3",
        )
        self.assertEqual(inherited["payload"]["exp"], h1b["payload"]["exp"])

    def test_expired_parent_rejected(self):
        root = self.mint_root()
        self.clock.advance(3601)
        with self.assertRaises(TokenError) as ctx:
            self.service.verify_online(root["token"], caller="acme-gateway")
        self.assertEqual(ctx.exception.code, ErrorCode.TOKEN_EXPIRED)
        self.assertLessEqual(ctx.exception.evidence["exp"], ctx.exception.evidence["now"])

    def test_new_expiry_in_past_rejected(self):
        h1 = self.hop1()
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=h1["token"],
                caller="acme-orders",
                target="acme-billing",
                requested_scopes=["billing:read"],
                requested_expiry=FROZEN_NOW,
                request_id="req-exp-4",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.TOKEN_EXPIRED)


class TestChainDepthAndCycle(ServiceFixture):
    def _chain_mint(self):
        return self.service.mint(
            tenant="t-chain", kid="k1", issuer="chain-svc-0",
            subject="u-chain", audience="chain-svc-0",
            scopes=["data:read"], ttl_seconds=7200,
        )

    def _hop(self, parent, i, request_id):
        return self.service.exchange(
            parent_token=parent["token"],
            caller=f"chain-svc-{i}",
            target=f"chain-svc-{i + 1}",
            requested_scopes=["data:read"],
            request_id=request_id,
        )

    def test_four_hops_allowed_fifth_rejected(self):
        token = self._chain_mint()
        for i in range(4):
            token = self._hop(token, i, f"req-chain-{i}")
        self.assertEqual(token["payload"]["act"], [f"chain-svc-{i}" for i in range(4)])
        self.assertEqual(token["depth"], 4)

        with self.assertRaises(TokenError) as ctx:
            self._hop(token, 4, "req-chain-4")
        self.assertEqual(ctx.exception.code, ErrorCode.CHAIN_TOO_LONG)
        self.assertEqual(ctx.exception.evidence["length_after"], 5)

    def test_cycle_rejected_when_target_already_in_chain(self):
        token = self._chain_mint()
        t1 = self._hop(token, 0, "req-c1")
        t2 = self._hop(t1, 1, "req-c2")
        t3 = self._hop(t2, 2, "req-c3")  # aud=chain-svc-3, act=[0,1,2]
        # 回到 chain-svc-2（已在链上）。
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=t3["token"],
                caller="chain-svc-3",
                target="chain-svc-2",
                requested_scopes=["data:read"],
                request_id="req-cycle",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.CHAIN_CYCLE)
        self.assertEqual(ctx.exception.evidence["target"], "chain-svc-2")

    def test_caller_already_in_actor_chain_rejected(self):
        # 畸形但签名合法的令牌：aud=chain-svc-2，而 act 中已包含 chain-svc-2，
        # 若允许交换则调用者会被再次追加 -> 成环，必须在边检查前拒绝。
        from solution.token import build_header, encode_token
        key = self.registry.get_key("t-chain", "k1")
        payload = {
            "iss": "chain-svc-1",
            "sub": "u-chain",
            "act": ["chain-svc-0", "chain-svc-2"],  # chain-svc-2 已在链上
            "aud": "chain-svc-2",
            "scp": ["data:read"],
            "exp": FROZEN_NOW + 3600,
            "jti": "cycle-caller-1",
            "root": "cycle-caller-1",
        }
        token = encode_token(build_header("t-chain", "k1"), payload, key)
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=token,
                caller="chain-svc-2",
                target="chain-svc-3",
                requested_scopes=["data:read"],
                request_id="req-caller-cycle",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.CHAIN_CYCLE)
        self.assertEqual(ctx.exception.evidence["caller"], "chain-svc-2")


class TestCrossTenant(ServiceFixture):
    def test_cross_tenant_presentation_rejected(self):
        globex = self.service.mint(
            tenant="t-globex", kid="k1", issuer="globex-idp",
            subject="u-g", audience="globex-gateway",
            scopes=["orders:read"], ttl_seconds=1800,
        )
        with self.assertRaises(TokenError) as ctx:
            self.service.verify_online(globex["token"], caller="acme-gateway")
        # 受众先不匹配；无论顺序如何，都绝不能验证通过。
        self.assertIn(
            ctx.exception.code,
            (ErrorCode.AUDIENCE_MISMATCH, ErrorCode.TENANT_MISMATCH),
        )

    def test_same_kid_different_tenant_key_fails_signature(self):
        acme_key = self.registry.get_key("t-acme", "k1")
        globex_key = self.registry.get_key("t-globex", "k1")
        self.assertNotEqual(acme_key, globex_key)

        payload = {
            "iss": "acme-idp", "sub": "u1", "act": [], "aud": "acme-gateway",
            "scp": ["orders:read"], "exp": FROZEN_NOW + 600,
            "jti": "forge-1", "root": "forge-1", "_tenant": "t-acme",
        }
        forged = craft_mod.craft_cross_tenant_signed(
            payload,
            signed_tenant="t-globex",
            signed_kid="k1",
            foreign_key_material=globex_key,
        )
        with self.assertRaises(TokenError) as ctx:
            self.service.verify_online(forged, caller="acme-gateway")
        self.assertEqual(ctx.exception.code, ErrorCode.BAD_SIGNATURE)

    def test_cross_tenant_edge_rejected(self):
        root = self.mint_root()
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=root["token"],
                caller="acme-gateway",
                target="globex-orders",
                requested_scopes=["orders:read"],
                request_id="req-xt-1",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.TENANT_MISMATCH)

    def test_unknown_tenant_and_key(self):
        with self.assertRaises(TokenError) as ctx:
            self.service.mint(
                tenant="t-unknown", kid="k1", issuer="acme-idp",
                subject="u", audience="acme-gateway",
                scopes=["orders:read"], ttl_seconds=60,
            )
        self.assertEqual(ctx.exception.code, ErrorCode.UNKNOWN_TENANT)

        with self.assertRaises(TokenError) as ctx:
            self.service.mint(
                tenant="t-acme", kid="k-unknown", issuer="acme-idp",
                subject="u", audience="acme-gateway",
                scopes=["orders:read"], ttl_seconds=60,
            )
        self.assertEqual(ctx.exception.code, ErrorCode.UNKNOWN_KEY)


if __name__ == "__main__":
    unittest.main()
