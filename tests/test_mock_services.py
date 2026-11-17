"""本机模拟服务 LocalService 的调用语义测试。"""

from __future__ import annotations

from solution.mock_services import LocalService

from tests._fixture import ServiceFixture


class TestLocalService(ServiceFixture):
    def test_service_identity_is_bound_to_caller(self):
        gateway = LocalService("acme-gateway", "t-acme", self.service)
        orders = LocalService("acme-orders", "t-acme", self.service)

        root = self.mint_root()  # aud=acme-gateway

        # 网关以自身身份完成第一跳。
        h1 = gateway.exchange(
            parent_token=root["token"],
            target="acme-orders",
            requested_scopes=["billing:read", "orders:read"],
            request_id="req-ms-1",
        )
        self.assertEqual(h1["payload"]["aud"], "acme-orders")

        # orders 验证成功；其他身份验证失败（受众绑定由服务层保证）。
        self.assertEqual(orders.verify(h1["token"])["valid"], True)
        wrong = LocalService("acme-billing", "t-acme", self.service)
        rejected = wrong.safe_verify(h1["token"])
        self.assertEqual(rejected["status"], "rejected")
        self.assertEqual(rejected["error_code"], "AUDIENCE_MISMATCH")

    def test_safe_exchange_returns_structured_rejection(self):
        gateway = LocalService("acme-gateway", "t-acme", self.service)
        root = self.mint_root()
        out = gateway.safe_exchange(
            parent_token=root["token"],
            target="acme-inventory",  # 未注册边
            requested_scopes=["orders:read"],
            request_id="req-ms-2",
        )
        self.assertEqual(out["status"], "rejected")
        self.assertEqual(out["error_code"], "EDGE_NOT_ALLOWED")
        self.assertTrue(out["evidence"])

    def test_safe_exchange_success_carries_ok_status(self):
        gateway = LocalService("acme-gateway", "t-acme", self.service)
        root = self.mint_root()
        out = gateway.safe_exchange(
            parent_token=root["token"],
            target="acme-orders",
            requested_scopes=["orders:read"],
            request_id="req-ms-3",
        )
        self.assertEqual(out["status"], "ok")
        self.assertFalse(out["replayed"])
        self.assertEqual(out["payload"]["act"], ["acme-gateway"])


if __name__ == "__main__":
    unittest.main()
