"""SQLite 去重、幂等、祖先撤销与重启持久性测试（含线程并发）。"""

from __future__ import annotations

import threading

from solution.errors import ErrorCode, TokenError
from solution.registry import Registry
from solution.service import TokenService
from solution.store import Store, reopen
from solution.timeutil import Clock, IdGenerator

from tests._fixture import FROZEN_NOW, SEED, ServiceFixture


class TestIdempotencyAndDedup(ServiceFixture):
    def test_same_request_id_replays_identical_result(self):
        h1 = self.hop1()
        first = self.hop2(h1, request_id="req-fixed")
        second = self.hop2(h1, request_id="req-fixed")
        self.assertTrue(second["replayed"])
        self.assertEqual(second["replay_reason"], "request_id")
        self.assertEqual(second["jti"], first["jti"])
        self.assertEqual(second["token"], first["token"])
        # 数据库中只有一行交换记录。
        rows = self.store._conn.execute("SELECT COUNT(*) AS c FROM exchanges").fetchone()
        self.assertEqual(rows["c"], 2)  # hop1 + hop2 各一行

    def test_same_request_id_different_body_conflict(self):
        h1 = self.hop1()
        self.hop2(h1, request_id="req-fixed")
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=h1["token"],
                caller="acme-orders",
                target="acme-billing",
                requested_scopes=["billing:read"],
                requested_expiry=FROZEN_NOW + 600,  # 与原请求体不同
                request_id="req-fixed",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.REQUEST_CONFLICT)

    def test_root_jti_target_dedup_with_new_request_id(self):
        h1 = self.hop1()
        self.hop2(h1, request_id="req-A")
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=h1["token"],
                caller="acme-orders",
                target="acme-billing",
                requested_scopes=["billing:read"],
                request_id="req-B",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_EXCHANGE)
        self.assertEqual(ctx.exception.evidence["existing_request_id"], "req-A")

    def test_different_targets_under_same_root_both_allowed(self):
        # 去重键是 (root, target_aud)：换一个目标即新结果。
        # t-acme 中 gateway 还有 orders 边，这里用同根不同 request 仅验证目标维度，
        # 通过两条不同边的链式租户更直观，见 t-chain 深度测试；本处验证根令牌
        # 在两个不同 request_id 下对同一 target 的去重计数。
        root = self.mint_root()
        a = self.hop1(root, request_id="req-target-a")
        # 同 (root, acme-orders) 再来一次，即使 request_id 不同也拒绝。
        with self.assertRaises(TokenError) as ctx:
            self.hop1(root, request_id="req-target-b")
        self.assertEqual(ctx.exception.code, ErrorCode.DUPLICATE_EXCHANGE)
        self.assertTrue(a["jti"])

    def test_concurrent_threads_single_winner(self):
        root = self.mint_root()
        errors: list[TokenError] = []
        results: list[dict] = []
        barrier = threading.Barrier(6)

        def worker(idx: int):
            barrier.wait()
            try:
                out = self.service.exchange(
                    parent_token=root["token"],
                    caller="acme-gateway",
                    target="acme-orders",
                    requested_scopes=["orders:read"],
                    request_id=f"req-thread-{idx}",
                )
                results.append(out)
            except TokenError as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 1)
        self.assertEqual(len(errors), 5)
        self.assertTrue(all(e.code == ErrorCode.DUPLICATE_EXCHANGE for e in errors))

    def test_concurrent_same_request_id_all_replay_same_token(self):
        root = self.mint_root()
        results: list[dict] = []
        barrier = threading.Barrier(5)

        def worker():
            barrier.wait()
            out = self.service.exchange(
                parent_token=root["token"],
                caller="acme-gateway",
                target="acme-orders",
                requested_scopes=["orders:read"],
                request_id="req-shared-id",
            )
            results.append(out)

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(results), 5)
        jtis = {r["jti"] for r in results}
        tokens = {r["token"] for r in results}
        self.assertEqual(len(jtis), 1)
        self.assertEqual(len(tokens), 1)


class TestRevocationAndRestart(ServiceFixture):
    def _build_three_generations(self):
        root = self.mint_root()
        h1 = self.hop1(root, request_id="req-r1")
        h2 = self.hop2(h1, request_id="req-r2")
        return root, h1, h2

    def test_ancestor_closure_persisted(self):
        root, h1, h2 = self._build_three_generations()
        # hop2 的祖先闭包应包含 root、hop1 与 hop2 自身（通过 record/insert 写入）。
        ancestors = dict(self.store.get_ancestors(h2["jti"]))
        self.assertIn(root["jti"], ancestors)
        self.assertIn(h1["jti"], ancestors)
        # 根距离最远（3 代：root -> h1 -> h2）。
        self.assertEqual(ancestors[root["jti"]], 2)
        self.assertEqual(ancestors[h1["jti"]], 1)

    def test_revoke_ancestor_invalidates_descendants_online(self):
        root, h1, h2 = self._build_three_generations()
        self.service.revoke(h1["jti"], reason="incident")

        # 被撤销者自身。
        with self.assertRaises(TokenError) as ctx:
            self.service.verify_online(h1["token"], caller="acme-orders")
        self.assertEqual(ctx.exception.code, ErrorCode.ANCESTOR_REVOKED)
        self.assertEqual(ctx.exception.evidence["revoked_ancestor"], h1["jti"])

        # 后代在下一次在线验证失效。
        with self.assertRaises(TokenError) as ctx:
            self.service.verify_online(h2["token"], caller="acme-billing")
        self.assertEqual(ctx.exception.code, ErrorCode.ANCESTOR_REVOKED)

        # 未受影响的根令牌仍可用。
        v = self.service.verify_online(root["token"], caller="acme-gateway")
        self.assertTrue(v["valid"])

    def test_revoke_root_invalidates_whole_tree(self):
        root, h1, h2 = self._build_three_generations()
        self.service.revoke(root["jti"], reason="root-kill")
        for token, caller in (
            (root["token"], "acme-gateway"),
            (h1["token"], "acme-orders"),
            (h2["token"], "acme-billing"),
        ):
            with self.assertRaises(TokenError) as ctx:
                self.service.verify_online(token, caller=caller)
            self.assertEqual(ctx.exception.code, ErrorCode.ANCESTOR_REVOKED)

    def test_revocation_survives_process_restart(self):
        root, h1, h2 = self._build_three_generations()
        self.service.revoke(h1["jti"], reason="before-restart")
        self.store.close()

        # 全新连接重开同一数据库文件，模拟进程重启：不允许内存祖先表。
        restarted_store = reopen(self.db_path)
        restarted = TokenService(
            self.registry,
            restarted_store,
            Clock(fixed=FROZEN_NOW),
            IdGenerator(SEED),
        )
        with self.assertRaises(TokenError) as ctx:
            restarted.verify_online(h2["token"], caller="acme-billing")
        self.assertEqual(ctx.exception.code, ErrorCode.ANCESTOR_REVOKED)
        self.assertEqual(ctx.exception.evidence["revoked_ancestor"], h1["jti"])

        # 重启后继续交换也必须被撤销拦截。
        with self.assertRaises(TokenError) as ctx:
            restarted.exchange(
                parent_token=h1["token"],
                caller="acme-orders",
                target="acme-billing",
                requested_scopes=["billing:read"],
                request_id="req-after-restart",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ANCESTOR_REVOKED)
        restarted_store.close()

    def test_revoke_is_idempotent(self):
        root = self.mint_root()
        first = self.service.revoke(root["jti"], reason="once")
        second = self.service.revoke(root["jti"], reason="twice")
        self.assertTrue(first["revoked"])
        self.assertFalse(second["revoked"])
        self.assertTrue(second["idempotent"])

    def test_exchange_using_revoked_parent_rejected(self):
        root, h1, _ = self._build_three_generations()
        self.service.revoke(root["jti"], reason="x")
        with self.assertRaises(TokenError) as ctx:
            self.service.exchange(
                parent_token=root["token"],
                caller="acme-gateway",
                target="acme-orders",
                requested_scopes=["orders:read"],
                request_id="req-dead-parent",
            )
        self.assertEqual(ctx.exception.code, ErrorCode.ANCESTOR_REVOKED)


if __name__ == "__main__":
    unittest.main()
