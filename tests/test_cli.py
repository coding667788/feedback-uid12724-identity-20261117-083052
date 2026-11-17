"""CLI 端到端测试：运行 cases/cases.json 并逐条断言验收场景结果。"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CASES = PROJECT_ROOT / "cases" / "cases.json"

# 每个用例的期望：(status, error_code 或 None)
EXPECTED = {
    # 合法两跳链
    "mint_root": ("ok", None),
    "hop1_gateway_to_orders": ("ok", None),
    "hop1_verify_ok": ("ok", None),
    "hop2_orders_to_billing": ("ok", None),
    "hop2_verify_ok": ("ok", None),
    # 混淆代理
    "confused_deputy_wrong_caller": ("rejected", "AUDIENCE_MISMATCH"),
    "confused_deputy_unregistered_edge": ("rejected", "EDGE_NOT_ALLOWED"),
    # scope 扩大 / 过期延长
    "scope_escalation": ("rejected", "SCOPE_ESCALATION"),
    "expiry_extension": ("rejected", "EXPIRY_EXTENDED"),
    # 幂等 / 去重 / 冲突
    "retry_same_request_id": ("ok", None),
    "duplicate_exchange_new_request": ("rejected", "DUPLICATE_EXCHANGE"),
    "request_id_conflict": ("rejected", "REQUEST_CONFLICT"),
    # 跨租户同 kid
    "mint_globex_root": ("ok", None),
    "cross_tenant_presentation": ("rejected", "AUDIENCE_MISMATCH"),
    "cross_tenant_forged_signature": ("ok", None),
    "cross_tenant_forged_verify": ("rejected", "BAD_SIGNATURE"),
    # 封装层拒绝
    "craft_remote_key_header": ("ok", None),
    "remote_key_header_verify": ("rejected", "INVALID_HEADER"),
    "craft_unknown_alg": ("ok", None),
    "unknown_alg_verify": ("rejected", "UNKNOWN_ALGORITHM"),
    "craft_dup_key": ("ok", None),
    "dup_key_verify": ("rejected", "DUPLICATE_JSON_KEY"),
    "craft_bad_b64": ("ok", None),
    "bad_b64_verify": ("rejected", "MALFORMED_TOKEN"),
    "craft_bad_sig": ("ok", None),
    "bad_sig_verify": ("rejected", "BAD_SIGNATURE"),
    "craft_tampered_aud": ("ok", None),
    "tampered_aud_verify": ("rejected", "BAD_SIGNATURE"),
    # $file 二进制样例
    "verify_from_file": ("ok", None),
    # 深度链：4 跳允许，第 5 跳与环拒绝
    "chain_mint": ("ok", None),
    "chain_hop1": ("ok", None),
    "chain_hop2": ("ok", None),
    "chain_hop3": ("ok", None),
    "chain_hop4": ("ok", None),
    "chain_hop5_rejected": ("rejected", "CHAIN_TOO_LONG"),
    "chain_cycle_rejected": ("rejected", "CHAIN_CYCLE"),
    # 祖先撤销及在线失效
    "revoke_hop1": ("ok", None),
    "descendant_after_revoke": ("rejected", "ANCESTOR_REVOKED"),
    "exchange_after_revoke": ("rejected", "ANCESTOR_REVOKED"),
    # 时钟与过期
    "advance_past_expiry": ("ok", None),
    "expired_verify": ("rejected", "TOKEN_EXPIRED"),
}


class TestCliEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        cls.tmp = Path(cls._tmp.name)
        # 复制 cases 与 samples，保证测试写入不污染工作区样例。
        shutil.copytree(PROJECT_ROOT / "cases", cls.tmp / "cases")
        shutil.copytree(PROJECT_ROOT / "samples", cls.tmp / "samples")
        cls.input_path = cls.tmp / "cases" / "cases.json"
        cls.output_path = cls.tmp / "out" / "result.json"

        spec = json.loads(cls.input_path.read_text(encoding="utf-8"))
        spec["db_path"] = str(cls.tmp / "runtime" / "cli.db")
        cls.input_path.write_text(
            json.dumps(spec, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        # -I 忽略 PYTHONPATH，使用项目根的隔离模式包装器 run_solution.py。
        proc = subprocess.run(
            [
                sys.executable, "-I",
                str(PROJECT_ROOT / "run_solution.py"),
                "--input", str(cls.input_path),
                "--output", str(cls.output_path),
            ],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        cls.proc = proc
        cls.result = json.loads(cls.output_path.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_process_exits_zero(self):
        self.assertEqual(
            self.proc.returncode, 0, msg=f"stderr={self.proc.stderr}"
        )

    def test_every_acceptance_case_has_expected_status(self):
        by_id = {r["id"]: r for r in self.result["results"]}
        self.assertEqual(
            set(by_id), set(EXPECTED),
            msg="cases.json 用例与测试期望表不一致",
        )
        for cid, (status, error_code) in EXPECTED.items():
            with self.subTest(case=cid):
                row = by_id[cid]
                self.assertEqual(row["status"], status)
                if error_code is not None:
                    self.assertEqual(row["error_code"], error_code)

    def test_legal_chain_invariants_in_output(self):
        by_id = {r["id"]: r for r in self.result["results"]}
        root = by_id["mint_root"]
        h1 = by_id["hop1_gateway_to_orders"]
        h2 = by_id["hop2_orders_to_billing"]

        self.assertEqual(h1["payload"]["act"], ["acme-gateway"])
        self.assertEqual(
            h2["payload"]["act"], ["acme-gateway", "acme-orders"]
        )
        self.assertEqual(h2["payload"]["sub"], root["payload"]["sub"])
        self.assertEqual(h1["root_jti"], h2["root_jti"])
        self.assertEqual(h2["payload"]["aud"], "acme-billing")
        self.assertEqual(h2["payload"]["scp"], ["billing:read"])

    def test_retry_returns_identical_token(self):
        by_id = {r["id"]: r for r in self.result["results"]}
        original = by_id["hop2_orders_to_billing"]
        replay = by_id["retry_same_request_id"]
        self.assertTrue(replay["replayed"])
        self.assertEqual(replay["token"], original["token"])
        self.assertEqual(replay["jti"], original["jti"])

    def test_revocation_evidence_names_ancestor(self):
        row = next(
            r for r in self.result["results"] if r["id"] == "descendant_after_revoke"
        )
        hop1 = next(
            r for r in self.result["results"] if r["id"] == "chain_hop1"
        )
        self.assertEqual(row["evidence"]["revoked_ancestor"], hop1["jti"])

    def test_rejections_carry_evidence(self):
        for row in self.result["results"]:
            if row["status"] == "rejected":
                self.assertTrue(row["evidence"], msg=f"{row['id']} 缺少证据")
                self.assertTrue(row["message"])

    def test_summary_counts_match(self):
        summary = self.result["summary"]
        self.assertEqual(
            summary["total"],
            summary["ok"] + summary["rejected"] + summary["other"],
        )
        self.assertEqual(summary["other"], 0)
        self.assertEqual(summary["total"], len(EXPECTED))


if __name__ == "__main__":
    unittest.main()
