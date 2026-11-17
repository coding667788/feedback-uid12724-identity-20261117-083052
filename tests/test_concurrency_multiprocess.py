"""多进程并发测试：独立 OS 进程 + 同一 SQLite 文件。

覆盖：
- 多进程同时交换同一 (root_jti, target_aud)：仅一个成功，其余 DUPLICATE_EXCHANGE；
- 多进程同 request_id 重试：全部成功且返回同一令牌；
- 一个进程撤销祖先，另一个进程重开连接后在线验证立即失效。
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from tests._fixture import FROZEN_NOW, ServiceFixture

WORKER = Path(__file__).resolve().parent / "_mp_worker.py"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
# -I 隔离模式下显式提供项目根；worker 自身也会把项目根插入 sys.path。
WORKER_ENV = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT)}


class TestMultiProcess(ServiceFixture):
    def _run_worker(self, args: list[str]) -> dict:
        out_file = self.tmp / f"out-{abs(hash(tuple(args)))%10_000_000}.json"
        cmd = [sys.executable, "-I", str(WORKER), "--out", str(out_file), *args]
        proc = subprocess.run(
            cmd,
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=60,
            env=WORKER_ENV,
        )
        self.assertEqual(
            proc.returncode, 0,
            msg=f"worker 失败: {proc.stderr}\ncmd={cmd}",
        )
        return json.loads(out_file.read_text(encoding="utf-8"))

    def test_concurrent_exchange_single_winner_across_processes(self):
        root = self.mint_root()
        processes = 5
        procs: list[subprocess.Popen] = []
        out_files = []
        for i in range(processes):
            out_file = self.tmp / f"mp-exchange-{i}.json"
            out_files.append(out_file)
            cmd = [
                sys.executable, "-I", str(WORKER),
                "--db", str(self.db_path),
                "--registry", str(self.registry_path),
                "--mode", "exchange",
                "--token", root["token"],
                "--request-id", f"req-mp-{i}",
                "--out", str(out_file),
            ]
            procs.append(subprocess.Popen(cmd, cwd=PROJECT_ROOT, env=WORKER_ENV))
        for p in procs:
            p.wait(timeout=60)
            self.assertEqual(p.returncode, 0)

        outcomes = [json.loads(f.read_text(encoding="utf-8")) for f in out_files]
        ok = [o for o in outcomes if o["status"] == "ok"]
        rejected = [o for o in outcomes if o["status"] == "rejected"]
        self.assertEqual(len(ok), 1)
        self.assertEqual(len(rejected), processes - 1)
        self.assertTrue(
            all(o["error_code"] == "DUPLICATE_EXCHANGE" for o in rejected)
        )
        # 数据库中该 (root, target) 只有一条交换记录。
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM exchanges WHERE root_jti = ? AND target_aud = ?",
            (root["jti"], "acme-orders"),
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 1)

    def test_same_request_id_replay_across_processes(self):
        root = self.mint_root()
        out_files = []
        procs = []
        for i in range(3):
            out_file = self.tmp / f"mp-replay-{i}.json"
            out_files.append(out_file)
            cmd = [
                sys.executable, "-I", str(WORKER),
                "--db", str(self.db_path),
                "--registry", str(self.registry_path),
                "--mode", "exchange",
                "--token", root["token"],
                "--request-id", "req-mp-shared",
                "--out", str(out_file),
            ]
            procs.append(subprocess.Popen(cmd, cwd=PROJECT_ROOT, env=WORKER_ENV))
        for p in procs:
            p.wait(timeout=60)
            self.assertEqual(p.returncode, 0)

        outcomes = [json.loads(f.read_text(encoding="utf-8")) for f in out_files]
        self.assertTrue(all(o["status"] == "ok" for o in outcomes))
        self.assertEqual(len({o["jti"] for o in outcomes}), 1)
        self.assertEqual(len({o["token"] for o in outcomes}), 1)

    def test_revocation_visible_in_another_process(self):
        root = self.mint_root()
        h1 = self.hop1(root, request_id="req-mp-rev-1")
        h2 = self.hop2(h1, request_id="req-mp-rev-2")

        # 进程 A：撤销 hop1。
        revoke_out = self.tmp / "mp-revoke.json"
        cmd = [
            sys.executable, "-I", str(WORKER),
            "--db", str(self.db_path),
            "--registry", str(self.registry_path),
            "--mode", "revoke",
            "--jti", h1["jti"],
            "--out", str(revoke_out),
        ]
        proc = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, env=WORKER_ENV)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertTrue(json.loads(revoke_out.read_text())["revoked"])

        # 进程 B：独立连接验证 hop2 -> 祖先撤销生效。
        verify_out = self.tmp / "mp-verify.json"
        cmd = [
            sys.executable, "-I", str(WORKER),
            "--db", str(self.db_path),
            "--registry", str(self.registry_path),
            "--mode", "verify",
            "--token", h2["token"],
            "--caller", "acme-billing",
            "--out", str(verify_out),
        ]
        proc = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, env=WORKER_ENV)
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        result = json.loads(verify_out.read_text())
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["error_code"], "ANCESTOR_REVOKED")
        self.assertEqual(result["evidence"]["revoked_ancestor"], h1["jti"])


if __name__ == "__main__":
    unittest.main()
