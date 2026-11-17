"""多进程测试 worker（由 test_concurrency_multiprocess / test_revocation_restart 调起）。

以独立操作系统进程打开同一个 SQLite 文件，证明交换去重与撤销语义
不是单进程内存行为。支持 ``python -I`` 隔离模式运行：自行把项目根
插入 sys.path，不依赖 PYTHONPATH。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from solution.errors import TokenError  # noqa: E402
from solution.registry import Registry  # noqa: E402
from solution.service import TokenService  # noqa: E402
from solution.store import Store  # noqa: E402
from solution.timeutil import Clock, IdGenerator  # noqa: E402

FROZEN_NOW = 1_700_000_000


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--registry", required=True)
    parser.add_argument("--mode", choices=("exchange", "revoke", "verify"), required=True)
    parser.add_argument("--token")
    parser.add_argument("--request-id")
    parser.add_argument("--jti")
    parser.add_argument("--caller", default="acme-gateway")
    parser.add_argument("--target", default="acme-orders")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    registry = Registry.load(args.registry)
    store = Store(args.db)
    service = TokenService(
        registry, store, Clock(fixed=FROZEN_NOW), IdGenerator(b"mp-worker-seed")
    )
    result: dict
    try:
        if args.mode == "exchange":
            data = service.exchange(
                parent_token=args.token,
                caller=args.caller,
                target=args.target,
                requested_scopes=["orders:read"],
                request_id=args.request_id,
            )
            result = {"status": "ok", "jti": data["jti"], "token": data["token"],
                      "replayed": data.get("replayed", False)}
        elif args.mode == "verify":
            data = service.verify_online(args.token, caller=args.caller)
            result = {"status": "ok", "jti": data["payload"]["jti"]}
        else:
            data = service.revoke(args.jti, reason="mp-worker-revoke")
            result = {"status": "ok", "revoked": data["revoked"], "jti": args.jti}
    except TokenError as exc:
        result = {"status": "rejected", "error_code": exc.code,
                  "message": exc.message, "evidence": exc.evidence}
    finally:
        store.close()

    Path(args.out).write_text(json.dumps(result, ensure_ascii=False), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
