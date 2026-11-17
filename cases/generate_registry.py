"""生成样例注册表 samples/registry.json（固定种子，可重放）。

密钥材料以无填充 base64url 存放在注册表内；仅用于本机模拟，
两个租户刻意使用相同 kid（k1）以覆盖“跨租户同 kid”验收场景。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from solution.encoding import b64url_encode


def key_material(seed: str) -> bytes:
    return hashlib.sha256(("hst1-sample-key|" + seed).encode("utf-8")).digest()


def build_registry() -> dict:
    tenants = {
        "t-acme": {
            "keys": [
                {
                    "kid": "k1",
                    "material_b64url": b64url_encode(key_material("t-acme/k1")),
                }
            ],
            "services": {
                "acme-idp": {"display_name": "Acme 身份发行服务"},
                "acme-gateway": {"display_name": "Acme 边缘网关"},
                "acme-orders": {"display_name": "Acme 订单服务"},
                "acme-billing": {"display_name": "Acme 计费服务"},
                "acme-inventory": {"display_name": "Acme 库存服务"},
            },
        },
        "t-globex": {
            # 刻意与 t-acme 使用相同 kid=k1，但密钥材料不同。
            "keys": [
                {
                    "kid": "k1",
                    "material_b64url": b64url_encode(key_material("t-globex/k1")),
                }
            ],
            "services": {
                "globex-idp": {"display_name": "Globex 身份发行服务"},
                "globex-gateway": {"display_name": "Globex 网关"},
                "globex-orders": {"display_name": "Globex 订单服务"},
            },
        },
        "t-chain": {
            "keys": [
                {
                    "kid": "k1",
                    "material_b64url": b64url_encode(key_material("t-chain/k1")),
                }
            ],
            "services": {f"chain-svc-{i}": {"display_name": f"链式服务 {i}"}
                         for i in range(6)},
        },
    }

    edges = [
        # t-acme 合法链：gateway -> orders -> billing
        {
            "tenant": "t-acme",
            "from": "acme-gateway",
            "to": "acme-orders",
            "scopes": ["orders:read", "orders:write", "billing:read"],
        },
        {
            "tenant": "t-acme",
            "from": "acme-orders",
            "to": "acme-billing",
            "scopes": ["billing:read"],
        },
        # 混淆代理场景所需：orders 未被允许直接换发 inventory
        # （不注册 acme-orders -> acme-inventory 即构成拒绝证据）
        # t-globex 内部合法边
        {
            "tenant": "t-globex",
            "from": "globex-gateway",
            "to": "globex-orders",
            "scopes": ["orders:read"],
        },
        # t-chain：注册 5 条边，使第 5 跳在委托深度规则处被拒绝
        *[
            {
                "tenant": "t-chain",
                "from": f"chain-svc-{i}",
                "to": f"chain-svc-{i + 1}",
                "scopes": ["data:read"],
            }
            for i in range(5)
        ],
    ]
    return {"version": 1, "tenants": tenants, "edges": edges}


def main() -> None:
    out = Path(__file__).resolve().parent.parent / "samples" / "registry.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        json.dump(build_registry(), fh, ensure_ascii=False, indent=2)
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
