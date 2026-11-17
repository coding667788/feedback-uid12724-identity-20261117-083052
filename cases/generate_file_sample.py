"""生成离线二进制样例 samples/token_sample.bin。

演示 cases.json 可用 {"$file": ...} 引用项目内源文件/二进制样例：
本脚本直接用注册表密钥离线铸造一枚结构合法的令牌并写入文本文件，
cases 中的 verify_from_file 用例读取它并在线验证。
"""

from __future__ import annotations

import json
from pathlib import Path

from solution.encoding import b64url_decode
from solution.registry import Registry
from solution.token import build_header, encode_token

FROZEN_NOW = 1_700_000_000


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    registry = Registry.load(root / "samples" / "registry.json")
    key = registry.get_key("t-acme", "k1")
    payload = {
        "iss": "acme-idp",
        "sub": "user-7788",
        "act": [],
        "aud": "acme-gateway",
        "scp": ["orders:read", "orders:write"],
        "exp": FROZEN_NOW + 3600,
        "jti": "file-sample-jti-0001",
        "root": "file-sample-jti-0001",
    }
    token = encode_token(build_header("t-acme", "k1"), payload, key)
    out = root / "samples" / "token_sample.bin"
    out.write_text(token, encoding="utf-8")
    meta = root / "samples" / "token_sample.meta.json"
    with meta.open("w", encoding="utf-8") as fh:
        json.dump(
            {"note": "token_sample.bin 是无换行的 HST1 令牌文本", "payload": payload},
            fh,
            ensure_ascii=False,
            indent=2,
        )
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
