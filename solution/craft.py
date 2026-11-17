"""测试专用令牌伪造工具（不参与正常业务路径）。

用于在 cases.json / 测试中构造“必须被拒绝”的畸形或越权令牌，
每个函数都只做局部篡改，其余部分保持合法，使拒绝原因可精确归因。
"""

from __future__ import annotations

import base64
import json

from .encoding import b64url_encode, canonical_dumps
from .token import ALGORITHM, TOKEN_TYPE, build_header, compute_signature


def _seg(raw: bytes) -> str:
    return b64url_encode(raw)


def craft_signed(
    header: dict,
    payload: dict,
    key_material: bytes,
    *,
    sign: bool = True,
    signature_override: bytes | None = None,
) -> str:
    header_seg = _seg(canonical_dumps(header))
    payload_seg = _seg(canonical_dumps(payload))
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    if signature_override is not None:
        sig = signature_override
    elif sign:
        sig = compute_signature(signing_input, key_material)
    else:
        sig = b"\x00" * 32
    return f"{header_seg}.{payload_seg}.{_seg(sig)}"


def craft_with_remote_key_header(payload: dict, key_material: bytes) -> str:
    """携带 jku 远程密钥地址的令牌——头解析阶段即拒绝。"""
    header = dict(build_header(payload.get("_tenant", "t-acme"), "k1"))
    header["jku"] = "https://keys.example.invalid/keys.json"
    payload = {k: v for k, v in payload.items() if not k.startswith("_")}
    return craft_signed(header, payload, key_material)


def craft_unknown_algorithm(payload: dict, key_material: bytes, *, alg: str = "RS256") -> str:
    header = {"alg": alg, "typ": TOKEN_TYPE, "kid": "k1", "tenant": payload["_tenant"]}
    payload = {k: v for k, v in payload.items() if not k.startswith("_")}
    # 仍用 HMAC 签名，证明拒绝原因是算法白名单而非签名。
    return craft_signed(header, payload, key_material)


def craft_duplicate_json_key(payload: dict, key_material: bytes) -> str:
    """载荷中手工放入重复 JSON 键（规范化编码器无法产生，只能手工拼字节）。"""
    header_seg = _seg(canonical_dumps(build_header(payload["_tenant"], "k1")))
    clean = {k: v for k, v in payload.items() if not k.startswith("_")}
    duplicated = dict(clean)
    # 在末尾再拼一个重复的 aud 键，json 模块不支持，手工构造字节串。
    base = json.dumps(duplicated, sort_keys=True, separators=(",", ":"))
    base = base[:-1] + ',"aud":"evil-svc"}'
    payload_seg = _seg(base.encode("utf-8"))
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    sig = _seg(compute_signature(signing_input, key_material))
    return f"{header_seg}.{payload_seg}.{sig}"


def craft_non_canonical_b64(payload: dict, key_material: bytes) -> str:
    """签名段使用带 '=' 填充的非规范 base64url。"""
    header_seg = _seg(canonical_dumps(build_header(payload["_tenant"], "k1")))
    clean = {k: v for k, v in payload.items() if not k.startswith("_")}
    payload_seg = _seg(canonical_dumps(clean))
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    sig = compute_signature(signing_input, key_material)
    padded = base64.urlsafe_b64encode(sig).decode("ascii")  # 含 '='
    return f"{header_seg}.{payload_seg}.{padded}"


def craft_wrong_signature(payload: dict, key_material: bytes) -> str:
    """结构合法但签名被全 0 覆盖。"""
    clean = {k: v for k, v in payload.items() if not k.startswith("_")}
    return craft_signed(
        build_header(payload["_tenant"], "k1"),
        clean,
        key_material,
        signature_override=b"\x00" * 32,
    )


def craft_tampered_audience(payload: dict, key_material: bytes, *, new_aud: str) -> str:
    """签名后篡改 aud 且不重新签名 -> BAD_SIGNATURE（证明签名绑定全部声明）。"""
    clean = {k: v for k, v in payload.items() if not k.startswith("_")}
    token = craft_signed(build_header(payload["_tenant"], "k1"), clean, key_material)
    header_seg, payload_seg, sig_seg = token.split(".")
    tampered = dict(clean)
    tampered["aud"] = new_aud
    tampered_seg = _seg(canonical_dumps(tampered))
    return f"{header_seg}.{tampered_seg}.{sig_seg}"


def craft_cross_tenant_signed(
    payload: dict,
    *,
    signed_tenant: str,
    signed_kid: str,
    foreign_key_material: bytes,
) -> str:
    """跨租户同 kid 攻击：头声明受害租户/kid，却用另一租户的同 kid 密钥签名。

    受害租户按 (tenant, kid) 解析到的是自己的密钥，HMAC 必然不匹配 ->
    BAD_SIGNATURE，证明 kid 不是全局密钥标识，租户隔离无法被同名 kid 绕过。
    """
    clean = {k: v for k, v in payload.items() if not k.startswith("_")}
    # 头仍指向载荷声明的受害租户与同名 kid。
    header = build_header(payload["_tenant"], signed_kid)
    return craft_signed(header, clean, foreign_key_material)
