"""HST1（HMAC-SHA256 Token, version 1）自定义令牌封装。

线格式（与 JWS 紧凑序列化相似，但本项目自行实现、自行约束）::

    BASE64URL(UTF8(规范化JSON(头))) .
    BASE64URL(UTF8(规范化JSON(载荷))) .
    BASE64URL(HMAC_SHA256(签名输入, 受信密钥))

签名输入 = 头段 + b"." + 载荷段（均为无填充 base64url ASCII）。

头固定且仅允许四个键：alg / typ / kid / tenant。
不允许 jku、jwk、x5u、x5c 等任何远程密钥地址或内联密钥——
密钥只能按 (tenant, kid) 从受信注册表解析。

载荷声明（全部必填）：
    iss   发行服务          str，非空
    sub   原始用户          str，非空，交换中保持不变
    act   委托链 actor_chain list[str]，铸造时为空，每次交换追加调用服务
    aud   受众服务          str，非空，下一跳的调用者必须与之相等
    scp   授权范围          list[str]，非空、去重、字典序排序
    exp   到期时间          int 秒级 Unix 时间戳（不允许 bool）
    jti   本令牌唯一 ID     str，非空
    root  根令牌 jti        str，非空，整棵委托树共用，用于去重与祖先撤销
"""

from __future__ import annotations

import hashlib
import hmac

from .encoding import b64url_decode, b64url_encode, canonical_dumps, json_decode_checked
from .errors import ErrorCode, TokenError

ALGORITHM = "HS256"
TOKEN_TYPE = "HST1"
HEADER_ALLOWED_KEYS = frozenset({"alg", "typ", "kid", "tenant"})
# 显式拒绝的“远程/内联密钥寻址”头参数（出现即 INVALID_HEADER）。
FORBIDDEN_HEADER_KEYS = frozenset(
    {"jku", "jwk", "x5u", "x5c", "x5t", "kid_url", "keyserver", "uri"}
)
PAYLOAD_REQUIRED_KEYS = ("iss", "sub", "act", "aud", "scp", "exp", "jti", "root")
SIGNATURE_LENGTH = 32  # HMAC-SHA256 输出 32 字节


# --------------------------------------------------------------------------- #
# 构造
# --------------------------------------------------------------------------- #
def build_header(tenant: str, kid: str) -> dict:
    return {"alg": ALGORITHM, "typ": TOKEN_TYPE, "kid": kid, "tenant": tenant}


def compute_signature(signing_input: bytes, key_material: bytes) -> bytes:
    return hmac.new(key_material, signing_input, hashlib.sha256).digest()


def encode_token(header: dict, payload: dict, key_material: bytes) -> str:
    """规范化编码并签名，返回线格式字符串。"""
    header_seg = b64url_encode(canonical_dumps(header))
    payload_seg = b64url_encode(canonical_dumps(payload))
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    signature = compute_signature(signing_input, key_material)
    return f"{header_seg}.{payload_seg}.{b64url_encode(signature)}"


# --------------------------------------------------------------------------- #
# 解析与结构化校验（不做注册表/状态校验，签名校验在 service 层完成）
# --------------------------------------------------------------------------- #
def _require_nonempty_str(value, field: str):
    if not isinstance(value, str) or not value:
        raise TokenError(
            ErrorCode.INVALID_CLAIM,
            f"声明 {field!r} 必须是非空字符串",
            {"field": field, "got_type": type(value).__name__},
        )


def _validate_header(header) -> None:
    if not isinstance(header, dict):
        raise TokenError(ErrorCode.INVALID_HEADER, "令牌头必须是 JSON 对象")
    keys = set(header.keys())
    forbidden = keys & FORBIDDEN_HEADER_KEYS
    if forbidden:
        raise TokenError(
            ErrorCode.INVALID_HEADER,
            "令牌头不允许远程密钥地址或内联密钥参数",
            {"forbidden_keys": sorted(forbidden)},
        )
    extra = keys - HEADER_ALLOWED_KEYS
    if extra:
        raise TokenError(
            ErrorCode.INVALID_HEADER,
            "令牌头含未允许的键",
            {"extra_keys": sorted(extra)},
        )
    alg = header.get("alg")
    if alg != ALGORITHM:
        raise TokenError(
            ErrorCode.UNKNOWN_ALGORITHM,
            f"不支持的算法 {alg!r}，本实现只接受 {ALGORITHM}",
            {"received_alg": alg},
        )
    if header.get("typ") != TOKEN_TYPE:
        raise TokenError(
            ErrorCode.INVALID_HEADER,
            f"typ 必须是 {TOKEN_TYPE}",
            {"received_typ": header.get("typ")},
        )
    _require_nonempty_str(header.get("kid"), "header.kid")
    _require_nonempty_str(header.get("tenant"), "header.tenant")


def _validate_payload(payload) -> None:
    if not isinstance(payload, dict):
        raise TokenError(ErrorCode.INVALID_CLAIM, "令牌载荷必须是 JSON 对象")
    missing = [k for k in PAYLOAD_REQUIRED_KEYS if k not in payload]
    if missing:
        raise TokenError(
            ErrorCode.INVALID_CLAIM, "载荷缺少必填声明", {"missing": missing}
        )
    extra = [k for k in payload.keys() if k not in PAYLOAD_REQUIRED_KEYS]
    if extra:
        raise TokenError(
            ErrorCode.INVALID_CLAIM,
            "载荷含未声明的额外键",
            {"extra_keys": sorted(extra)},
        )
    for field in ("iss", "sub", "aud", "jti", "root"):
        _require_nonempty_str(payload[field], field)

    act = payload["act"]
    if not isinstance(act, list) or any(
        not isinstance(x, str) or not x for x in act
    ):
        raise TokenError(
            ErrorCode.INVALID_CLAIM,
            "声明 'act' 必须是非空字符串组成的列表",
        )

    scp = payload["scp"]
    if (
        not isinstance(scp, list)
        or not scp
        or any(not isinstance(x, str) or not x for x in scp)
    ):
        raise TokenError(
            ErrorCode.INVALID_CLAIM,
            "声明 'scp' 必须是非空字符串组成的非空列表",
        )
    if len(set(scp)) != len(scp):
        raise TokenError(ErrorCode.INVALID_CLAIM, "声明 'scp' 不允许重复 scope")
    if scp != sorted(scp):
        raise TokenError(
            ErrorCode.INVALID_CLAIM, "声明 'scp' 必须按字典序规范化排序"
        )

    exp = payload["exp"]
    # bool 是 int 的子类，显式排除，避免 True/False 混入时间戳。
    if not isinstance(exp, int) or isinstance(exp, bool) or exp < 0:
        raise TokenError(
            ErrorCode.INVALID_CLAIM,
            "声明 'exp' 必须是非负整数秒级时间戳",
            {"got_type": type(exp).__name__},
        )


def decode_token(token: str) -> tuple[dict, dict, bytes, bytes]:
    """解析线格式并完成全部无状态结构校验。

    返回 (header, payload, signing_input, signature)。
    签名是否正确、租户/受众/委托链/撤销等有状态校验由 service 层完成。
    """
    if not isinstance(token, str) or not token:
        raise TokenError(
            ErrorCode.MALFORMED_TOKEN, "令牌必须是非空字符串", {"reason": "empty"}
        )
    parts = token.split(".")
    if len(parts) != 3 or any(not seg for seg in parts):
        raise TokenError(
            ErrorCode.MALFORMED_TOKEN,
            "令牌必须恰好包含两个 '.' 分隔的三个非空段",
            {"segments": len(parts), "expected": 3},
        )
    header_seg, payload_seg, signature_seg = parts

    header = json_decode_checked(b64url_decode(header_seg, what="令牌头"), what="令牌头")
    _validate_header(header)

    payload = json_decode_checked(
        b64url_decode(payload_seg, what="令牌载荷"), what="令牌载荷"
    )
    _validate_payload(payload)

    signature = b64url_decode(signature_seg, what="签名段")
    if len(signature) != SIGNATURE_LENGTH:
        raise TokenError(
            ErrorCode.BAD_SIGNATURE,
            f"HMAC-SHA256 签名必须为 {SIGNATURE_LENGTH} 字节",
            {"received_length": len(signature)},
        )

    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    return header, payload, signing_input, signature


def verify_signature(signing_input: bytes, signature: bytes, key_material: bytes) -> None:
    expected = compute_signature(signing_input, key_material)
    if not hmac.compare_digest(expected, signature):
        raise TokenError(
            ErrorCode.BAD_SIGNATURE,
            "HMAC-SHA256 签名校验失败",
            {"algorithm": ALGORITHM, "expected_length": SIGNATURE_LENGTH},
        )
