"""base64url 严格编解码与规范化 JSON（RFC 8785 风格的确定性子集）。

规范化签名表示固定为：
  json.dumps(obj, ensure_ascii=False, sort_keys=True,
             separators=(",", ":"), allow_nan=False)
即键按 UTF-16 码元排序、无多余空白、不允许 NaN/Infinity。
所有参与 HMAC 的字节都是该字符串的 UTF-8 编码。
"""

from __future__ import annotations

import base64
import json

from .errors import ErrorCode, TokenError


def b64url_encode(raw: bytes) -> str:
    """无填充 base64url 编码。"""
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str, *, what: str = "segment") -> bytes:
    """严格无填充 base64url 解码。

    明确拒绝：
    - 非 ASCII 字符、空白；
    - 填充 '='；
    - 非字母表字符（标准 base64 的 '+' '/' 也拒绝）；
    - 长度导致的非法尾块。
    """
    if not segment:
        raise TokenError(
            ErrorCode.MALFORMED_TOKEN, f"空的 {what}", {"segment": what}
        )
    if not segment.isascii() or any(ch.isspace() for ch in segment):
        raise TokenError(
            ErrorCode.MALFORMED_TOKEN,
            f"{what} 含非 ASCII 或空白字符",
            {"segment": what, "reason": "non_ascii_or_whitespace"},
        )
    if "=" in segment:
        raise TokenError(
            ErrorCode.MALFORMED_TOKEN,
            f"{what} 不允许 base64 填充 '='",
            {"segment": what, "reason": "padding_forbidden"},
        )
    # base64url 字母表：A-Z a-z 0-9 - _
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    illegal = sorted({ch for ch in segment if ch not in allowed})
    if illegal:
        raise TokenError(
            ErrorCode.MALFORMED_TOKEN,
            f"{what} 含 base64url 字母表之外的字符（标准 base64 的 +/ 亦拒绝）",
            {"segment": what, "illegal_chars": illegal},
        )
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(segment + padding)
    except Exception as exc:  # pragma: no cover - 上面的检查已覆盖绝大多数情况
        raise TokenError(
            ErrorCode.MALFORMED_TOKEN,
            f"{what} 尾块非法",
            {"segment": what, "reason": "bad_tail"},
        ) from exc


class _RejectDuplicates(dict):
    """object_pairs_hook：同一对象层级出现重复键即拒绝。"""

    def __init__(self, pairs):
        super().__init__()
        for key, value in pairs:
            if key in self:
                raise TokenError(
                    ErrorCode.DUPLICATE_JSON_KEY,
                    f"JSON 对象存在重复键: {key!r}",
                    {"duplicate_key": key},
                )
            self[key] = value


def canonical_dumps(obj) -> bytes:
    """规范化 JSON 序列化，返回 UTF-8 字节，作为 HMAC 输入。"""
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def json_decode_checked(raw: bytes, *, what: str):
    """严格 JSON 解码：拒绝重复键；只允许对象/数组顶层由调用方再约束。"""
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_RejectDuplicates)
    except TokenError:
        raise
    except UnicodeDecodeError as exc:
        raise TokenError(ErrorCode.MALFORMED_TOKEN, f"{what} 不是合法 UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise TokenError(
            ErrorCode.MALFORMED_TOKEN,
            f"{what} 不是合法 JSON: {exc.msg}",
            {"position": exc.pos},
        ) from exc
