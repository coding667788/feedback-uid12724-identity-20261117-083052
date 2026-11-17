"""统一错误码与异常定义。

所有安全拒绝路径都返回稳定的字符串错误码（见 README“错误码”章节），
CLI 输出与测试断言均基于这些码，而不是异常文本。
"""

from __future__ import annotations


class ErrorCode:
    # ---- 令牌封装层 ----
    MALFORMED_TOKEN = "MALFORMED_TOKEN"              # 分段数不对 / base64url 不规范
    INVALID_HEADER = "INVALID_HEADER"                # 头字段非法（含远程密钥地址）
    UNKNOWN_ALGORITHM = "UNKNOWN_ALGORITHM"          # 头 alg 不是 HS256
    DUPLICATE_JSON_KEY = "DUPLICATE_JSON_KEY"        # 头或载荷存在重复 JSON 键
    INVALID_CLAIM = "INVALID_CLAIM"                  # 声明缺失/类型/形状不合法
    BAD_SIGNATURE = "BAD_SIGNATURE"                  # HMAC 不匹配
    TOKEN_EXPIRED = "TOKEN_EXPIRED"                  # exp 已过期

    # ---- 注册表 ----
    UNKNOWN_TENANT = "UNKNOWN_TENANT"                # 租户不在受信注册表
    UNKNOWN_KEY = "UNKNOWN_KEY"                       # (tenant, kid) 不存在
    UNKNOWN_SERVICE = "UNKNOWN_SERVICE"              # 服务未注册
    TENANT_MISMATCH = "TENANT_MISMATCH"              # 跨租户调用/交换
    EDGE_NOT_ALLOWED = "EDGE_NOT_ALLOWED"            # 交换边未预注册

    # ---- 委托链与交换约束 ----
    AUDIENCE_MISMATCH = "AUDIENCE_MISMATCH"          # 调用服务不等于原 audience（混淆代理）
    SCOPE_ESCALATION = "SCOPE_ESCALATION"            # 请求 scope 不是原 scope 子集
    EXPIRY_EXTENDED = "EXPIRY_EXTENDED"              # 新 exp 晚于原 exp
    CHAIN_CYCLE = "CHAIN_CYCLE"                      # 委托链成环
    CHAIN_TOO_LONG = "CHAIN_TOO_LONG"                # 超过 4 跳

    # ---- 幂等 / 撤销 / 存储 ----
    REQUEST_CONFLICT = "REQUEST_CONFLICT"            # 同 request_id 不同请求体
    DUPLICATE_EXCHANGE = "DUPLICATE_EXCHANGE"        # 同 (根 jti, 目标) 不同 request_id
    ANCESTOR_REVOKED = "ANCESTOR_REVOKED"            # 任一祖先 jti（含自身）已撤销
    STORE_ERROR = "STORE_ERROR"                      # SQLite 未预期错误


class TokenError(Exception):
    """业务异常：携带稳定错误码、人类可读信息与结构化证据。"""

    def __init__(self, code: str, message: str, evidence: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.evidence = evidence or {}

    def to_dict(self) -> dict:
        return {
            "error_code": self.code,
            "message": self.message,
            "evidence": self.evidence,
        }
