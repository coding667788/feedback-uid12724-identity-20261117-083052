"""核心业务：令牌铸造、在线验证、受众绑定交换与撤销。

所有安全规则集中在本模块，store 只负责持久化约束：
- 每次交换先在线验证父令牌（签名/受众/委托链/过期/祖先撤销全部生效）；
- 目标服务必须位于预注册交换边，且边 scope 与令牌 scope 同时约束；
- scope 只缩不扩、exp 只短不长、sub 与 root_jti 永不改变；
- actor_chain 追加“调用服务”，最长 4 跳且不得成环；
- 去重键 UNIQUE(root_jti, target_aud)，request_id 唯一且绑定请求体哈希。
"""

from __future__ import annotations

import hashlib
import sqlite3

from .encoding import canonical_dumps
from .errors import ErrorCode, TokenError
from .registry import Registry
from .store import Store
from .timeutil import Clock, IdGenerator
from .token import (
    build_header,
    decode_token,
    encode_token,
    verify_signature,
)

MAX_CHAIN_HOPS = 4


def _request_hash(canonical_request: dict) -> str:
    """请求体指纹：规范化 JSON 的 SHA-256 hex，用于 request_id 冲突判定。"""
    return hashlib.sha256(canonical_dumps(canonical_request)).hexdigest()


class TokenService:
    def __init__(self, registry: Registry, store: Store, clock: Clock, ids: IdGenerator):
        self.registry = registry
        self.store = store
        self.clock = clock
        self.ids = ids

    # ------------------------------------------------------------------ #
    # 铸造初始令牌（模拟受信发行服务，不走交换边）
    # ------------------------------------------------------------------ #
    def mint(
        self,
        *,
        tenant: str,
        kid: str,
        issuer: str,
        subject: str,
        audience: str,
        scopes: list[str],
        ttl_seconds: int,
    ) -> dict:
        if not self.registry.tenant_exists(tenant):
            raise TokenError(
                ErrorCode.UNKNOWN_TENANT, f"租户 {tenant!r} 未注册", {"tenant": tenant}
            )
        # 发行方与受众都必须是该租户内已注册服务。
        issuer_tenant = self.registry.require_service(issuer)
        audience_tenant = self.registry.require_service(audience)
        if issuer_tenant != tenant or audience_tenant != tenant:
            raise TokenError(
                ErrorCode.TENANT_MISMATCH,
                "铸造令牌的发行方/受众必须与租户一致",
                {
                    "tenant": tenant,
                    "issuer_tenant": issuer_tenant,
                    "audience_tenant": audience_tenant,
                },
            )
        key_material = self.registry.get_key(tenant, kid)  # 校验 kid 受信
        scopes = sorted(self._normalize_scopes(scopes))
        if ttl_seconds <= 0:
            raise TokenError(ErrorCode.INVALID_CLAIM, "ttl_seconds 必须为正整数")

        now = self.clock.now()
        jti = self.ids.jti()
        payload = {
            "iss": issuer,
            "sub": subject,
            "act": [],
            "aud": audience,
            "scp": scopes,
            "exp": now + int(ttl_seconds),
            "jti": jti,
            "root": jti,  # 根令牌的 root 指向自身
        }
        token = encode_token(build_header(tenant, kid), payload, key_material)
        # 根令牌自身作为距离 0 的祖先闭包条目，供整棵树撤销查询。
        try:
            self.store.record_token(
                jti=jti,
                root_jti=jti,
                parent_jti=None,
                tenant=tenant,
                aud=audience,
                depth=0,
                created_at=now,
                ancestors=[(jti, 0)],
            )
        except sqlite3.IntegrityError as exc:
            raise TokenError(
                ErrorCode.STORE_ERROR,
                "铸造令牌与既有存储状态冲突（请确认使用全新数据库）",
                {"jti": jti},
            ) from exc
        return {
            "token": token,
            "jti": jti,
            "root_jti": jti,
            "tenant": tenant,
            "kid": kid,
            "header": build_header(tenant, kid),
            "payload": payload,
            "depth": 0,
        }

    # ------------------------------------------------------------------ #
    # 在线验证：无状态密码学/声明校验 + 有状态撤销校验
    # ------------------------------------------------------------------ #
    def verify_online(self, token: str, *, caller: str) -> dict:
        header, payload, signing_input, signature = decode_token(token)
        tenant = header["tenant"]
        kid = header["kid"]

        # 租户与 kid 必须来自受信注册表；令牌头无法指定远程密钥地址。
        key_material = self.registry.get_key(tenant, kid)
        verify_signature(signing_input, signature, key_material)

        now = self.clock.now()
        if payload["exp"] <= now:
            raise TokenError(
                ErrorCode.TOKEN_EXPIRED,
                "令牌已过期",
                {"exp": payload["exp"], "now": now, "jti": payload["jti"]},
            )

        # 受众绑定：出示令牌的调用服务必须等于当前 audience（防混淆代理）。
        if caller != payload["aud"]:
            raise TokenError(
                ErrorCode.AUDIENCE_MISMATCH,
                "调用服务不等于令牌 audience",
                {"caller": caller, "aud": payload["aud"], "jti": payload["jti"]},
            )

        # 调用服务必须注册且与令牌同租户（跨租户同 kid 在此被拦截）。
        caller_tenant = self.registry.require_service(caller)
        if caller_tenant != tenant:
            raise TokenError(
                ErrorCode.TENANT_MISMATCH,
                "调用服务与令牌不属于同一租户",
                {
                    "token_tenant": tenant,
                    "caller_tenant": caller_tenant,
                    "caller": caller,
                },
            )

        # 委托链形状：深度上限与成环检查。
        act = payload["act"]
        if len(act) > MAX_CHAIN_HOPS:
            raise TokenError(
                ErrorCode.CHAIN_TOO_LONG,
                f"actor_chain 最多 {MAX_CHAIN_HOPS} 跳",
                {"length": len(act), "max": MAX_CHAIN_HOPS, "jti": payload["jti"]},
            )
        if len(set(act)) != len(act):
            raise TokenError(
                ErrorCode.CHAIN_CYCLE,
                "actor_chain 内存在重复服务（成环）",
                {"act": act, "jti": payload["jti"]},
            )

        # 祖先撤销（含自身）：SQLite 闭包查询，进程重启后依然有效。
        revoked = self.store.find_revoked_ancestor(payload["jti"])
        if revoked is not None:
            raise TokenError(
                ErrorCode.ANCESTOR_REVOKED,
                "令牌自身或其委托祖先已被撤销",
                {
                    "jti": payload["jti"],
                    "revoked_ancestor": revoked["jti"],
                    "revoked_at": revoked["revoked_at"],
                    "reason": revoked["reason"],
                },
            )

        return {
            "valid": True,
            "tenant": tenant,
            "kid": kid,
            "payload": payload,
            "caller": caller,
            "depth": len(act),
        }

    # ------------------------------------------------------------------ #
    # 受众绑定交换
    # ------------------------------------------------------------------ #
    def exchange(
        self,
        *,
        parent_token: str,
        caller: str,
        target: str,
        requested_scopes: list[str],
        requested_expiry: int | None = None,
        request_id: str,
    ) -> dict:
        # 1) 父令牌完整在线验证（签名、受众绑定、链、过期、祖先撤销）。
        verified = self.verify_online(parent_token, caller=caller)
        parent = verified["payload"]
        tenant = verified["tenant"]

        # 2) 目标服务注册且与调用方同租户。
        target_tenant = self.registry.require_service(target)
        if target_tenant != tenant:
            raise TokenError(
                ErrorCode.TENANT_MISMATCH,
                "目标服务与令牌不属于同一租户",
                {"token_tenant": tenant, "target_tenant": target_tenant},
            )

        # 3) 委托链结构性检查先于边/scope：成环与超深在任何授权判断前拒绝。
        act = list(parent["act"])
        if caller in act or target in act:
            raise TokenError(
                ErrorCode.CHAIN_CYCLE,
                "交换将使 actor_chain 成环",
                {"act": act, "caller": caller, "target": target},
            )
        act.append(caller)
        if len(act) > MAX_CHAIN_HOPS:
            raise TokenError(
                ErrorCode.CHAIN_TOO_LONG,
                f"交换后 actor_chain 超过 {MAX_CHAIN_HOPS} 跳（第 5 跳被拒绝）",
                {"length_after": len(act), "max": MAX_CHAIN_HOPS},
            )

        # 4) 交换边必须预注册：(tenant, caller -> target) 精确匹配。
        edge = self.registry.edge(tenant, caller, target)

        # 5) scope 只能缩小：同时受父令牌 scope 与交换边 scope 上限约束。
        requested_set = self._normalize_scopes(requested_scopes)
        parent_scopes = set(parent["scp"])
        edge_scopes = set(edge["scopes"])
        if not requested_set <= parent_scopes:
            raise TokenError(
                ErrorCode.SCOPE_ESCALATION,
                "请求 scope 超出父令牌授权范围",
                {
                    "requested": sorted(requested_set),
                    "parent_scopes": sorted(parent_scopes),
                    "added": sorted(requested_set - parent_scopes),
                },
            )
        if not requested_set <= edge_scopes:
            raise TokenError(
                ErrorCode.SCOPE_ESCALATION,
                "请求 scope 超出交换边允许范围",
                {
                    "requested": sorted(requested_set),
                    "edge_scopes": sorted(edge_scopes),
                    "added": sorted(requested_set - edge_scopes),
                },
            )
        requested = sorted(requested_set)

        now = self.clock.now()
        # 6) 到期时间不能延长；默认沿用父 exp，显式给值只能更短且必须仍在未来。
        new_exp = parent["exp"] if requested_expiry is None else int(requested_expiry)
        if new_exp > parent["exp"]:
            raise TokenError(
                ErrorCode.EXPIRY_EXTENDED,
                "新令牌到期时间晚于父令牌",
                {"parent_exp": parent["exp"], "requested_exp": new_exp},
            )
        if new_exp <= now:
            raise TokenError(
                ErrorCode.TOKEN_EXPIRED,
                "新令牌到期时间必须在当前时间之后",
                {"new_exp": new_exp, "now": now},
            )

        # 7) 幂等 / 去重检查 + 插入临界区：
        #    进程内用 store.lock 串行化；跨进程由 SQLite UNIQUE 约束兜底。
        canonical_request = {
            "parent_jti": parent["jti"],
            "caller": caller,
            "target": target,
            "requested_scopes": requested,
            "requested_expiry": new_exp,
        }
        req_hash = _request_hash(canonical_request)

        with self.store.lock:
            existing_by_request = self.store.get_exchange_by_request(request_id)
            if existing_by_request is not None:
                if existing_by_request["request_hash"] != req_hash:
                    raise TokenError(
                        ErrorCode.REQUEST_CONFLICT,
                        "同一 request_id 关联了不同的交换请求体",
                        {"request_id": request_id},
                    )
                return self._replay_result(existing_by_request, parent, reason="request_id")

            existing_by_edge = self.store.get_exchange_by_root_target(
                parent["root"], target
            )
            if existing_by_edge is not None:
                if existing_by_edge["request_id"] == request_id:
                    return self._replay_result(
                        existing_by_edge, parent, reason="request_id"
                    )
                raise TokenError(
                    ErrorCode.DUPLICATE_EXCHANGE,
                    "同一根 jti 到同一目标 audience 的交换结果已存在",
                    {
                        "root_jti": parent["root"],
                        "target_aud": target,
                        "existing_request_id": existing_by_edge["request_id"],
                        "new_request_id": request_id,
                    },
                )

            # 8) 构造新令牌：sub/root 不变，aud 指向目标，act 追加调用方。
            new_jti = self.ids.jti()
            new_payload = {
                "iss": caller,
                "sub": parent["sub"],
                "act": act,
                "aud": target,
                "scp": requested,
                "exp": new_exp,
                "jti": new_jti,
                "root": parent["root"],
            }
            kid = header_kid_of(parent_token)
            key_material = self.registry.get_key(tenant, kid)
            new_token = encode_token(
                build_header(tenant, kid), new_payload, key_material
            )

            # 新令牌的祖先闭包 = 父令牌的全部祖先（距离整体 +1）+ 父令牌自身（距离 1）。
            parent_ancestors = self.store.get_ancestors(parent["jti"])
            merged: dict[str, int] = {}
            for anc_jti, distance in parent_ancestors:
                merged[anc_jti] = distance + 1
            merged[parent["jti"]] = 1
            ancestor_list = sorted(
                merged.items(), key=lambda item: (item[1], item[0])
            )

            try:
                self.store.insert_exchange(
                    root_jti=parent["root"],
                    parent_jti=parent["jti"],
                    target_aud=target,
                    new_jti=new_jti,
                    token_text=new_token,
                    request_id=request_id,
                    request_hash=req_hash,
                    created_at=now,
                    tenant=tenant,
                    depth=len(act),
                    ancestors=ancestor_list,
                )
            except sqlite3.IntegrityError as exc:
                # 跨进程 UNIQUE 竞争：回读已提交结果，保证多进程行为一致。
                winner = self.store.get_exchange_by_root_target(parent["root"], target)
                if winner is not None:
                    if (
                        winner["request_id"] == request_id
                        and winner["request_hash"] == req_hash
                    ):
                        return self._replay_result(
                            winner, parent, reason="request_id"
                        )
                    raise TokenError(
                        ErrorCode.DUPLICATE_EXCHANGE,
                        "并发交换命中唯一约束，已有其他请求完成该交换",
                        {
                            "root_jti": parent["root"],
                            "target_aud": target,
                            "existing_request_id": winner["request_id"],
                        },
                    ) from exc
                raise TokenError(
                    ErrorCode.STORE_ERROR, f"数据库约束失败: {exc}"
                ) from exc

        return {
            "token": new_token,
            "jti": new_jti,
            "root_jti": parent["root"],
            "parent_jti": parent["jti"],
            "tenant": tenant,
            "payload": new_payload,
            "depth": len(act),
            "replayed": False,
        }

    # ------------------------------------------------------------------ #
    # 撤销
    # ------------------------------------------------------------------ #
    def revoke(self, jti: str, *, reason: str) -> dict:
        existing = self.store.is_revoked(jti)
        if existing is not None:
            return {"revoked": False, "idempotent": True, "record": existing}
        created = self.store.revoke(jti, self.clock.now(), reason)
        return {"revoked": created, "idempotent": not created, "jti": jti}

    # ------------------------------------------------------------------ #
    def _replay_result(self, row: dict, parent: dict, *, reason: str) -> dict:
        header, payload, _, _ = decode_token(row["token_text"])
        return {
            "token": row["token_text"],
            "jti": row["new_jti"],
            "root_jti": row["root_jti"],
            "parent_jti": row["parent_jti"],
            "tenant": header["tenant"],
            "payload": payload,
            "depth": len(payload["act"]),
            "replayed": True,
            "replay_reason": reason,
        }

    @staticmethod
    def _normalize_scopes(scopes) -> set[str]:
        if not isinstance(scopes, list) or not scopes:
            raise TokenError(
                ErrorCode.INVALID_CLAIM, "scopes 必须是非空字符串列表"
            )
        if any(not isinstance(s, str) or not s for s in scopes):
            raise TokenError(ErrorCode.INVALID_CLAIM, "scopes 含空值或非字符串")
        return set(scopes)


def header_kid_of(token: str) -> str:
    """从令牌头读取 kid（调用前令牌已通过 decode_token 结构校验）。"""
    header, _, _, _ = decode_token(token)
    return header["kid"]
