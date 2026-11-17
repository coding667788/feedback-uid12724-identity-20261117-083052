"""cases.json 驱动的命令行入口。

用法::

    python -m solution --input cases.json --output result.json

cases.json schema（详见 README“输入输出 schema”章节）::

    {
      "registry": "samples/registry.json",
      "db_path": "runtime/exchanger.db",
      "seed_b64url": "...",
      "clock": {"freeze": 1700000000},
      "cases": [ {"id": "...", "action": "mint|exchange|verify|revoke|craft|advance", ...} ]
    }

令牌引用：同一文件内前序用例产出的令牌可用 {"$token": "<case_id>"} 引用，
也可用 {"$file": "相对/绝对路径"} 引用项目内源文件或二进制样例。
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import craft as craft_mod
from .encoding import b64url_decode
from .errors import ErrorCode, TokenError
from .registry import Registry
from .service import TokenService
from .store import Store
from .timeutil import Clock, IdGenerator
from .token import build_header, decode_token, encode_token

CRAFT_MODES = frozenset(
    {
        "remote_key_header",
        "unknown_algorithm",
        "duplicate_json_key",
        "non_canonical_b64",
        "wrong_signature",
        "tampered_audience",
        "cross_tenant_signed",
    }
)


def _resolve_ref(value, base_dir: Path, token_map: dict[str, str]):
    """解析 {"$token": id} / {"$file": path} 引用，普通值原样返回。"""
    if isinstance(value, dict) and len(value) == 1:
        if "$token" in value:
            ref = value["$token"]
            if ref not in token_map:
                raise KeyError(f"引用了不存在的令牌产出用例: {ref}")
            return token_map[ref]
        if "$file" in value:
            path = Path(value["$file"])
            if not path.is_absolute():
                path = base_dir / path
            return path.read_bytes().decode("utf-8")
    return value


def _resolve_args(args: dict, base_dir: Path, token_map: dict[str, str]) -> dict:
    return {key: _resolve_ref(value, base_dir, token_map) for key, value in args.items()}


def _build_payload(case: dict, base_clock_now: int) -> dict:
    """为 craft 动作构造一个结构合法的基础载荷。"""
    return {
        "_tenant": case["tenant"],
        "iss": case["issuer"],
        "sub": case["subject"],
        "act": list(case.get("actor_chain", [])),
        "aud": case["audience"],
        "scp": sorted(set(case["scopes"])),
        "exp": base_clock_now + int(case.get("ttl_seconds", 3600)),
        "jti": case.get("jti", "craft-jti-" + case["id"]),
        "root": case.get("root_jti", case.get("jti", "craft-jti-" + case["id"])),
    }


def run(input_path: Path, output_path: Path) -> dict:
    base_dir = input_path.parent
    with input_path.open("r", encoding="utf-8") as fh:
        spec = json.load(fh)

    registry_path = Path(spec["registry"])
    if not registry_path.is_absolute():
        registry_path = base_dir / registry_path
    registry = Registry.load(registry_path)

    db_path = Path(spec["db_path"])
    if not db_path.is_absolute():
        db_path = base_dir / db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    store = Store(db_path)

    seed = b64url_decode(spec.get("seed_b64url", "ZGVmYXVsdC1zZWVk"), what="seed")
    clock = Clock()
    if isinstance(spec.get("clock"), dict) and "freeze" in spec["clock"]:
        clock.freeze(int(spec["clock"]["freeze"]))
    ids = IdGenerator(seed)
    service = TokenService(registry, store, clock, ids)

    token_map: dict[str, str] = {}
    jti_map: dict[str, str] = {}
    results = []
    summary = {"total": 0, "ok": 0, "rejected": 0, "other": 0}

    for case in spec["cases"]:
        summary["total"] += 1
        cid = case["id"]
        action = case["action"]
        entry = {"id": cid, "action": action, "description": case.get("description", "")}
        try:
            if action == "advance":
                clock.advance(int(case["seconds"]))
                entry["status"] = "ok"
                entry["now"] = clock.now()

            elif action == "mint":
                result = service.mint(
                    tenant=case["tenant"],
                    kid=case["kid"],
                    issuer=case["issuer"],
                    subject=case["subject"],
                    audience=case["audience"],
                    scopes=list(case["scopes"]),
                    ttl_seconds=int(case["ttl_seconds"]),
                )
                token_map[cid] = result["token"]
                jti_map[cid] = result["jti"]
                entry.update(status="ok", **_public_token_result(result))

            elif action == "exchange":
                args = _resolve_args(case["args"], base_dir, token_map)
                result = service.exchange(
                    parent_token=args["parent_token"],
                    caller=args["caller"],
                    target=args["target"],
                    requested_scopes=list(args["requested_scopes"]),
                    requested_expiry=args.get("requested_expiry"),
                    request_id=args["request_id"],
                )
                token_map[cid] = result["token"]
                jti_map[cid] = result["jti"]
                entry.update(status="ok", **_public_token_result(result))

            elif action == "verify":
                args = _resolve_args(case["args"], base_dir, token_map)
                result = service.verify_online(
                    args["token"], caller=args["caller"]
                )
                entry.update(
                    status="ok",
                    valid=True,
                    tenant=result["tenant"],
                    depth=result["depth"],
                    payload=result["payload"],
                )

            elif action == "revoke":
                jti = jti_map.get(case["jti_ref"], case.get("jti"))
                if not jti:
                    raise TokenError(
                        ErrorCode.INVALID_CLAIM,
                        "revoke 需要 jti 或已存在的 jti_ref",
                    )
                result = service.revoke(jti, reason=case.get("reason", "manual"))
                entry.update(status="ok", **result)

            elif action == "craft":
                mode = case["mode"]
                if mode not in CRAFT_MODES:
                    raise TokenError(
                        ErrorCode.INVALID_CLAIM,
                        f"未知 craft 模式 {mode!r}",
                        {"allowed": sorted(CRAFT_MODES)},
                    )
                payload = _build_payload(case, clock.now())
                key_material = registry.get_key(case["tenant"], case["kid"])
                if mode == "remote_key_header":
                    token = craft_mod.craft_with_remote_key_header(payload, key_material)
                elif mode == "unknown_algorithm":
                    token = craft_mod.craft_unknown_algorithm(payload, key_material)
                elif mode == "duplicate_json_key":
                    token = craft_mod.craft_duplicate_json_key(payload, key_material)
                elif mode == "non_canonical_b64":
                    token = craft_mod.craft_non_canonical_b64(payload, key_material)
                elif mode == "wrong_signature":
                    token = craft_mod.craft_wrong_signature(payload, key_material)
                elif mode == "tampered_audience":
                    token = craft_mod.craft_tampered_audience(
                        payload, key_material, new_aud=case["new_audience"]
                    )
                elif mode == "cross_tenant_signed":
                    foreign_key = registry.get_key(
                        case["foreign_tenant"], case["foreign_kid"]
                    )
                    token = craft_mod.craft_cross_tenant_signed(
                        payload,
                        signed_tenant=case["foreign_tenant"],
                        signed_kid=case["foreign_kid"],
                        foreign_key_material=foreign_key,
                    )
                token_map[cid] = token
                jti_map[cid] = payload["jti"]
                entry.update(
                    status="ok",
                    crafted=True,
                    mode=mode,
                    token=token,
                    note="仅用于负面测试；后续 verify/exchange 应拒绝",
                )
            else:
                raise TokenError(
                    ErrorCode.INVALID_CLAIM, f"未知 action {action!r}"
                )

        except TokenError as exc:
            entry.update(status="rejected", **exc.to_dict())
        except (KeyError, ValueError, OSError) as exc:
            entry.update(
                status="error",
                error_code=ErrorCode.STORE_ERROR,
                message=str(exc),
                evidence={},
            )

        summary[
            "ok" if entry["status"] == "ok"
            else "rejected" if entry["status"] == "rejected"
            else "other"
        ] += 1
        results.append(entry)

    store.close()
    output = {
        "input_file": str(input_path),
        "registry": str(registry_path),
        "db_path": str(db_path),
        "summary": summary,
        "results": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(output, fh, ensure_ascii=False, indent=2)
    return output


def _public_token_result(result: dict) -> dict:
    return {
        "token": result["token"],
        "jti": result["jti"],
        "root_jti": result["root_jti"],
        "parent_jti": result.get("parent_jti"),
        "tenant": result["tenant"],
        "depth": result["depth"],
        "payload": result["payload"],
        "replayed": result.get("replayed", False),
        "replay_reason": result.get("replay_reason"),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m solution",
        description="本地服务间 HMAC-SHA256 令牌交换器",
    )
    parser.add_argument("--input", required=True, help="cases.json 路径")
    parser.add_argument("--output", required=True, help="result.json 输出路径")
    args = parser.parse_args(argv)
    output = run(Path(args.input), Path(args.output))
    print(
        json.dumps(
            {
                "summary": output["summary"],
                "output": args.output,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
