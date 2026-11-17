# 本地服务间令牌交换器（HST1 / HMAC-SHA256）

一个只依赖 Python 3.12 标准库的本地令牌交换器：服务之间通过**受众绑定**的
自定义 HMAC-SHA256 令牌进行委托换发，只接受受信注册表中预注册的租户、密钥
与交换边，并用 SQLite 保证多进程下的交换去重、请求幂等与祖先撤销一致性。

无 Docker、无网络、无第三方依赖（仅标准库；题目允许的 `cryptography` 未使用，
HMAC-SHA256 由 `hmac`/`hashlib` 提供）。

---

## 1. 目录结构

```
.
├── solution/                  # 可运行包（python -m solution）
│   ├── __main__.py            # -m 入口
│   ├── cli.py                 # cases.json 驱动的命令行
│   ├── errors.py              # 稳定错误码与 TokenError
│   ├── encoding.py            # 严格 base64url、规范化 JSON、重复键检测
│   ├── token.py               # HST1 令牌构造/解码/签名/结构校验
│   ├── registry.py            # 租户/密钥/服务/交换边受信注册表
│   ├── store.py               # SQLite 去重、幂等、祖先闭包、撤销
│   ├── service.py             # 铸造/在线验证/交换/撤销核心规则
│   ├── mock_services.py       # 本机模拟服务（无网络）
│   ├── craft.py               # 负面测试用令牌伪造工具
│   └── timeutil.py            # 可控时钟与确定性 ID 生成器
├── tests/                     # unittest 自动化测试（63 个）
│   ├── _fixture.py            # 临时注册表/SQLite 夹具
│   ├── _mp_worker.py          # 多进程测试 worker（独立 OS 进程）
│   ├── test_encoding_token.py
│   ├── test_exchange_rules.py
│   ├── test_store_idempotency.py
│   ├── test_concurrency_multiprocess.py
│   ├── test_registry_determinism.py
│   ├── test_mock_services.py
│   └── test_cli.py            # cases.json 端到端断言
├── cases/
│   ├── cases.json             # 验收场景输入（41 个用例）
│   ├── generate_registry.py   # 样例注册表生成器（固定种子）
│   └── generate_file_sample.py# 二进制样例 token_sample.bin 生成器
├── samples/
│   ├── registry.json          # 受信注册表样例
│   ├── token_sample.bin       # 离线 HST1 令牌文本样例（$file 引用）
│   └── token_sample.meta.json
├── run_solution.py            # python -I 隔离模式包装入口
└── runtime/result.json        # 一次完整运行的输出样例
```

---

## 2. 运行方式

```bash
# 入口一：场景驱动
python -m solution --input cases/cases.json --output runtime/result.json

# 入口二：自动化测试
python -m unittest discover -s tests -v
```

隔离模式（`-I`，忽略环境变量与用户站点包）下使用包装器：

```bash
python -I run_solution.py --input cases/cases.json --output runtime/result.json
```

所有写入只发生在 `runtime/` 与系统临时目录；测试使用 `tempfile` 独立目录，
不污染样例数据。

---

## 3. HST1 令牌线格式与规范化签名表示

### 3.1 线格式

三段无填充 base64url，以 `.` 连接（类似 JWS 紧凑序列化，但约束自行实现）：

```
B64URL(UTF8(canonical(header))) . B64URL(UTF8(canonical(payload))) . B64URL(HMAC-SHA256(signing_input, key))
signing_input = 头段 + "." + 载荷段（ASCII 字节）
```

### 3.2 规范化签名表示（canonical JSON）

头与载荷在签名前都序列化为**同一确定性表示**：

```python
json.dumps(obj, ensure_ascii=False, sort_keys=True,
           separators=(",", ":"), allow_nan=False).encode("utf-8")
```

- 键按字典序排序、无空白、无 `NaN/Infinity`；
- HMAC 覆盖头段与载荷段的**确切线字节**，任何声明（含 `aud`、`act`、`scp`）
  被篡改都会导致 `BAD_SIGNATURE`，不可能“只验签不看受众”；
- 签名比较使用 `hmac.compare_digest` 常量时间比较。

### 3.3 令牌头（仅允许 4 个键）

| 键 | 含义 | 约束 |
|---|---|---|
| `alg` | 算法 | 固定 `HS256`，其他值 → `UNKNOWN_ALGORITHM` |
| `typ` | 类型 | 固定 `HST1` |
| `kid` | 密钥 ID | 必须与 `tenant` 一起在注册表中存在 |
| `tenant` | 租户 ID | 必须是受信租户 |

显式禁止 `jku`、`jwk`、`x5u`、`x5c`、`x5t`、`kid_url`、`keyserver`、`uri`
等任何远程密钥地址或内联密钥参数（出现即 `INVALID_HEADER`）。**密钥只能按
`(tenant, kid)` 从本地受信注册表解析**，令牌头无法指定密钥来源。

### 3.4 载荷声明（全部必填，缺一即 `INVALID_CLAIM`）

| 声明 | 含义 | 交换时的规则 |
|---|---|---|
| `iss` | 发行服务 | 新令牌 `iss` = 本次调用服务 |
| `sub` | 原始用户 | **永不改变** |
| `act` | 委托链 `actor_chain` | 追加调用服务；≤4 跳；不得成环 |
| `aud` | 受众服务 | 调用者必须等于当前 `aud`；新令牌 `aud` = 目标服务 |
| `scp` | 授权范围（排序去重字符串列表） | 只能是父 scope 与交换边 scope 的子集 |
| `exp` | 到期时间（整数秒级 Unix 时间戳，拒绝 bool） | 不能晚于父 `exp` |
| `jti` | 本令牌唯一 ID | 每次交换产生新 jti |
| `root` | 根令牌 jti | 整棵委托树共用，**永不改变**，去重与撤销的锚点 |

封装层额外强制：拒绝重复 JSON 键（`DUPLICATE_JSON_KEY`）、拒绝不规范
base64url（填充 `=`、`+`、`/`、空白、非 ASCII → `MALFORMED_TOKEN`）、
拒绝未知算法与额外头/载荷键。

---

## 4. 受信注册表（`samples/registry.json`）

```json
{
  "version": 1,
  "tenants": {
    "<tenant-id>": {
      "keys": [{"kid": "k1", "material_b64url": "<无填充base64url密钥>"}],
      "services": {"<service-id>": {"display_name": "..."}}
    }
  },
  "edges": [
    {"tenant": "<tenant>", "from": "<caller>", "to": "<target>",
     "scopes": ["<该边允许的scope上限>"]}
  ]
}
```

加载期完整性校验：租户非空、`kid` 不重复、服务 ID 全局唯一、每条边的两端
必须是同租户已注册服务且 scope 非空、边不得重复注册。

**跨租户同 kid**：两个租户可以使用相同 `kid`（样例中三个租户都有 `k1`），
但密钥材料不同。验证时按 `(tenant, kid)` 解析密钥，同名 kid 无法跨租户伪造
签名（`tests/test_exchange_rules.py::test_same_kid_different_tenant_key_fails_signature`）。

---

## 5. 交换安全规则（`solution/service.py`）

`exchange()` 的判定顺序（每一步拒绝都带错误码与证据）：

1. **父令牌在线验证** `verify_online`：
   结构解析 → `(tenant, kid)` 解析受信密钥 → HMAC 验签 → 过期检查
   → **受众绑定**（`caller == payload.aud`，否则 `AUDIENCE_MISMATCH`）
   → 调用服务注册且同租户（`TENANT_MISMATCH`）→ 链形状（深度/环）
   → **祖先撤销闭包查询**（`ANCESTOR_REVOKED`）。
2. 目标服务已注册且与令牌同租户，否则 `TENANT_MISMATCH`。
3. 委托链结构检查先于授权：`caller`/`target` 已在 `act` 中 →
   `CHAIN_CYCLE`；追加后超过 4 跳 → `CHAIN_TOO_LONG`。
4. 交换边 `(tenant, caller → target)` 必须预注册，否则 `EDGE_NOT_ALLOWED`。
5. scope 双重收窄：`requested ⊆ parent.scp` 且 `requested ⊆ edge.scopes`，
   否则 `SCOPE_ESCALATION`（证据给出 `added` 越权项）。
6. 到期时间：缺省沿用父 `exp`；显式给值只能更短且仍在未来，否则
   `EXPIRY_EXTENDED` / `TOKEN_EXPIRED`。
7. 幂等与去重（见下节）。
8. 构造新令牌：`sub`/`root` 不变，`act` 追加调用者，`aud` 重绑目标。

### 5.1 委托深度

根令牌 `act=[]`（深度 0）；每跳追加**调用服务**。合法链最多 4 跳
（`act` 长度 4），产生第 5 跳的交换被 `CHAIN_TOO_LONG` 拒绝。
`act` 中出现重复服务即 `CHAIN_CYCLE`。

### 5.2 幂等与去重（SQLite 约束，非内存表）

| 场景 | 行为 | 错误码 |
|---|---|---|
| 同 `request_id` + 同请求体重试 | 返回原令牌，`replayed=true` | 成功 |
| 同 `request_id` + 不同请求体 | 拒绝 | `REQUEST_CONFLICT` |
| 同 `(root_jti, target_aud)` + 新 `request_id` | 拒绝创建第二份结果 | `DUPLICATE_EXCHANGE` |
| 同 `(root_jti, target_aud)` 并发 | 数据库 `UNIQUE` 保证仅一份，败者回读 | 同上/重放 |

请求体指纹为规范化 JSON 的 SHA-256（`request_hash`）。进程内用可重入锁把
“检查+插入”临界区串行化；跨进程由 SQLite 的 `UNIQUE` 索引与 WAL 串行化。

### 5.3 祖先撤销

- 每枚令牌入库时写入**完整祖先闭包** `token_ancestors(descendant, ancestor, distance)`，
  根令牌把自身记为距离 0 的祖先；
- 撤销任何 jti 后，其全部后代在下一次 `verify_online`/`exchange` 时通过
  单次索引联表查询命中 `ANCESTOR_REVOKED`，证据含被撤销祖先 jti、时间与原因；
- 撤销记录与闭包都在 SQLite 中，**进程重启后依然有效**（多进程测试
  `test_revocation_visible_in_another_process` 与重启测试
  `test_revocation_survives_process_restart`）；
- 撤销本身幂等。

---

## 6. SQLite 表结构（`solution/store.py`）

| 表 | 关键约束 | 用途 |
|---|---|---|
| `exchanges` | `UNIQUE(request_id)`、`UNIQUE(root_jti, target_aud)` | 交换去重与幂等，保存令牌文本 |
| `tokens` | `jti PRIMARY KEY` | 令牌元数据（root、父、租户、受众、深度） |
| `token_ancestors` | `PRIMARY KEY(descendant_jti, ancestor_jti)` + 祖先索引 | 祖先闭包，撤销传播 |
| `revocations` | `jti PRIMARY KEY` | 撤销台账 |

pragma：`journal_mode=WAL`、`synchronous=FULL`、`busy_timeout=10000`，
保证多进程交换与撤销按提交顺序一致可见。一次交换的 exchange 行、token 行、
闭包行在**同一事务**提交，不会出现“已去重但闭包缺失”的中间状态。

---

## 7. 错误码表

| 错误码 | 触发条件 |
|---|---|
| `MALFORMED_TOKEN` | 分段数错误、空段、非法/带填充 base64url、非法 JSON/UTF-8 |
| `INVALID_HEADER` | 头非对象、含远程密钥地址、含未允许键、typ 错误 |
| `UNKNOWN_ALGORITHM` | `alg` 不是 `HS256` |
| `DUPLICATE_JSON_KEY` | 头或载荷 JSON 同层重复键 |
| `INVALID_CLAIM` | 声明缺失/类型错误/scope 未排序或重复/exp 非非负整数 |
| `BAD_SIGNATURE` | HMAC 不匹配或签名长度不是 32 字节 |
| `TOKEN_EXPIRED` | 令牌已过期，或新 exp 不在未来 |
| `UNKNOWN_TENANT` / `UNKNOWN_KEY` / `UNKNOWN_SERVICE` | 注册表查无该项 |
| `TENANT_MISMATCH` | 调用方/目标与令牌租户不一致 |
| `EDGE_NOT_ALLOWED` | 交换边未预注册 |
| `AUDIENCE_MISMATCH` | 调用服务 ≠ 令牌 audience（混淆代理） |
| `SCOPE_ESCALATION` | 请求 scope 超出父令牌或交换边范围 |
| `EXPIRY_EXTENDED` | 新 exp 晚于父 exp |
| `CHAIN_CYCLE` / `CHAIN_TOO_LONG` | 委托链成环 / 超过 4 跳 |
| `REQUEST_CONFLICT` | 同 request_id 绑定了不同请求体 |
| `DUPLICATE_EXCHANGE` | 同 root jti 到同目标的第二份交换结果 |
| `ANCESTOR_REVOKED` | 自身或任一祖先 jti 已撤销 |
| `STORE_ERROR` | 未预期的存储层错误 |

---

## 8. 输入 / 输出 Schema

### 8.1 `cases.json`

```json
{
  "registry": "../samples/registry.json",
  "db_path": "../runtime/cases.db",
  "seed_b64url": "Y2FzZXMtZml4ZWQtc2VlZC0yMDI2",
  "clock": {"freeze": 1700000000},
  "cases": [
    {"id": "mint_root", "action": "mint", "tenant": "t-acme", "kid": "k1",
     "issuer": "acme-idp", "subject": "user-7788", "audience": "acme-gateway",
     "scopes": ["orders:read"], "ttl_seconds": 3600},

    {"id": "hop1", "action": "exchange",
     "args": {"parent_token": {"$token": "mint_root"},
              "caller": "acme-gateway", "target": "acme-orders",
              "requested_scopes": ["orders:read"],
              "requested_expiry": 1700001800,
              "request_id": "req-hop1-0001"}},

    {"id": "v1", "action": "verify",
     "args": {"token": {"$token": "hop1"}, "caller": "acme-orders"}},

    {"id": "vfile", "action": "verify",
     "args": {"token": {"$file": "../samples/token_sample.bin"},
              "caller": "acme-gateway"}},

    {"id": "rev1", "action": "revoke", "jti_ref": "hop1",
     "reason": "security-incident-drill"},

    {"id": "wait", "action": "advance", "seconds": 4000},

    {"id": "forged", "action": "craft", "mode": "wrong_signature",
     "tenant": "t-acme", "kid": "k1", "issuer": "acme-idp",
     "subject": "user-7788", "audience": "acme-gateway",
     "scopes": ["orders:read"], "ttl_seconds": 3600,
     "jti": "craft-sig-0001", "root_jti": "craft-sig-0001"}
  ]
}
```

- 引用：`{"$token": "<前序用例 id>"}` 引用前序产出的令牌；
  `{"$file": "<相对输入文件的路径>"}` 引用项目内源文件或二进制样例。
- `action` 取值：`mint` / `exchange` / `verify` / `revoke` / `advance` / `craft`。
- `craft.mode` 取值：`remote_key_header`、`unknown_algorithm`、
  `duplicate_json_key`、`non_canonical_b64`、`wrong_signature`、
  `tampered_audience`（需 `new_audience`）、`cross_tenant_signed`
  （需 `foreign_tenant`/`foreign_kid`）。
- `clock.freeze` 固定虚拟时钟；`advance` 拨快秒数，使过期场景可重放。

### 8.2 `result.json`

```json
{
  "input_file": "...", "registry": "...", "db_path": "...",
  "summary": {"total": 41, "ok": 22, "rejected": 19, "other": 0},
  "results": [
    {"id": "hop1", "action": "exchange", "description": "...",
     "status": "ok", "token": "h.p.s", "jti": "...", "root_jti": "...",
     "parent_jti": "...", "tenant": "t-acme", "depth": 1,
     "payload": {"iss": "...", "sub": "...", "act": ["..."], "aud": "...",
                 "scp": ["..."], "exp": 1700003600, "jti": "...", "root": "..."},
     "replayed": false, "replay_reason": null},
    {"id": "scope_escalation", "action": "exchange", "status": "rejected",
     "error_code": "SCOPE_ESCALATION", "message": "...",
     "evidence": {"requested": ["..."], "added": ["..."]}}
  ]
}
```

`status` 只有 `ok` / `rejected`（安全拒绝，带 `error_code` 与 `evidence`）/
`error`（输入或 IO 类非安全故障，计数到 `summary.other`，验收用例中为 0）。

---

## 9. 验收场景对照（cases.json 41 例 / 测试 63 个）

| 验收要求 | cases.json 用例 | 错误码/断言 |
|---|---|---|
| 合法两跳链 | `mint_root` → `hop1_gateway_to_orders` → `hop2_orders_to_billing` + 两个 verify | `ok`，sub/root 不变、act 逐跳追加、scope 收窄 |
| 混淆代理 | `confused_deputy_wrong_caller`、`confused_deputy_unregistered_edge` | `AUDIENCE_MISMATCH`、`EDGE_NOT_ALLOWED` |
| 跨租户同 kid | `cross_tenant_presentation`、`cross_tenant_forged_signature`/`..._verify` | `AUDIENCE_MISMATCH`、`BAD_SIGNATURE` |
| scope 扩大 | `scope_escalation` | `SCOPE_ESCALATION`（含 added 证据） |
| 链环 | `chain_cycle_rejected`、`test_caller_already_in_actor_chain_rejected` | `CHAIN_CYCLE` |
| 第五跳 | `chain_hop1..4` 成功、`chain_hop5_rejected` | `CHAIN_TOO_LONG`，`length_after=5` |
| 并发重复交换 | 线程测试 + `test_concurrent_exchange_single_winner_across_processes`（5 进程） | 仅 1 成功，余 `DUPLICATE_EXCHANGE`，库中 1 行 |
| request_id 重试 | `retry_same_request_id`、`request_id_conflict`、3 进程重放测试 | 同令牌 `replayed=true` / `REQUEST_CONFLICT` |
| 祖先撤销后重启 | `revoke_hop1`、`descendant_after_revoke`、`exchange_after_revoke` + 跨进程/重启测试 | `ANCESTOR_REVOKED`，证据点名祖先 jti |
| 封装层拒绝 | jku / RS256 / 重复键 / 填充 base64 / 坏签名 / 篡改 aud | 各自对应错误码，篡改 aud → `BAD_SIGNATURE` |
| 过期 | `advance_past_expiry` + `expired_verify` | `TOKEN_EXPIRED` |
| $file 二进制样例 | `verify_from_file` | `ok` |

测试全部断言**具体状态、错误码或证据字段**（例如撤销祖先 jti、越权 scope
列表、链长度、库内行数、跨进程返回令牌完全一致），不存在仅打印成功的检查。

---

## 10. 确定性与可重放

- `IdGenerator`：`SHA-256(seed | namespace | counter)` 派生 jti/request_id，
  同种子同调用序列产出逐字节相同的结果（`test_full_run_replay_produces_identical_jtis`）。
- `Clock` 可冻结/拨快；cases.json 固定 `clock.freeze=1700000000`。
- 注册表与二进制样例由 `cases/generate_*.py` 以固定输入重新生成。

## 11. 自行约定的非安全性细节

- 时间戳精度为秒级整数；`scp` 强制字典序排序去重；`act` 为字符串列表。
- 交换缺省沿用父 `exp`；不签发“无过期”令牌。
- 注册表为本地受信配置文件，不支持热更新（重启加载）。
- 模拟服务不做网络监听，仅以固定 `service_id` 表达调用身份。
- 密钥样例为 SHA-256 派生的 32 字节随机形态材料，仅用于本机演示。
