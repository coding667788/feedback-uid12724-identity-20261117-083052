"""SQLite 持久化：交换去重、请求幂等、祖先闭包与撤销。

设计要点：
- 交换唯一性由数据库 UNIQUE(root_jti, target_aud) 约束保证，而不是应用内存；
  多进程并发下第二个提交者收到 IntegrityError，再回读已提交结果。
- request_id 同样为 UNIQUE：同 request_id 重试回读原结果；同 request_id
  不同请求体由应用层比对 request_hash 后拒绝（REQUEST_CONFLICT）。
- 每枚后代令牌与其全部祖先的关系写入 token_ancestors 闭包表，
  撤销查询是单次索引查询；进程重启后状态不丢失（题目禁止只用内存祖先表）。
- WAL + busy_timeout 让多进程“交换与撤销”按提交顺序串行可见。
"""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path

from .errors import ErrorCode, TokenError

SCHEMA = """
CREATE TABLE IF NOT EXISTS exchanges (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    root_jti      TEXT NOT NULL,
    parent_jti    TEXT NOT NULL,
    target_aud    TEXT NOT NULL,
    new_jti       TEXT NOT NULL,
    token_text    TEXT NOT NULL,
    request_id    TEXT NOT NULL UNIQUE,
    request_hash  TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    UNIQUE(root_jti, target_aud)
);

CREATE TABLE IF NOT EXISTS revocations (
    jti         TEXT PRIMARY KEY,
    revoked_at  INTEGER NOT NULL,
    reason      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS token_ancestors (
    descendant_jti TEXT NOT NULL,
    ancestor_jti   TEXT NOT NULL,
    distance       INTEGER NOT NULL,
    PRIMARY KEY (descendant_jti, ancestor_jti)
);
CREATE INDEX IF NOT EXISTS idx_ancestor_lookup
    ON token_ancestors(ancestor_jti);

CREATE TABLE IF NOT EXISTS tokens (
    jti        TEXT PRIMARY KEY,
    root_jti   TEXT NOT NULL,
    parent_jti TEXT,
    tenant     TEXT NOT NULL,
    aud        TEXT NOT NULL,
    depth      INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
"""


class Store:
    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        # 进程内互斥：让同进程多线程的“去重检查 + 插入”整体原子；
        # 跨进程仍由 SQLite 的 UNIQUE 索引与 WAL 串行化保证。
        self._lock = threading.RLock()
        # check_same_thread=False：交换服务自身的线程池测试也复用同一连接，
        # 所有写操作都在短事务内并加连接级互斥。
        self._conn = sqlite3.connect(
            self.db_path, timeout=10.0, check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=10000")
        with self._conn:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def transaction(self):
        """立即提交的短事务；IntegrityError 原样上抛给服务层处理。"""
        with self._lock:
            try:
                yield self._conn
                self._conn.commit()
            except Exception:
                self._conn.rollback()
                raise

    # ------------------------------------------------------------------ #
    # 令牌登记与祖先闭包
    # ------------------------------------------------------------------ #
    def record_token(
        self,
        jti: str,
        root_jti: str,
        parent_jti: str | None,
        tenant: str,
        aud: str,
        depth: int,
        created_at: int,
        ancestors: list[tuple[str, int]],
    ) -> None:
        """登记一枚新令牌，并写入其完整祖先闭包。

        ancestors: [(ancestor_jti, distance), ...]，包含根到父的所有祖先。
        """
        with self._lock, self.transaction() as conn:
            conn.execute(
                "INSERT INTO tokens(jti, root_jti, parent_jti, tenant, aud, depth, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (jti, root_jti, parent_jti, tenant, aud, depth, created_at),
            )
            conn.executemany(
                "INSERT OR IGNORE INTO token_ancestors(descendant_jti, ancestor_jti, distance)"
                " VALUES (?,?,?)",
                [(jti, ancestor_jti, distance) for ancestor_jti, distance in ancestors],
            )

    def is_revoked(self, jti: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT jti, revoked_at, reason FROM revocations WHERE jti = ?", (jti,)
            ).fetchone()
        return dict(row) if row else None

    def find_revoked_ancestor(self, jti: str) -> dict | None:
        """返回命中的已撤销祖先（含自身），无命中返回 None。"""
        with self._lock:
            row = self._conn.execute(
                """
                SELECT r.jti AS jti, r.revoked_at AS revoked_at, r.reason AS reason
                FROM revocations r
                JOIN token_ancestors ta ON ta.ancestor_jti = r.jti
                WHERE ta.descendant_jti = ?
                UNION
                SELECT jti, revoked_at, reason FROM revocations WHERE jti = ?
                ORDER BY revoked_at
                LIMIT 1
                """,
                (jti, jti),
            ).fetchone()
        return dict(row) if row else None

    def revoke(self, jti: str, revoked_at: int, reason: str) -> bool:
        """撤销 jti；已存在返回 False（幂等）。"""
        with self._lock, self.transaction() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO revocations(jti, revoked_at, reason) VALUES (?,?,?)",
                (jti, revoked_at, reason),
            )
            return cur.rowcount == 1

    # ------------------------------------------------------------------ #
    # 交换去重 / 幂等
    # ------------------------------------------------------------------ #
    def get_exchange_by_request(self, request_id: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM exchanges WHERE request_id = ?", (request_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_exchange_by_root_target(self, root_jti: str, target_aud: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM exchanges WHERE root_jti = ? AND target_aud = ?",
                (root_jti, target_aud),
            ).fetchone()
        return dict(row) if row else None

    def insert_exchange(
        self,
        root_jti: str,
        parent_jti: str,
        target_aud: str,
        new_jti: str,
        token_text: str,
        request_id: str,
        request_hash: str,
        created_at: int,
        tenant: str,
        depth: int,
        ancestors: list[tuple[str, int]],
    ) -> None:
        """单事务提交一次交换：去重约束、令牌登记、祖先闭包原子生效。

        任一 UNIQUE 冲突抛 sqlite3.IntegrityError，整个事务回滚，
        不会出现“交换已去重但闭包缺失”的中间状态。
        """
        with self._lock, self.transaction() as conn:
            conn.execute(
                "INSERT INTO exchanges(root_jti, parent_jti, target_aud, new_jti,"
                " token_text, request_id, request_hash, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (
                    root_jti,
                    parent_jti,
                    target_aud,
                    new_jti,
                    token_text,
                    request_id,
                    request_hash,
                    created_at,
                ),
            )
            conn.execute(
                "INSERT INTO tokens(jti, root_jti, parent_jti, tenant, aud, depth, created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (new_jti, root_jti, parent_jti, tenant, target_aud, depth, created_at),
            )
            conn.executemany(
                "INSERT OR IGNORE INTO token_ancestors(descendant_jti, ancestor_jti, distance)"
                " VALUES (?,?,?)",
                [(new_jti, ancestor_jti, distance) for ancestor_jti, distance in ancestors],
            )

    def get_token_row(self, jti: str) -> dict | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tokens WHERE jti = ?", (jti,)
            ).fetchone()
        return dict(row) if row else None

    def get_ancestors(self, descendant_jti: str) -> list[tuple[str, int]]:
        """返回某令牌已持久化的全部 (祖先 jti, 距离)。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT ancestor_jti, distance FROM token_ancestors"
                " WHERE descendant_jti = ? ORDER BY distance, ancestor_jti",
                (descendant_jti,),
            ).fetchall()
        return [(row["ancestor_jti"], row["distance"]) for row in rows]

    @property
    def lock(self) -> threading.RLock:
        """暴露进程内互斥锁，供 service 包裹“检查+插入”临界区。"""
        return self._lock


def reopen(db_path: str | Path) -> Store:
    """以新进程/新连接方式重开同一数据库文件（重启场景测试用）。"""
    path = Path(db_path)
    if not path.exists():
        raise TokenError(ErrorCode.STORE_ERROR, f"数据库文件不存在: {path}")
    return Store(path)
