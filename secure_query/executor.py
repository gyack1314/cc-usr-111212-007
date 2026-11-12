"""绑定校验后的 SQLite 只读执行。

安全约束：
- 连接以 ``mode=ro`` 打开，且执行前强制 PRAGMA query_only=ON；
- 只执行编译计划中的 SQL，标识符来自目录白名单，用户值全部绑定参数；
- 可信脱敏函数在连接上显式注册，不依赖数据库内任何用户函数；
- 执行前复核 policy/schema 版本、principal 摘要与计划摘要，
  绑定不符一律拒绝，过期计划无法换 principal 复用。
"""
from __future__ import annotations

import sqlite3

from .masking import SQLITE_FUNCTIONS
from .plan import recompute_plan_digest


class BindingError(RuntimeError):
    pass


def open_readonly(db_path: str) -> sqlite3.Connection:
    # mode=ro：物理只读；uri 形式固定，路径不参与 SQL 文本。
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    for name, impl, narg in SQLITE_FUNCTIONS:
        conn.create_function(name, narg, impl, deterministic=True)
    return conn


def verify_binding(plan_dict: dict, *, policy_version, schema_version,
                   principal, mask_id):
    if plan_dict.get("policy_version") != policy_version:
        raise BindingError("计划绑定的 policy_version 已过期")
    if plan_dict.get("schema_version") != schema_version:
        raise BindingError("计划绑定的 schema_version 已过期")
    if plan_dict.get("mask_id") != mask_id:
        raise BindingError("计划绑定的脱敏函数版本不一致")
    snapshot = plan_dict.get("policy_snapshot", {})
    if snapshot.get("principal") != principal:
        raise BindingError("principal 与编译冻结属性不一致，拒绝复用计划")
    if plan_dict.get("plan_digest") != recompute_plan_digest(plan_dict):
        raise BindingError("计划内容与绑定摘要不符（疑似被篡改）")


def execute_plan(conn: sqlite3.Connection, plan_dict: dict, *,
                 policy_version, schema_version, principal, mask_id):
    verify_binding(
        plan_dict,
        policy_version=policy_version,
        schema_version=schema_version,
        principal=principal,
        mask_id=mask_id,
    )
    # 双保险：即便连接写权限配置失误，也禁止任何写操作与 DDL。
    conn.execute("PRAGMA query_only=ON")
    cur = conn.execute(plan_dict["sql"], plan_dict["params"])
    rows = [list(r) for r in cur.fetchall()]
    columns = [d[0] for d in cur.description]
    return columns, rows
