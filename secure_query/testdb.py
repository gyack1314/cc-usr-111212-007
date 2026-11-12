"""把冻结 catalog 的合成数据装载到独立 SQLite 库（测试/演示用）。

只用于对照测试：在另建的数据库文件/内存连接上建表，表名列名取自目录
白名单并安全引号，值全部参数化插入。初始资料读取工具不连接数据库。
"""
from __future__ import annotations

import sqlite3

from .context import quote_ident
from .masking import SQLITE_FUNCTIONS


def build_sqlite_db(document, db_path: str | None = None) -> sqlite3.Connection:
    target = db_path or ":memory:"
    conn = sqlite3.connect(target)
    # 编译 SQL 只会调用这里显式注册的可信脱敏函数。
    for name, impl, narg in SQLITE_FUNCTIONS:
        conn.create_function(name, narg, impl, deterministic=True)
    try:
        for table in document["catalog"]:
            col_defs = ", ".join(
                f"{quote_ident(c['name'])} {_sqlite_type(c['type'])}"
                for c in table["columns"]
            )
            conn.execute(
                f"CREATE TABLE {quote_ident(table['name'])} ({col_defs})"
            )
            placeholders = ", ".join("?" for _ in table["columns"])
            conn.executemany(
                f"INSERT INTO {quote_ident(table['name'])} "
                f"VALUES ({placeholders})",
                [list(row) for row in table.get("rows", [])],
            )
        conn.commit()
    except Exception:
        conn.close()
        raise
    return conn


def _sqlite_type(t: str) -> str:
    return {
        "text": "TEXT",
        "integer": "INTEGER",
        "real": "REAL",
        "boolean": "INTEGER",
    }[t]
