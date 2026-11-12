"""编译期拒绝：必须指到 AST 位置和原字段，而不是执行后才发现。"""
from __future__ import annotations


class CompileError(Exception):
    """查询违反冻结策略或 AST 契约。

    position 为从查询根开始的路径元组，例如
    ``("queries", 0, "from", "on", "left")``；
    field 为 ``(表名, 字段ID)`` 形式的原字段坐标，可为 None。
    """

    def __init__(self, message: str, position=(), field=None):
        self.message = message
        self.position = tuple(position)
        self.field = field
        loc = "/".join(str(p) for p in self.position) or "<root>"
        if field is not None:
            table, fid = field
            loc += f" [{table}.字段{fid}]"
        super().__init__(f"{loc}: {message}")


def fail(message: str, position=(), field=None) -> "CompileError":
    return CompileError(message, position, field)
