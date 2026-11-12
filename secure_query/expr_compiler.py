"""表达式编译：使用点权限检查、类型推断与参数化 SQL 发射。

使用点规则：
- join ON / WHERE / GROUP BY / HAVING / ORDER BY / 聚合参数只能引用 visible 列；
- masked 列只允许在根投影直接投影（裸列），不允许计算、过滤、排序探测原值；
- forbidden 列在任何位置引用即拒绝（含星号展开）；
- 聚合输出只有全部输入 visible 才允许生成，禁止先算后遮；
- 所有用户字面量进入 ParamBank，SQL 文本里不出现用户值。
"""
from __future__ import annotations

from dataclasses import dataclass

from .context import LevelTools, quote_ident
from .errors import fail
from .relations import LabeledCol, ParamBank, col_ref, find_column, internal_quote

_SQL_COMPARE = {
    "eq": "=", "ne": "<>", "lt": "<", "le": "<=", "gt": ">", "ge": ">=",
}
_SQL_LOGIC = {"and": "AND", "or": "OR"}
_AGG_SQL = {
    "count": "COUNT", "sum": "SUM", "min": "MIN", "max": "MAX",
}
_NUMERIC = {"integer", "real"}


@dataclass
class ExprResult:
    sql: str
    type: str
    level: str
    lineage: tuple
    is_aggregate: bool
    masked_bare_col: LabeledCol | None = None


def compile_policy_predicate(ctx, policy, table, base_alias, params: ParamBank,
                             position):
    """eq_attr 行谓词 → scan 内部 WHERE；principal 值冻结为绑定参数。

    谓词限定在物理表的内部别名上（b_ 前缀），与派生子查询别名（s_）分离，
    确保过滤作用于基表行而不是同名派生表。
    """
    field_id = policy.row_field
    col_spec = table.col(field_id, position)
    frozen_value = ctx.attr_value(policy.row_attribute, position + ("attribute",))
    ref_sql = f"{internal_quote(base_alias)}.{quote_ident(col_spec.name)}"
    requested_key = f"rls_{table.name}_{field_id}"
    ph = params.add(frozen_value, key=requested_key)
    # ParamBank 在自连接导致重键时会追加后缀，以实际占位符键为准。
    actual_key = ph[1:]
    info = {
        "table": table.name,
        "field": field_id,
        "field_name": col_spec.name,
        "attribute": policy.row_attribute,
        "op": "eq_attr",
        # 编译期参数键；最终 ? 位置索引在 finalize 重排后回填。
        "param_key": actual_key,
        "bound_param_index": None,
        "position": list(position),
    }
    return f"{ref_sql} = {ph}", info


def compile_on(ctx, node, left_rel, right_rel, params, position):
    scope = left_rel.columns + right_rel.columns
    result = _compile_bool(ctx, node, scope, params, position, "join ON")
    return result.sql


def compile_bool_expr(ctx, node, scope, params, position, context_name):
    return _compile_bool(ctx, node, scope, params, position, context_name)


def _compile_bool(ctx, node, scope, params, position, context_name):
    result = compile_expr(ctx, node, scope, params, position,
                          allow_masked_bare=False)
    if result.type != "boolean":
        raise fail(f"{context_name} 必须是布尔表达式，得到 {result.type}",
                   position)
    return result


def compile_expr(ctx, node, scope: list[LabeledCol], params: ParamBank,
                 position, *, allow_masked_bare):
    if "col" in node:
        rel_alias, ref = node["col"]
        col = find_column(scope, rel_alias, ref, position + ("col",))
        if col.level == "forbidden":
            raise fail("forbidden 列禁止引用", position,
                       _field_coordinate(col))
        if col.level == "masked" and not allow_masked_bare:
            raise fail(
                "masked 列只能在最外层直接投影，禁止计算/过滤/排序探测原值",
                position, _field_coordinate(col),
            )
        return ExprResult(
            sql=col_ref(col),
            type=col.type,
            level=col.level,
            lineage=col.lineage,
            is_aggregate=False,
            masked_bare_col=col if col.level == "masked" else None,
        )

    if "literal" in node:
        lit = node["literal"]
        return ExprResult(
            sql=params.add(lit["value"]),
            type=lit["type"],
            level="visible",
            lineage=(),
            is_aggregate=False,
        )

    op = node["op"]
    if op in _SQL_COMPARE:
        left = compile_expr(ctx, node["left"], scope, params,
                            position + ("left",), allow_masked_bare=False)
        right = compile_expr(ctx, node["right"], scope, params,
                             position + ("right",), allow_masked_bare=False)
        _check_comparable(left, right, position)
        return ExprResult(
            sql=f"({left.sql} {_SQL_COMPARE[op]} {right.sql})",
            type="boolean",
            level=LevelTools.strictest(left.level, right.level),
            lineage=left.lineage + right.lineage,
            is_aggregate=False,
        )
    if op in _SQL_LOGIC:
        left = _compile_bool(ctx, node["left"], scope, params,
                             position + ("left",), "逻辑运算")
        right = _compile_bool(ctx, node["right"], scope, params,
                              position + ("right",), "逻辑运算")
        return ExprResult(
            sql=f"({left.sql} {_SQL_LOGIC[op]} {right.sql})",
            type="boolean",
            level=LevelTools.strictest(left.level, right.level),
            lineage=left.lineage + right.lineage,
            is_aggregate=left.is_aggregate or right.is_aggregate,
        )
    if op == "not":
        inner = _compile_bool(ctx, node["expr"], scope, params,
                              position + ("expr",), "not")
        return ExprResult(
            sql=f"(NOT {inner.sql})", type="boolean", level=inner.level,
            lineage=inner.lineage, is_aggregate=inner.is_aggregate,
        )
    if op == "is_null":
        inner = compile_expr(ctx, node["expr"], scope, params,
                             position + ("expr",), allow_masked_bare=False)
        return ExprResult(
            sql=f"({inner.sql} IS NULL)", type="boolean", level=inner.level,
            lineage=inner.lineage, is_aggregate=inner.is_aggregate,
        )
    if op == "aggregate":
        return _compile_aggregate(ctx, node, scope, params, position)
    raise fail(f"未知表达式算子 {op!r}", position)


def _compile_aggregate(ctx, node, scope, params, position):
    func = node["func"]
    distinct = node.get("distinct", False)
    if func == "count_star":
        # 不引用列；无权基表行已在 scan 被剔除，计数天然不含它们。
        return ExprResult(
            sql="COUNT(*)", type="integer", level="visible",
            lineage=(), is_aggregate=True,
        )
    # 聚合参数强制 visible：递归时 allow_masked_bare=False，
    # masked/forbidden 在列引用点直接拒绝，杜绝先算后遮。
    arg = compile_expr(ctx, node["expr"], scope, params,
                       position + ("expr",), allow_masked_bare=False)
    if arg.is_aggregate:
        raise fail("不允许嵌套聚合", position)
    if arg.level != "visible":
        raise fail("聚合输入含受限列，禁止对受限表达式先算后遮", position,
                   _lineage_coordinate(arg.lineage))
    if distinct and func not in ("count", "sum"):
        raise fail("distinct 仅支持 count/sum", position + ("distinct",))
    inner = ("DISTINCT " + arg.sql) if distinct else arg.sql
    return ExprResult(
        sql=f"{_AGG_SQL[func]}({inner})",
        type=_aggregate_type(func, arg.type, position),
        level="visible",
        lineage=arg.lineage,
        is_aggregate=True,
    )


def _aggregate_type(func, arg_type, position):
    if func == "count":
        return "integer"
    if func == "sum":
        if arg_type not in _NUMERIC:
            raise fail(f"sum 要求数值输入，得到 {arg_type}", position)
        return arg_type
    if func in ("min", "max"):
        return arg_type
    raise fail(f"未支持的聚合 {func}", position)


def _check_comparable(left: ExprResult, right: ExprResult, position):
    if left.type == "boolean" or right.type == "boolean":
        raise fail("布尔值不能参与比较", position)
    if {left.type, right.type} <= _NUMERIC or left.type == right.type:
        return
    raise fail(f"比较两侧类型不兼容: {left.type} 与 {right.type}", position)


def _field_coordinate(col: LabeledCol):
    for src in col.lineage:
        if "table" in src and "field" in src:
            return (src["table"], src["field"])
    return None


def _lineage_coordinate(lineage):
    for src in lineage:
        if "table" in src and "field" in src:
            return (src["table"], src["field"])
    return None
