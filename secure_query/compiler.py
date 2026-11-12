"""受限查询编译器总入口与 SELECT 关系编译。

编译产出 :class:`CompiledQuery`：
- 白名单物理名、安全引号的只读 SQLite SQL；
- 全部用户/策略字面量均为 ``?`` 绑定参数；
- 每列的来源字段与权限等级、行过滤说明、策略与 principal 绑定。
拒绝在编译期完成并指到 AST 位置与原字段。
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass

from . import ast_nodes
from .context import FrozenContext, freeze, quote_ident
from .errors import fail
from .expr_compiler import compile_bool_expr, compile_expr
from .masking import get_mask
from .relations import (
    AliasGen,
    CompiledRelation,
    LabeledCol,
    ParamBank,
    col_ref,
    collect_aliases,
    compile_join,
    compile_scan,
    compile_union,
    field_coordinate,
    internal_quote,
)


@dataclass
class OutputColumn:
    name: str
    type: str
    level: str
    lineage: tuple
    masked: bool


@dataclass
class CompiledQuery:
    sql: str
    params: list
    columns: list[OutputColumn]
    rls_filters: list
    policy_version: str
    schema_version: str
    mask_id: str
    principal_id: str
    principal_digest: str
    plan_digest: str
    # 供执行入口复核的冻结快照（不含数据行）。
    policy_snapshot: dict
    ast_position_of_output: list


# ------------------------------------------------------------ SELECT

def compile_select(ctx: FrozenContext, node, position, aliases: AliasGen,
                   params: ParamBank, *, is_root: bool,
                   masked_passthrough: bool = False):
    input_rel = _compile_input(ctx, node["from"], position + ("from",),
                               aliases, params)
    scope = list(input_rel.columns)
    select_alias = aliases.make("q")

    where_sql = None
    if "where" in node:
        where_result = compile_bool_expr(
            ctx, node["where"], scope, params, position + ("where",), "WHERE",
        )
        where_sql = where_result.sql
        if where_result.is_aggregate:
            raise fail("WHERE 不允许聚合表达式", position + ("where",))

    group_sqls = []
    group_identities = set()
    for i, gexpr in enumerate(node.get("group_by", [])):
        gp = position + ("group_by", i)
        gres = compile_expr(ctx, gexpr, scope, params, gp,
                            allow_masked_bare=False)
        if gres.is_aggregate:
            raise fail("GROUP BY 不允许聚合表达式", gp)
        group_sqls.append(gres.sql)
        key = _identity_of(gexpr, gres, scope, gp)
        group_identities.add(key)

    having_sql = None
    if "having" in node:
        hp = position + ("having",)
        if not group_sqls:
            raise fail("HAVING 需要 GROUP BY", hp)
        hres = compile_bool_expr(ctx, node["having"], scope, params, hp,
                                 "HAVING")
        having_sql = hres.sql

    # 投影：星号先按 schema 展开，再逐列做规则检查，不悄悄省略禁列。
    projections = _expand_stars(ctx, node, scope, position)
    seen_output_names: set[str] = set()
    output_cols: list[LabeledCol] = []
    select_items: list[str] = []
    out_positions: list = []

    for proj_item, proj_position in projections:
        out_name = proj_item["as"]
        if out_name in seen_output_names:
            raise fail(f"输出别名 {out_name!r} 重复，重复别名不能洗白来源",
                       proj_position + ("as",))
        seen_output_names.add(out_name)

        expr_node = proj_item["expr"]
        is_bare_masked = _is_bare_col_of_level(expr_node, scope, "masked")
        # 根投影允许 masked 裸列；union 分支允许裸列向下传递（passthrough），
        # 由 union 根在最外层统一脱敏。其余嵌套位置一律拒绝。
        allow_masked = (is_root or masked_passthrough) and is_bare_masked
        result = compile_expr(
            ctx, expr_node, scope, params, proj_position + ("expr",),
            allow_masked_bare=allow_masked,
        )
        if result.masked_bare_col is not None and not (
            is_root or masked_passthrough
        ):
            raise fail(
                "masked 列只能在最外层直接投影，嵌套 SELECT 不得保留原值",
                proj_position,
            )
        if group_sqls and not result.is_aggregate:
            key = _identity_of(expr_node, result, scope, proj_position)
            if key not in group_identities:
                raise fail(
                    "非聚合投影必须出现在 GROUP BY 中", proj_position,
                )

        internal_name = f"q_{len(output_cols)}"
        labeled = LabeledCol(
            holder_alias=select_alias,
            user_aliases=frozenset(),  # 下游只能按输出名引用，见 order 解析
            internal_name=internal_name,
            type=result.type,
            lineage=result.lineage or ({"stage": "literal",
                                        "select": True},),
            level=result.level,
            needs_mask=result.masked_bare_col is not None,
            output_name=out_name,
        )
        output_cols.append(labeled)
        select_items.append(f"{result.sql} AS {internal_quote(internal_name)}")
        out_positions.append(proj_position)

    # ORDER BY 不放进内层 select SQL：它在最外层根包装上按输出列发射，
    # 避免内层引用外层根别名导致作用域错位。这里只做权限检查与表达式编译，
    # 实际排序片段由 _finalize 用输出列内部名重新生成。
    order_items = _check_order(ctx, node, scope, output_cols, params,
                               position)

    sql = _assemble_select(
        input_rel, select_items, where_sql, group_sqls, having_sql,
        select_alias,
    )
    rel = CompiledRelation(
        sql=sql,
        alias=select_alias,
        columns=output_cols,
        rls_filters=input_rel.rls_filters,
        output_alias_map={c.output_name: c for c in output_cols},
        is_select=True,
    )
    rel._out_positions = out_positions
    rel._order_items = order_items
    return rel


def _compile_input(ctx, node, position, aliases, params):
    kind = node["kind"]
    if kind == "scan":
        rel = compile_scan(ctx, node, position, aliases, params)
        return rel
    if kind == "join":
        return compile_join(ctx, node, position, aliases, params,
                            lambda n, p: _compile_input(ctx, n, p, aliases,
                                                        params))
    if kind == "union_all":
        return compile_union(
            ctx, node, position, aliases, params,
            lambda n, p, is_root, masked_passthrough=False: compile_select(
                ctx, n, p, aliases, params, is_root=is_root,
                masked_passthrough=masked_passthrough),
        )
    raise fail(f"不支持的 FROM 关系 {kind!r}", position)


def _expand_stars(ctx, node, scope, position):
    """星号按输入 schema 完整展开；forbidden 在展开结果上照常拒绝。"""
    result = []
    for i, item in enumerate(node["project"]):
        p = position + ("project", i)
        if item.get("star") is True:
            for col in scope:
                # 直接复用已带权限标签的列：展开项走与手写 col 完全相同
                # 的检查路径，forbidden 不会被悄悄省略，列序与输入 schema 一致。
                user_alias = next(iter(col.user_aliases), None)
                if user_alias is None:
                    raise fail(
                        "星号只能展开带关系别名的输入列", p,
                    )
                synthetic = {
                    "as": col.output_name or col.internal_name,
                    "expr": {"col": [user_alias, _star_ref(col)]},
                }
                result.append((synthetic, p))
        else:
            result.append((item, p))
    return result


def _star_ref(col: LabeledCol):
    for src in col.lineage:
        if "field" in src:
            return src["field"]
    return col.internal_name


def _is_bare_col_of_level(expr_node, scope, level):
    if "col" not in expr_node:
        return False
    rel_alias, ref = expr_node["col"]
    matches = [c for c in scope if c.matches_ref(rel_alias, ref)]
    return len(matches) == 1 and matches[0].level == level


def _identity_of(expr_node, result, scope, position):
    """GROUP BY 身份：裸列按原始字段坐标，其余按 SQL 结构保守比对。"""
    if "col" in expr_node:
        rel_alias, ref = expr_node["col"]
        col = next((c for c in scope if c.matches_ref(rel_alias, ref)), None)
        if col is None:
            raise fail("GROUP BY 列无法解析", position)
        coords = tuple(sorted(
            (s["table"], s["field"]) for s in col.lineage
            if "table" in s and "field" in s
        ))
        return ("col", coords)
    return ("expr", result.sql)


def _check_order(ctx, node, scope, output_cols, params, position):
    """权限检查 ORDER BY，并把每个排序列映射到一个输出列。

    排序只允许引用本层投影输出（裸列必须能解析到某个输出列），
    这样根层可以纯粹按输出列内部名发射，不存在跨作用域引用。
    """
    order_items = node.get("order_by", [])
    checked = []
    for i, item in enumerate(order_items):
        p = position + ("order_by", i)
        expr = item["expr"]
        direction = item.get("direction", "asc").upper()
        target = _resolve_order_target(expr, scope, output_cols, p)
        coordinate = field_coordinate(target)
        if target.level == "forbidden":
            raise fail("forbidden 列禁止用于排序", p, coordinate)
        if target.level == "masked" or target.needs_mask:
            raise fail("masked 列禁止排序探测原值", p, coordinate)
        if "col" not in expr:
            # 非裸列表达式必须能在输入 scope 上以 visible 编译（提前失败），
            # 但排序语义仍要求其对应一个输出列；不支持对未投影表达式排序。
            res = compile_expr(ctx, expr, scope, params, p + ("expr",),
                               allow_masked_bare=False)
            if res.is_aggregate:
                raise fail("ORDER BY 不允许新引入聚合", p)
            raise fail("ORDER BY 表达式必须是投影输出列的裸引用", p)
        # 裸列：确认它解析到的就是某个输出列，记录该输出列的内部名。
        checked.append({"internal_name": target.internal_name,
                        "direction": direction, "position": p})
    return checked


def _resolve_order_target(expr, scope, output_cols, position):
    if "col" not in expr:
        # 表达式排序：真实权限检查在 compile_expr 重编译处完成。
        return LabeledCol(
            holder_alias="", user_aliases=frozenset(), internal_name="",
            type="boolean", lineage=(), level="visible",
        )
    rel_alias, ref = expr["col"]
    # 先查本层输出别名（ORDER BY 可引用投影输出名）。
    out = next((c for c in output_cols if c.output_name == ref), None)
    if out is not None:
        return out
    matches = [c for c in scope if c.matches_ref(rel_alias, ref)]
    if not matches:
        raise fail(f"ORDER BY 未知列 [{rel_alias}, {ref!r}]", position)
    if len(matches) > 1:
        raise fail("ORDER BY 列引用歧义", position)
    source_col = matches[0]
    # 先做权限判定：受限列即便未投影，也要报权限错误而非“未投影”。
    coordinate = field_coordinate(source_col)
    if source_col.level == "forbidden":
        raise fail("forbidden 列禁止用于排序", position, coordinate)
    if source_col.level == "masked":
        raise fail("masked 列禁止排序探测原值", position, coordinate)
    # 裸列若引用的是输入列，它必须已被投影（按来源坐标匹配某个输出列）。
    projected = _find_output_for_source(source_col, output_cols)
    if projected is None:
        raise fail(
            "ORDER BY 裸列必须是投影输出列（不允许对未投影列排序）",
            position,
        )
    return projected


def _find_output_for_source(source_col, output_cols):
    src_coords = {
        (s["table"], s["field"]) for s in source_col.lineage
        if "table" in s and "field" in s
    }
    for out in output_cols:
        out_coords = {
            (s["table"], s["field"]) for s in out.lineage
            if "table" in s and "field" in s
        }
        if src_coords and src_coords == out_coords:
            return out
    return None


def _assemble_select(input_rel, select_items, where_sql, group_sqls,
                     having_sql, select_alias):
    parts = [
        "SELECT " + ", ".join(select_items),
        f"FROM {input_rel.sql} AS {internal_quote(input_rel.alias)}",
    ]
    if where_sql is not None:
        parts.append("WHERE " + where_sql)
    if group_sqls:
        parts.append("GROUP BY " + ", ".join(group_sqls))
    if having_sql is not None:
        parts.append("HAVING " + having_sql)
    return "(" + " ".join(parts) + ")"


# ------------------------------------------------------------ 根包装与脱敏

def compile_query(ctx: FrozenContext, query_ast, *, position=()):
    ast_nodes.validate_statement(query_ast, position)
    collect_aliases(
        query_ast["from"] if query_ast["kind"] == "select" else query_ast,
        set(), position,
    )
    aliases = AliasGen()
    params = ParamBank()

    if query_ast["kind"] == "union_all":
        root_rel = compile_union(
            ctx, query_ast, position, aliases, params,
            lambda n, p, is_root, masked_passthrough=False: compile_select(
                ctx, n, p, aliases, params, is_root=is_root,
                masked_passthrough=masked_passthrough),
        )
        out_positions = [
            position + ("inputs", 0, "project", i)
            for i in range(len(root_rel.columns))
        ]
    else:
        root_rel = compile_select(ctx, query_ast, position, aliases, params,
                                  is_root=True)
        out_positions = getattr(root_rel, "_out_positions", [])

    return _finalize(ctx, root_rel, params, out_positions, position)


def _finalize(ctx, root_rel, params, out_positions, position):
    mask = get_mask(ctx.mask_id)
    outer_items = []
    output_columns = []
    for i, col in enumerate(root_rel.columns):
        out_name = col.output_name or col.internal_name
        inner_ref = col_ref(col)
        if col.needs_mask:
            if col.level != "masked":
                raise AssertionError("needs_mask 与 level 不一致")
            if col.type != "text":
                raise fail("prefix-sha256 脱敏仅登记给 text 列",
                           out_positions[i] if i < len(out_positions) else position)
            # 盐位以命名占位符入参；函数名来自可信注册表。
            salt_ph = params.add(None, key=f"salt_{i}")
            masked_sql = f"{mask.sqlite_name}({salt_ph}, {inner_ref})"
            outer_items.append(f"{masked_sql} AS {quote_ident(out_name)}")
            output_columns.append(OutputColumn(
                name=out_name, type=mask.output_type, level="masked",
                lineage=col.lineage, masked=True,
            ))
        else:
            outer_items.append(f"{inner_ref} AS {quote_ident(out_name)}")
            output_columns.append(OutputColumn(
                name=out_name, type=col.type, level=col.level,
                lineage=col.lineage, masked=False,
            ))

    named_sql = (
        f"SELECT {', '.join(outer_items)} "
        f"FROM {root_rel.sql} AS {internal_quote(root_rel.alias)}"
    )
    # ORDER BY 在最外层按输出列内部名发射：根包装投影出的列在此处可见，
    # 排序作用于脱敏/投影之后的最终结果列。
    order_items = getattr(root_rel, "_order_items", [])
    if order_items:
        # 输出列内部名 -> 根包装内的可引用名（与 outer_items 同源）。
        name_to_output = {
            col.internal_name: col.output_name or col.internal_name
            for col in root_rel.columns
        }
        order_sql = ", ".join(
            f"{quote_ident(name_to_output[item['internal_name']])} "
            f"{item['direction']}"
            for item in order_items
        )
        named_sql += " ORDER BY " + order_sql
    # 按最终 SQL 文本中的出现顺序把命名占位符重写为 ? 并排参：
    # 根层盐位在文本上先于内层行谓词出现，不能按编译顺序绑定。
    placeholder_re = r":(p\d+|salt_\d+|rls_[A-Za-z0-9_]+)"
    placeholder_order = re.findall(placeholder_re, named_sql)
    sql = re.sub(placeholder_re, "?", named_sql)
    ordered_params = params.ordered(placeholder_order)

    # 回填行过滤说明的最终 ? 位置索引，供来源/策略说明与审计使用。
    key_to_index = {key: i for i, key in enumerate(placeholder_order)}
    rls_filters = []
    for info in root_rel.rls_filters:
        info = dict(info)
        info["bound_param_index"] = key_to_index.get(info["param_key"])
        rls_filters.append(info)

    snapshot = ctx.policy_snapshot()
    principal_digest = _digest({"principal": ctx.principal})
    plan_digest = _digest({
        "sql": sql,
        "params": ordered_params,
        "policy_version": ctx.policy_version,
        "schema_version": ctx.schema_version,
        "mask": ctx.mask_id,
        "principal": ctx.principal,
    })
    return CompiledQuery(
        sql=sql,
        params=ordered_params,
        columns=output_columns,
        rls_filters=rls_filters,
        policy_version=ctx.policy_version,
        schema_version=ctx.schema_version,
        mask_id=ctx.mask_id,
        principal_id=str(ctx.principal.get("id", "")),
        principal_digest=principal_digest,
        plan_digest=plan_digest,
        policy_snapshot=snapshot,
        ast_position_of_output=out_positions,
    )


def compile_from_document(document, query_index=0):
    """从原始 JSON 资料冻结上下文并编译指定查询。"""
    ctx = freeze(
        catalog=document["catalog"],
        policies=document["policies"],
        principal=document["principal"],
        policy_version=document["policy_version"],
        schema_version=document["schema_version"],
        mask_id=document["mask"],
    )
    try:
        query = document["queries"][query_index]
    except IndexError:
        raise fail("查询索引超出范围", ("queries", query_index))
    return compile_query(ctx, query, position=("queries", query_index))


def _digest(obj) -> str:
    raw = json.dumps(obj, ensure_ascii=False, sort_keys=True,
                     allow_nan=False, default=_json_default).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _json_default(o):
    if isinstance(o, tuple):
        return list(o)
    if isinstance(o, frozenset):
        return sorted(o)
    raise TypeError(f"不可序列化对象 {type(o)!r}")
