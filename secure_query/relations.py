"""关系层编译：scan/join/union 的标签传播与关系 SQL 骨架。

设计要点：
- 每个关系节点带一个内部别名（s/j/u/q 前缀，自动生成），列引用一律
  以 ``"内部别名"."内部列名"`` 限定；内部列名只取目录白名单物理名或
  q_/u_ 前缀生成名，用户字符串永远不会成为内部名。
- 行过滤在 scan 内部完成：left join 右侧被过滤的行根本不参与 ON 匹配，
  左表行只得到空扩展，绝不把右侧谓词挪到 WHERE。
- LabeledCol 携带原始字段坐标（table/field）与权限等级；重命名、重复别名、
  UNION 按位置对齐都不能洗白，UNION 任一分支受限即继承最严格等级。
"""
from __future__ import annotations

from dataclasses import dataclass, field as dc_field

from .context import FrozenContext, LevelTools, quote_ident
from .errors import fail


@dataclass
class LabeledCol:
    """中间关系的一列。

    holder_alias : 当前持有该列的关系内部 SQL 别名（限定引用用）
    user_aliases : 用户可见的关系别名集合（col 引用解析用）
    internal_name: 当前关系内的内部列名（白名单物理名或生成名）
    lineage      : 原始字段来源链，元素为 {table, field, field_name, ...}
    level        : visible / masked / forbidden
    """

    holder_alias: str
    user_aliases: frozenset[str]
    internal_name: str
    type: str
    lineage: tuple[dict, ...]
    level: str
    needs_mask: bool = False
    output_name: str | None = None

    def matches_ref(self, rel_alias, ref) -> bool:
        if rel_alias not in self.user_aliases:
            return False
        for src in self.lineage:
            if src.get("field") == ref or src.get("field_name") == ref:
                return True
        return False


@dataclass
class CompiledRelation:
    sql: str
    alias: str
    columns: list[LabeledCol]
    rls_filters: list[dict]
    output_alias_map: dict = dc_field(default_factory=dict)
    is_select: bool = False
    is_union: bool = False


class ParamBank:
    """绑定参数仓库。

    SQL 嵌套后，占位符在最终文本中的出现顺序与编译顺序不一致
    （根层脱敏盐位会先于内层行谓词出现），因此每个参数带一个编译期键，
    SQL 全部发射完成后按占位符出现顺序重排。
    """

    def __init__(self):
        self.values: list = []
        self._by_key: dict[str, object] = {}

    def add(self, value, key: str | None = None) -> str:
        if key is None:
            key = f"p{len(self._by_key)}"
        # 同一表被多次扫描（自连接）会产生同名行谓词键，追加唯一后缀。
        if key in self._by_key:
            n = 1
            while f"{key}__{n}" in self._by_key:
                n += 1
            key = f"{key}__{n}"
        self._by_key[key] = value
        return f":{key}"

    def ordered(self, placeholder_order: list[str]) -> list:
        missing = [k for k in placeholder_order if k not in self._by_key]
        extra = set(self._by_key) - set(placeholder_order)
        if missing or extra:
            raise AssertionError(f"占位符与参数不符 missing={missing} extra={sorted(extra)}")
        return [self._by_key[k] for k in placeholder_order]


class AliasGen:
    def __init__(self):
        self._n = 0

    def make(self, prefix: str) -> str:
        name = f"{prefix}_{self._n}"
        self._n += 1
        return name


def internal_quote(name: str) -> str:
    # 受控内部名有两类：目录白名单物理名（freeze 时已过标识符正则），
    # 以及 q_/u_/j_/s_ 前缀生成名；quote_ident 会再次校验白名单标识符规则。
    return quote_ident(name)


def col_ref(col: LabeledCol) -> str:
    return f"{internal_quote(col.holder_alias)}.{internal_quote(col.internal_name)}"


def find_column(columns: list[LabeledCol], rel_alias, ref, position):
    """解析 [关系别名, 字段ID或输出列名]；未知/歧义一律拒绝。"""
    matches = [c for c in columns if c.matches_ref(rel_alias, ref)]
    if not matches:
        raise fail(f"未知列引用 [{rel_alias}, {ref!r}]", position)
    if len(matches) > 1:
        raise fail(f"列引用 [{rel_alias}, {ref!r}] 存在歧义", position)
    return matches[0]


def field_coordinate(col: LabeledCol):
    for src in col.lineage:
        if "table" in src and "field" in src:
            return (src["table"], src["field"])
    return None


def collect_aliases(node, seen: set, position):
    """契约：每层关系别名唯一；union 分支各自独立作用域。"""
    if not isinstance(node, dict):
        raise fail("关系节点必须是对象", position)
    kind = node.get("kind")
    if kind == "scan":
        alias = node.get("alias")
        if not isinstance(alias, str) or not alias:
            raise fail("scan 别名必须为非空字符串", position + ("alias",))
        if alias in seen:
            raise fail(f"关系别名 {alias!r} 重复，别名遮蔽不允许", position)
        seen.add(alias)
    elif kind == "join":
        collect_aliases(node["left"], seen, position + ("left",))
        collect_aliases(node["right"], seen, position + ("right",))
    elif kind == "union_all":
        for i, branch in enumerate(node["inputs"]):
            collect_aliases(branch, set(seen), position + ("inputs", i))
    elif kind == "select":
        collect_aliases(node["from"], seen, position + ("from",))


# ---------------------------------------------------------------- scan

def compile_scan(ctx: FrozenContext, node, position, aliases: AliasGen,
                 params: ParamBank):
    table_name = node["table"]
    user_alias = node["alias"]
    table = ctx.table(table_name, position)
    policy = ctx.policy_for(table_name)
    # 物理表与派生子查询必须使用不同内部名，否则 WHERE 会被绑定到
    # 同名派生表（全量行），行过滤静默失效。
    base_alias = aliases.make("b")
    internal_alias = aliases.make("s")

    select_items = []
    labeled: list[LabeledCol] = []
    for col_spec in table.columns:
        level = policy.level_of(col_spec.id)
        labeled.append(LabeledCol(
            holder_alias=internal_alias,
            user_aliases=frozenset({user_alias}),
            internal_name=col_spec.name,
            type=col_spec.type,
            lineage=({
                "table": table_name,
                "field": col_spec.id,
                "field_name": col_spec.name,
                "stage": "scan",
            },),
            level=level,
        ))
        select_items.append(
            f"{internal_quote(base_alias)}.{quote_ident(col_spec.name)} "
            f"AS {quote_ident(col_spec.name)}"
        )

    where_sql = None
    rls_info = None
    if policy.row_predicate is not None:
        from .expr_compiler import compile_policy_predicate
        where_sql, rls_info = compile_policy_predicate(
            ctx, policy, table, base_alias, params, position + ("row",),
        )

    sql = (
        "SELECT " + ", ".join(select_items)
        + " FROM " + quote_ident(table_name)
        + " AS " + internal_quote(base_alias)
    )
    if where_sql is not None:
        sql += " WHERE " + where_sql
    return CompiledRelation(
        sql=f"({sql})",
        alias=internal_alias,
        columns=labeled,
        rls_filters=[rls_info] if rls_info else [],
    )


# ---------------------------------------------------------------- join

def compile_join(ctx: FrozenContext, node, position, aliases, params,
                 relation_compiler):
    left_rel = relation_compiler(node["left"], position + ("left",))
    right_rel = relation_compiler(node["right"], position + ("right",))
    join_alias = aliases.make("j")
    from .expr_compiler import compile_on
    on_sql = compile_on(ctx, node["on"], left_rel, right_rel, params,
                        position + ("on",))
    join_type = node["join_type"].upper()
    sql = (
        f"({left_rel.sql} AS {internal_quote(left_rel.alias)} "
        f"{join_type} JOIN {right_rel.sql} AS {internal_quote(right_rel.alias)} "
        f"ON {on_sql})"
    )
    # join 不改写子列的 holder：ON 与上层引用仍可限定到具体一侧。
    columns = list(left_rel.columns) + list(right_rel.columns)
    return CompiledRelation(
        sql=sql,
        alias=join_alias,
        columns=columns,
        rls_filters=left_rel.rls_filters + right_rel.rls_filters,
    )


# ---------------------------------------------------------------- union

def compile_union(ctx: FrozenContext, node, position, aliases, params,
                  select_compiler):
    branches = []
    for i, branch in enumerate(node["inputs"]):
        bp = position + ("inputs", i)
        if branch.get("kind") != "select":
            raise fail("union_all 分支必须是 select", bp)
        # 分支允许 masked 裸列向下传递，根层统一脱敏。
        branches.append(
            select_compiler(branch, bp, is_root=False,
                            masked_passthrough=True),
        )

    width = len(branches[0].columns)
    for i, rel in enumerate(branches[1:], start=1):
        if len(rel.columns) != width:
            raise fail(
                f"union_all 第 {i} 分支列数 {len(rel.columns)} "
                f"与首分支 {width} 不一致",
                position + ("inputs", i),
            )

    union_alias = aliases.make("u")
    merged: list[LabeledCol] = []
    for pos in range(width):
        first = branches[0].columns[pos]
        lineage: list[dict] = []
        user_aliases: set[str] = set()
        types = set()
        worst = "visible"
        needs_mask = False
        for bi, rel in enumerate(branches):
            col = rel.columns[pos]
            types.add(col.type)
            worst = LevelTools.strictest(worst, col.level)
            user_aliases.update(col.user_aliases)
            # 任一分支该位置带脱敏标记，合并列就在根层脱敏。
            needs_mask = needs_mask or col.needs_mask
            for src in col.lineage:
                lineage.append({**src, "union_branch": bi})
        if len(types) != 1:
            raise fail(
                f"union_all 第 {pos + 1} 列类型不一致: {sorted(types)}",
                position,
            )
        merged_name = f"u_{pos}"
        merged.append(LabeledCol(
            holder_alias=union_alias,
            user_aliases=frozenset(user_aliases),
            internal_name=merged_name,
            type=first.type,
            lineage=tuple(lineage),
            level=worst,
            needs_mask=needs_mask,
            # 契约：union 以首分支列名输出。
            output_name=first.output_name,
        ))

    # 延迟导入避免 relations <-> expr_compiler 循环。
    from .expr_compiler import col_ref as emit_col_ref
    parts = []
    for rel in branches:
        items = ", ".join(
            f"{emit_col_ref(c)} AS {internal_quote(merged[i].internal_name)}"
            for i, c in enumerate(rel.columns)
        )
        parts.append(
            f"SELECT {items} FROM {rel.sql} AS {internal_quote(rel.alias)}"
        )
    sql = "(" + " UNION ALL ".join(parts) + ")"
    return CompiledRelation(
        sql=sql,
        alias=union_alias,
        columns=merged,
        rls_filters=[f for rel in branches for f in rel.rls_filters],
        is_union=True,
    )
