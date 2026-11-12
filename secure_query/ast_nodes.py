"""公开 AST 子集的严格形状校验。

契约（docs/data-contract.md）：
- 关系：scan(table,alias)、join(join_type=inner/left,left,right,on)、
  union_all(inputs)、select(from, where?, group_by?, having?, order_by?, project)
- 表达式：col=[关系别名,字段ID或输出列名]、literal={type,value}、
  eq/ne/lt/le/gt/ge、and/or/not/is_null、
  聚合 count_star/count/sum/min/max
- 不支持子查询、窗口、任意函数、相关引用、LIMIT 或原始 SQL。

校验只确认形状；名称、类型与权限由编译阶段解析。任何未知节点、未知键、
原始 SQL 片段（字符串形式的语句/函数名）一律拒绝。
"""
from __future__ import annotations

from .errors import fail

REL_KINDS = {"scan", "join", "union_all", "select"}
COMPARE_OPS = {"eq", "ne", "lt", "le", "gt", "ge"}
LOGIC_OPS = {"and", "or"}
UNARY_OPS = {"not", "is_null"}
AGG_FUNCS = {"count_star", "count", "sum", "min", "max"}
LITERAL_TYPES = {"text", "integer", "real", "boolean"}
# 表达式允许的全部键，防止 {"op": "...", "sql": "DROP TABLE ..."} 之类夹带。
_EXPR_EXTRA = {"op", "col", "literal", "left", "right", "expr", "func", "distinct"}
_PROJECT_KEYS = {"as", "expr", "star"}
_ORDER_KEYS = {"expr", "direction"}
_SELECT_KEYS = {
    "kind", "from", "where", "group_by", "having", "order_by", "project",
}
_SCAN_KEYS = {"kind", "table", "alias"}
_JOIN_KEYS = {"kind", "join_type", "left", "right", "on"}
_UNION_KEYS = {"kind", "inputs"}


def validate_statement(node, position=()):
    """递归校验整条语句（select 或 union_all 根）。"""
    _validate_relation(node, position, top=True, in_union=False)


def _validate_relation(node, position, top=False, in_union=False):
    if not isinstance(node, dict):
        raise fail("关系节点必须是对象", position)
    kind = node.get("kind")
    if kind not in REL_KINDS:
        raise fail(f"未知关系节点 {kind!r}，不接受原始SQL片段", position)
    if kind == "scan":
        _reject_extra(node, _SCAN_KEYS, position)
        if not _is_ident(node.get("table")) or not _is_ident(node.get("alias")):
            raise fail("scan 的 table/alias 必须为非空字符串", position)
    elif kind == "join":
        _reject_extra(node, _JOIN_KEYS, position)
        if node.get("join_type") not in ("inner", "left"):
            raise fail("仅支持 inner/left join", position + ("join_type",))
        _validate_relation(node["left"], position + ("left",))
        _validate_relation(node["right"], position + ("right",))
        validate_expr(node["on"], position + ("on",))
    elif kind == "union_all":
        _reject_extra(node, _UNION_KEYS, position)
        inputs = node.get("inputs")
        if not isinstance(inputs, list) or len(inputs) < 2:
            raise fail("union_all 至少需要两个输入分支", position)
        for i, branch in enumerate(inputs):
            # union 分支允许 select（契约内的组合关系），但不允许再嵌套
            # join 之外的子查询结构；分支 select 仍走完整 select 校验。
            _validate_relation(
                branch, position + ("inputs", i), in_union=True,
            )
    elif kind == "select":
        if not top and not in_union:
            # 通用子查询不在公开子集内；union 分支 select 是唯一合法的
            # 嵌套 select 位置。
            raise fail("不支持子查询，select 只能作为语句根或 union 分支",
                       position)
        _validate_select(node, position)


def _validate_select(node, position):
    _reject_extra(node, _SELECT_KEYS, position)
    if "from" not in node:
        raise fail("select 缺少 from", position)
    _validate_relation(node["from"], position + ("from",))
    if "where" in node:
        validate_expr(node["where"], position + ("where",))
    group_by = node.get("group_by", [])
    if not isinstance(group_by, list):
        raise fail("group_by 必须是表达式数组", position + ("group_by",))
    for i, e in enumerate(group_by):
        validate_expr(e, position + ("group_by", i))
    if "having" in node:
        validate_expr(node["having"], position + ("having",))
    order_by = node.get("order_by", [])
    if not isinstance(order_by, list):
        raise fail("order_by 必须是数组", position + ("order_by",))
    for i, item in enumerate(order_by):
        p = position + ("order_by", i)
        if not isinstance(item, dict):
            raise fail("排序项必须是对象", p)
        _reject_extra(item, _ORDER_KEYS, p)
        if item.get("direction", "asc") not in ("asc", "desc"):
            raise fail("排序方向只能是 asc/desc", p + ("direction",))
        validate_expr(item["expr"], p + ("expr",))
    project = node.get("project")
    if not isinstance(project, list) or not project:
        raise fail("project 必须为非空数组", position + ("project",))
    for i, item in enumerate(project):
        p = position + ("project", i)
        if not isinstance(item, dict):
            raise fail("投影项必须是对象", p)
        _reject_extra(item, _PROJECT_KEYS, p)
        if not _is_ident(item.get("as")):
            raise fail("投影别名 as 必须为非空字符串", p + ("as",))
        if "star" in item:
            if item["star"] is not True:
                raise fail("star 标记只能为 true", p + ("star",))
            if "expr" in item:
                raise fail("star 投影不能同时携带 expr", p)
        else:
            validate_expr(item["expr"], p + ("expr",))


def validate_expr(node, position):
    if not isinstance(node, dict):
        raise fail("表达式必须是对象", position)
    _reject_extra(node, _EXPR_EXTRA, position)
    if "col" in node:
        col = node["col"]
        if (
            not isinstance(col, list)
            or len(col) != 2
            or not _is_ident(col[0])
            or not isinstance(col[1], (str, int))
        ):
            raise fail("col 必须形如 [关系别名, 字段ID或输出列名]", position + ("col",))
        return
    if "literal" in node:
        lit = node["literal"]
        if not isinstance(lit, dict) or set(lit) != {"type", "value"}:
            raise fail("literal 必须只含 type/value", position + ("literal",))
        if lit["type"] not in LITERAL_TYPES:
            raise fail(f"不支持的字面量类型 {lit['type']!r}", position + ("literal", "type"))
        _check_literal_value(lit, position + ("literal",))
        return
    op = node.get("op")
    if op in COMPARE_OPS:
        validate_expr(node["left"], position + ("left",))
        validate_expr(node["right"], position + ("right",))
    elif op in LOGIC_OPS:
        validate_expr(node["left"], position + ("left",))
        validate_expr(node["right"], position + ("right",))
    elif op in UNARY_OPS:
        validate_expr(node["expr"], position + ("expr",))
    elif op == "aggregate":
        func = node.get("func")
        if func not in AGG_FUNCS:
            raise fail(f"未知聚合 {func!r}，任意函数不在公开子集", position + ("func",))
        if not isinstance(node.get("distinct", False), bool):
            raise fail("distinct 必须为布尔值", position + ("distinct",))
        if func == "count_star":
            if "expr" in node:
                raise fail("count_star 不接受参数", position)
        else:
            if "expr" not in node:
                raise fail(f"{func} 缺少聚合参数", position + ("expr",))
            validate_expr(node["expr"], position + ("expr",))
            if _contains_aggregate(node["expr"]):
                raise fail("不允许嵌套聚合", position + ("expr",))
    else:
        raise fail(f"未知表达式算子 {op!r}，不接受原始SQL片段", position)


def _contains_aggregate(node) -> bool:
    if isinstance(node, dict):
        if node.get("op") == "aggregate":
            return True
        return any(_contains_aggregate(v) for v in node.values())
    if isinstance(node, list):
        return any(_contains_aggregate(v) for v in node)
    return False


def _check_literal_value(lit, position):
    t, v = lit["type"], lit["value"]
    if t == "text":
        if not isinstance(v, str):
            raise fail("text 字面量必须是字符串", position + ("value",))
    elif t == "integer":
        # bool 是 int 的子类，显式排除。
        if type(v) is not int:
            raise fail("integer 字面量必须是整数", position + ("value",))
    elif t == "real":
        if type(v) is not float:
            raise fail("real 字面量必须是有限浮点", position + ("value",))
        if v != v or v in (float("inf"), float("-inf")):
            raise fail("不接受非有限浮点", position + ("value",))
    elif t == "boolean":
        if not isinstance(v, bool):
            raise fail("boolean 字面量必须是布尔", position + ("value",))


def _is_ident(x) -> bool:
    return isinstance(x, str) and bool(x)


def _reject_extra(node, allowed, position):
    extra = set(node) - allowed
    if extra:
        raise fail(f"出现契约外字段 {sorted(extra)!r}，疑似夹带", position)
