"""目录、策略与 principal 属性的一次冻结。

编译入口构造一次 FrozenContext：之后所有行谓词、列等级、类型解析与
principal 取值都不再变化。策略所需字段在扫描内部可信可用（行过滤），
但不会因此被赋予用户可见权限。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .ast_nodes import validate_expr
from .errors import fail

LEVELS = ("visible", "masked", "forbidden")
# 等级序：数值越大越受限。UNION 按位置取最严格者。
LEVEL_ORDER = {"visible": 0, "masked": 1, "forbidden": 2}


class LevelTools:
    @staticmethod
    def rank(level: str) -> int:
        return LEVEL_ORDER[level]

    @staticmethod
    def strictest(*levels: str) -> str:
        return max(levels, key=lambda lv: LEVEL_ORDER[lv])
# 物理名必须是安全标识符，再经双引号转义；白名单之外的名字无法进入 SQL。
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
TYPES = ("text", "integer", "real", "boolean")


@dataclass(frozen=True)
class ColumnSpec:
    id: int
    name: str
    type: str


@dataclass(frozen=True)
class TableSpec:
    name: str
    columns: tuple[ColumnSpec, ...]
    column_by_id: dict[int, ColumnSpec]

    def col(self, field_id: int, position=()) -> ColumnSpec:
        try:
            return self.column_by_id[field_id]
        except KeyError:
            raise fail(f"表 {self.name} 不存在字段ID {field_id}", position,
                       (self.name, field_id))


@dataclass(frozen=True)
class FrozenPolicy:
    table: str
    # 已通过形状校验的 eq_attr 行谓词原始 AST。
    row_predicate: dict | None
    row_field: int | None
    row_attribute: str | None
    column_levels: dict[int, str]

    def level_of(self, field_id: int) -> str:
        # 未登记即禁止：默认拒绝，绝不默认放行。
        return self.column_levels.get(field_id, "forbidden")


@dataclass(frozen=True)
class FrozenContext:
    tables: dict[str, TableSpec]
    policies: dict[str, FrozenPolicy]
    principal: dict[str, Any]
    policy_version: str
    schema_version: str
    mask_id: str

    def table(self, name: str, position=()) -> TableSpec:
        try:
            return self.tables[name]
        except KeyError:
            raise fail(f"表 {name!r} 不在目录白名单", position)

    def policy_for(self, table_name: str) -> FrozenPolicy:
        try:
            return self.policies[table_name]
        except KeyError:
            # 没有策略的表默认全禁止：编译无策略表等于无可读字段。
            return _deny_all_policy(table_name)

    def attr_value(self, attribute: str, position=()) -> Any:
        if attribute not in self.principal:
            raise fail(f"principal 缺少冻结属性 {attribute!r}", position)
        return self.principal[attribute]

    def policy_snapshot(self) -> dict:
        """用于绑定摘要的冻结策略快照（不含数据行）。"""
        return {
            "policy_version": self.policy_version,
            "schema_version": self.schema_version,
            "mask": self.mask_id,
            "principal": self.principal,
            "policies": {
                t: {
                    "row": p.row_predicate,
                    "columns": {str(k): v for k, v in sorted(p.column_levels.items())},
                }
                for t, p in sorted(self.policies.items())
            },
        }


def _deny_all_policy(table_name: str) -> FrozenPolicy:
    return FrozenPolicy(table_name, None, None, None, {})


def check_physical_name(name: str, position=()) -> str:
    if not isinstance(name, str) or not _IDENT_RE.fullmatch(name):
        raise fail(f"物理名 {name!r} 不符合白名单标识符规则", position)
    return name


def quote_ident(name: str) -> str:
    # 先过白名单正则，再做标准双引号转义，双重保险。
    check_physical_name(name)
    return '"' + name.replace('"', '""') + '"'


def freeze(catalog, policies, principal, policy_version, schema_version, mask_id):
    """把原始 JSON 资料冻结为编译上下文，并做全部结构校验。"""
    if not isinstance(catalog, list) or not catalog:
        raise fail("catalog 必须为非空数组", ("catalog",))
    tables: dict[str, TableSpec] = {}
    for ti, table in enumerate(catalog):
        tp = ("catalog", ti)
        name = table.get("name")
        check_physical_name(name, tp + ("name",))
        if name in tables:
            raise fail(f"表名 {name} 重复", tp)
        cols = []
        by_id = {}
        seen_names = set()
        for ci, col in enumerate(table.get("columns", [])):
            cp = tp + ("columns", ci)
            cid = col.get("id")
            if type(cid) is not int:
                raise fail("字段ID必须是整数", cp + ("id",))
            cname = col.get("name")
            check_physical_name(cname, cp + ("name",))
            ctype = col.get("type")
            if ctype not in TYPES:
                raise fail(f"未知字段类型 {ctype!r}", cp + ("type",))
            if cid in by_id or cname in seen_names:
                raise fail("字段ID或物理名重复", cp)
            spec = ColumnSpec(cid, cname, ctype)
            cols.append(spec)
            by_id[cid] = spec
            seen_names.add(cname)
        if not cols:
            raise fail("表至少需要一个字段", tp)
        tables[name] = TableSpec(name, tuple(cols), by_id)

    frozen_policies: dict[str, FrozenPolicy] = {}
    if not isinstance(policies, list):
        raise fail("policies 必须是数组", ("policies",))
    for pi, policy in enumerate(policies):
        pp = ("policies", pi)
        tname = policy.get("table")
        if tname not in tables:
            raise fail(f"策略表 {tname!r} 不在目录", pp + ("table",))
        if tname in frozen_policies:
            raise fail(f"表 {tname} 存在多条策略", pp)
        table_spec = tables[tname]
        levels = {}
        for raw_id, level in policy.get("columns", {}).items():
            cp = pp + ("columns", raw_id)
            try:
                fid = int(raw_id)
            except (TypeError, ValueError):
                raise fail("列规则键必须是字段ID字符串", cp)
            if level not in LEVELS:
                raise fail(f"列权限未知 {level!r}", cp)
            table_spec.col(fid, cp)
            levels[fid] = level
        row_ast = policy.get("row")
        row_field = row_attribute = None
        if row_ast is not None:
            rp = pp + ("row",)
            if not isinstance(row_ast, dict) or row_ast.get("op") != "eq_attr":
                raise fail("当前仅支持 eq_attr 行谓词", rp)
            if set(row_ast) != {"op", "field", "attribute"}:
                raise fail("eq_attr 只能含 op/field/attribute", rp)
            row_field = row_ast["field"]
            row_attribute = row_ast["attribute"]
            if type(row_field) is not int:
                raise fail("行谓词字段必须是字段ID整数", rp + ("field",))
            if not isinstance(row_attribute, str) or not row_attribute:
                raise fail("行谓词属性名非法", rp + ("attribute",))
            table_spec.col(row_field, rp + ("field",))
            # 编译成标准比较表达式后复用表达式校验管线；
            # 右侧在编译时替换为冻结 principal 字面量。
            predicate = {
                "op": "eq",
                "left": {"col": ["__row_policy__", row_field]},
                "right": {"literal": {"type": "text",
                                       "value": str(principal.get(row_attribute, ""))}},
            }
            validate_expr(predicate, rp)
            if row_attribute not in principal:
                raise fail(f"principal 缺少行谓词属性 {row_attribute!r}",
                           rp + ("attribute",))
            row_ast = predicate
        frozen_policies[tname] = FrozenPolicy(
            tname, row_ast, row_field, row_attribute, levels,
        )

    if not isinstance(principal, dict) or not principal:
        raise fail("principal 必须为非空对象", ("principal",))
    if not isinstance(policy_version, str) or not policy_version:
        raise fail("policy_version 必须为非空字符串", ("policy_version",))
    if not isinstance(schema_version, str) or not schema_version:
        raise fail("schema_version 必须为非空字符串", ("schema_version",))
    if not isinstance(mask_id, str) or not mask_id:
        raise fail("mask 必须为非空字符串", ("mask",))
    # 提前失败：引用未登记脱敏函数不应拖到投影阶段。
    from .masking import get_mask
    get_mask(mask_id)

    return FrozenContext(
        tables=tables,
        policies=frozen_policies,
        principal=dict(principal),
        policy_version=policy_version,
        schema_version=schema_version,
        mask_id=mask_id,
    )
