"""逐行安全参考解释器。

与编译 SQL 完全独立的第二实现：直接在基表数据行上执行，行谓词先于
一切关系运算生效。用于与 SQLite 编译结果逐行对照，证明无权基表行
从未参与 join、过滤、分组与聚合。

解释器复用编译期的 AST 形状校验与冻结上下文，但不导入 SQL 发射代码，
也不读取编译产物中的 SQL 文本。
"""
from __future__ import annotations

from dataclasses import dataclass

from . import ast_nodes
from .context import FrozenContext
from .errors import fail
from .masking import get_mask
from .relations import collect_aliases


@dataclass
class IColumn:
    name: str           # 当前作用域内的列名（字段物理名或 q_/u_ 生成名）
    type: str
    lineage: tuple
    level: str
    user_aliases: frozenset
    output_name: str | None = None
    needs_mask: bool = False


@dataclass
class IRelation:
    columns: list[IColumn]
    rows: list[list]           # 与 columns 等长、按列对齐的值行
    rls_applied: list[dict]


def interpret(ctx: FrozenContext, query_ast, tables_rows: dict, position=()):
    """返回 (输出列说明, 脱敏后的结果行)。tables_rows: 表名 -> 行列表。"""
    ast_nodes.validate_statement(query_ast, position)
    collect_aliases(
        query_ast["from"] if query_ast["kind"] == "select" else query_ast,
        set(), position,
    )
    state = _State(ctx, tables_rows, position)
    if query_ast["kind"] == "union_all":
        rel = state.union_all(query_ast, position)
    else:
        rel = state.select(query_ast, position, is_root=True)
    return state.finalize(rel)


class _State:
    def __init__(self, ctx: FrozenContext, tables_rows: dict, root_position):
        self.ctx = ctx
        self.tables_rows = tables_rows
        self.root_position = root_position
        self._seq = 0

    def _gen(self, prefix):
        name = f"{prefix}_{self._seq}"
        self._seq += 1
        return name

    # ------------------------------------------------------------ scan

    def scan(self, node, position):
        table_name = node["table"]
        user_alias = node["alias"]
        table = self.ctx.table(table_name, position)
        policy = self.ctx.policy_for(table_name)
        raw_rows = self.tables_rows.get(table_name)
        if raw_rows is None:
            raise fail(f"缺少基表 {table_name} 的数据", position)

        columns = [
            IColumn(
                name=col.name, type=col.type,
                lineage=({
                    "table": table_name, "field": col.id,
                    "field_name": col.name, "stage": "scan",
                },),
                level=policy.level_of(col.id),
                user_aliases=frozenset({user_alias}),
            )
            for col in table.columns
        ]
        rls_applied = []
        rows = []
        for raw in raw_rows:
            if len(raw) != len(table.columns):
                raise fail(f"基表 {table_name} 行宽与 schema 不符", position)
            row = list(raw)
            if policy.row_predicate is not None:
                keep, rls_info = self._row_passes(
                    policy, table, row, columns, position,
                )
                # 同表所有行共用同一谓词说明，登记一次即可。
                if not rls_applied:
                    rls_applied.append(rls_info)
                if not keep:
                    continue
            rows.append(row)
        return IRelation(
            columns=columns, rows=rows,
            rls_applied=rls_applied,
        )

    def _row_passes(self, policy, table, row, columns, position):
        field_idx = next(
            i for i, c in enumerate(table.columns) if c.id == policy.row_field
        )
        attr_value = self.ctx.attr_value(
            policy.row_attribute, position + ("row", "attribute"),
        )
        # 严格等值：null 不相等（与 SQL 三值逻辑下 col = NULL 被过滤一致）。
        keep = row[field_idx] is not None and row[field_idx] == attr_value
        info = {
            "table": table.name,
            "field": policy.row_field,
            "field_name": table.columns[field_idx].name,
            "attribute": policy.row_attribute,
            "op": "eq_attr",
            "position": list(position + ("row",)),
        }
        return keep, info

    # ------------------------------------------------------------ join

    def join(self, node, position):
        left = self.relation(node["left"], position + ("left",))
        right = self.relation(node["right"], position + ("right",))
        columns = self._join_columns(left.columns, right.columns)
        rows = []
        for lrow in left.rows:
            matched = False
            for rrow in right.rows:
                combined = lrow + rrow
                if self._truthy(node["on"], combined, columns,
                                position + ("on",)):
                    rows.append(combined)
                    matched = True
            if not matched and node["join_type"] == "left":
                # 左连接空扩展：右侧全部为 NULL，左行绝不因右表过滤而消失。
                rows.append(lrow + [None] * len(right.columns))
        return IRelation(
            columns=columns, rows=rows,
            rls_applied=left.rls_applied + right.rls_applied,
        )

    def _join_columns(self, left_cols, right_cols):
        out = []
        for c in left_cols + right_cols:
            out.append(IColumn(
                name=c.name, type=c.type, lineage=c.lineage, level=c.level,
                user_aliases=c.user_aliases,
            ))
        return out

    # ------------------------------------------------------------ union

    def union_all(self, node, position):
        branches = [
            self.select(b, position + ("inputs", i), is_root=False,
                        masked_passthrough=True)
            for i, b in enumerate(node["inputs"])
        ]
        width = len(branches[0].columns)
        for i, rel in enumerate(branches[1:], start=1):
            if len(rel.columns) != width:
                raise fail(f"union 第 {i} 分支列数不一致",
                           position + ("inputs", i))
        columns = []
        for pos in range(width):
            first = branches[0].columns[pos]
            types = {rel.columns[pos].type for rel in branches}
            if len(types) != 1:
                raise fail(f"union 第 {pos + 1} 列类型不一致", position)
            worst = max(
                (rel.columns[pos].level for rel in branches),
                key=lambda lv: {"visible": 0, "masked": 1, "forbidden": 2}[lv],
            )
            needs_mask = any(rel.columns[pos].needs_mask for rel in branches)
            aliases = frozenset().union(*(
                rel.columns[pos].user_aliases for rel in branches
            ))
            lineage = tuple(
                {**s, "union_branch": bi}
                for bi, rel in enumerate(branches)
                for s in rel.columns[pos].lineage
            )
            columns.append(IColumn(
                name=self._gen("u"), type=first.type, lineage=lineage,
                level=worst, user_aliases=aliases,
                output_name=first.output_name, needs_mask=needs_mask,
            ))
        rows = []
        for rel in branches:
            for row in rel.rows:
                rows.append(list(row))
        return IRelation(
            columns=columns, rows=rows,
            rls_applied=[f for rel in branches for f in rel.rls_applied],
        )

    # ------------------------------------------------------------ select

    def select(self, node, position, *, is_root, masked_passthrough=False):
        src = self.relation(node["from"], position + ("from",))
        scope = list(src.columns)

        if "where" in node:
            # 生成新的行列表，绝不原地改写子关系：join 列对象与子关系共享，
            # 原地改行会污染同一编译树中的其他求值路径。
            filtered = [
                row for row in src.rows
                if self._truthy(node["where"], row, scope,
                                position + ("where",))
            ]
            src = IRelation(
                columns=list(src.columns), rows=filtered,
                rls_applied=list(src.rls_applied),
            )
            scope = list(src.columns)

        group_nodes = node.get("group_by", [])
        projections = self._expand_stars(node["project"], scope, position)
        has_aggregate = any(
            self._contains_aggregate(proj["expr"]) for proj, _ in projections
        )

        if not group_nodes and not has_aggregate and "having" not in node:
            # 逐行模式：每条输入行产生一条输出行，保留全部行。
            out_columns, out_rows = self._project_rows(
                node, projections, src.rows, scope, position, is_root,
                masked_passthrough,
            )
            rel = IRelation(
                columns=out_columns, rows=out_rows,
                rls_applied=src.rls_applied,
            )
            self._order(node, rel, scope, [src.rows], position)
            return rel

        # 分组模式：无 GROUP BY 但有聚合/HAVING 时整个输入为一个组
        # （空输入也保留一个空组，使 COUNT(*) 为 0）。
        groups, group_scope = self._group(
            node, src, scope, group_nodes, position,
        )
        out_columns, out_rows = self._project_groups(
            node, projections, groups, group_scope, position, is_root,
            bool(group_nodes), masked_passthrough,
        )
        rel = IRelation(
            columns=out_columns, rows=out_rows, rls_applied=src.rls_applied,
        )
        self._order(node, rel, scope, groups, position)
        return rel

    def _project_rows(self, node, projections, input_rows, scope, position,
                      is_root, masked_passthrough):
        out_columns = []
        out_rows = [[] for _ in input_rows]
        seen_names = set()
        for proj, proj_pos in projections:
            out_name = proj["as"]
            if out_name in seen_names:
                raise fail(f"输出别名 {out_name!r} 重复", proj_pos + ("as",))
            seen_names.add(out_name)
            expr = proj["expr"]
            bare_masked = self._is_bare_level(expr, scope, "masked")
            allow_masked = (is_root or masked_passthrough) and bare_masked
            if bare_masked and not (is_root or masked_passthrough):
                raise fail("masked 列不能在嵌套 SELECT 保留原值", proj_pos)
            level, lineage, vtype, needs_mask = self._expr_meta(
                expr, scope, proj_pos, allow_masked,
            )
            gen_name = self._gen("q")
            out_columns.append(IColumn(
                name=gen_name, type=vtype, lineage=lineage, level=level,
                user_aliases=frozenset(), output_name=out_name,
                needs_mask=needs_mask,
            ))
            for ri, row in enumerate(input_rows):
                out_rows[ri].append(
                    self._eval(expr, row, scope, proj_pos + ("expr",),
                               allow_masked=allow_masked),
                )
        return out_columns, out_rows

    def _project_groups(self, node, projections, groups, scope, position,
                        is_root, is_grouped, masked_passthrough):
        out_columns = []
        out_rows = [[] for _ in groups]
        seen_names = set()
        has_agg = False
        for proj, proj_pos in projections:
            out_name = proj["as"]
            if out_name in seen_names:
                raise fail(f"输出别名 {out_name!r} 重复", proj_pos + ("as",))
            seen_names.add(out_name)
            expr = proj["expr"]
            bare_masked = self._is_bare_level(expr, scope, "masked")
            allow_masked = (is_root or masked_passthrough) and bare_masked
            if bare_masked and not (is_root or masked_passthrough):
                raise fail("masked 列不能在嵌套 SELECT 保留原值", proj_pos)
            level, lineage, vtype, needs_mask = self._expr_meta(
                expr, scope, proj_pos, allow_masked,
            )
            is_agg = self._contains_aggregate(expr)
            has_agg = has_agg or is_agg
            if is_grouped and not is_agg:
                if not self._in_group_by(expr, node.get("group_by", []),
                                         scope, proj_pos):
                    raise fail("非聚合投影必须出现在 GROUP BY 中", proj_pos)
            gen_name = self._gen("q")
            out_columns.append(IColumn(
                name=gen_name, type=vtype, lineage=lineage, level=level,
                user_aliases=frozenset(), output_name=out_name,
                needs_mask=needs_mask,
            ))
            for gi, group_rows in enumerate(groups):
                if is_agg:
                    value = self._eval_aggregate(expr, group_rows, scope,
                                                 proj_pos)
                elif not group_rows:
                    value = None
                else:
                    value = self._eval(expr, group_rows[0], scope,
                                       proj_pos + ("expr",),
                                       allow_masked=allow_masked)
                out_rows[gi].append(value)
        return out_columns, out_rows

    def _group(self, node, src, scope, group_nodes, position):
        if not group_nodes and "having" not in node:
            # 无 GROUP BY 无 HAVING：聚合时整个输入是一个组（可为空组）。
            return [src.rows], scope
        if not group_nodes:
            # HAVING 无 GROUP BY：整个输入为单组，按 HAVING 过滤组。
            groups = [src.rows]
        else:
            buckets: dict = {}
            order = []
            for row in src.rows:
                key = tuple(
                    self._eval(g, row, scope, position + ("group_by", i),
                               allow_masked=False)
                    for i, g in enumerate(group_nodes)
                )
                if key not in buckets:
                    buckets[key] = []
                    order.append(key)
                buckets[key].append(row)
            groups = [buckets[k] for k in order]
        if "having" in node:
            hp = position + ("having",)
            kept = []
            for group_rows in groups:
                if self._having_truthy(node["having"], group_rows, scope, hp):
                    kept.append(group_rows)
            groups = kept
        return groups, scope

    def _having_truthy(self, node, group_rows, scope, position):
        value = self._eval_having(node, group_rows, scope, position)
        return value is True

    def _eval_having(self, node, group_rows, scope, position):
        if "literal" in node:
            return node["literal"]["value"]
        if "col" in node:
            # HAVING 裸列必须是 GROUP BY 列，组内取值一致，取首行即可。
            if not group_rows:
                return None
            return self._eval(node, group_rows[0], scope, position,
                              allow_masked=False)
        op = node["op"]
        if op in ("eq", "ne", "lt", "le", "gt", "ge"):
            lv = self._having_operand(node["left"], group_rows, scope,
                                      position + ("left",))
            rv = self._having_operand(node["right"], group_rows, scope,
                                      position + ("right",))
            if lv is None or rv is None:
                return None
            return {
                "eq": lv == rv, "ne": lv != rv, "lt": lv < rv,
                "le": lv <= rv, "gt": lv > rv, "ge": lv >= rv,
            }[op]
        if op in ("and", "or"):
            lv = self._eval_having(node["left"], group_rows, scope,
                                   position + ("left",))
            rv = self._eval_having(node["right"], group_rows, scope,
                                   position + ("right",))
            return {"and": _three_and(lv, rv), "or": _three_or(lv, rv)}[op]
        if op == "not":
            v = self._eval_having(node["expr"], group_rows, scope,
                                  position + ("expr",))
            return None if v is None else not v
        if op == "is_null":
            v = self._having_operand(node["expr"], group_rows, scope,
                                     position + ("expr",))
            return v is None
        if op == "aggregate":
            return self._eval_aggregate(node, group_rows, scope, position)
        raise fail(f"HAVING 不支持的算子 {op!r}", position)

    def _having_operand(self, node, group_rows, scope, position):
        if node.get("op") == "aggregate":
            return self._eval_aggregate(node, group_rows, scope, position)
        return self._eval_having(node, group_rows, scope, position)

    def _order(self, node, rel, input_scope, groups, position):
        order_items = node.get("order_by", [])
        if not order_items:
            return
        # 排序在投影后执行：裸列若指向输入关系，按组内代表行从输入 scope
        # 取值（与编译器回退输入 scope 一致）；输出名引用则取结果列。
        representative = groups[0][0] if groups and groups[0] else None
        indexed = list(enumerate(rel.rows))

        def sort_key(pair):
            idx, row = pair
            keys = []
            for item in order_items:
                expr = item["expr"]
                if "col" in expr:
                    value = self._order_col_value(
                        expr, row, rel.columns, input_scope, representative,
                        position,
                    )
                else:
                    value = self._eval(
                        expr, row, rel.columns,
                        position + ("order_by",) + ("expr",),
                        allow_masked=False, output_lookup=rel.columns,
                    )
                # NULL 排最前（与 SQLite 默认 ASC NULLS FIRST 对齐）。
                keys.append((value is None, value))
            return tuple(keys)

        directions = [i.get("direction", "asc") for i in order_items]
        import functools

        def cmp(a, b):
            ka, kb = sort_key(a), sort_key(b)
            for (na, va), (nb, vb), direction in zip(ka, kb, directions):
                if na and nb:
                    continue
                if na:
                    return -1
                if nb:
                    return 1
                if va == vb:
                    continue
                less = va < vb
                return -1 if less == (direction == "asc") else 1
            return 0

        indexed.sort(key=functools.cmp_to_key(cmp))
        rel.rows = [row for _, row in indexed]

    def _order_col_value(self, expr, out_row, out_columns, input_scope,
                         representative, position):
        rel_alias, name = expr["col"]
        # 输出名引用（ORDER BY 可引用投影别名）。
        if isinstance(name, str):
            for idx, col in enumerate(out_columns):
                if col.output_name == name:
                    self._assert_orderable(col, position)
                    return out_row[idx]
        # 输入关系裸列引用：权限检查后从输入 scope 解析。
        matches = [
            (i, c) for i, c in enumerate(input_scope)
            if rel_alias in c.user_aliases and any(
                s.get("field") == name or s.get("field_name") == name
                for s in c.lineage
            )
        ]
        if not matches:
            raise fail(f"ORDER BY 未知列 [{rel_alias}, {name!r}]", position)
        if len(matches) > 1:
            raise fail("ORDER BY 列引用歧义", position)
        idx, col = matches[0]
        self._assert_orderable(col, position)
        if representative is None:
            return None
        return representative[idx]

    def _assert_orderable(self, col, position):
        if col.level == "forbidden":
            raise fail("forbidden 列禁止用于排序", position,
                       self._coordinate(col))
        if col.level == "masked" or col.needs_mask:
            raise fail("masked 列禁止排序探测原值", position,
                       self._coordinate(col))

    # ------------------------------------------------------------ 表达式

    def _eval(self, node, row, scope, position, *, allow_masked,
              output_lookup=None):
        if "col" in node:
            col, idx = self._resolve(node["col"], scope, position,
                                     output_lookup)
            if col.level == "forbidden":
                raise fail("forbidden 列禁止引用", position,
                           self._coordinate(col))
            if col.level == "masked" and not allow_masked:
                raise fail("masked 列禁止计算/过滤/排序探测原值",
                           position, self._coordinate(col))
            return row[idx]
        if "literal" in node:
            return node["literal"]["value"]
        op = node["op"]
        if op in ("eq", "ne", "lt", "le", "gt", "ge"):
            lv = self._eval(node["left"], row, scope,
                            position + ("left",), allow_masked=False)
            rv = self._eval(node["right"], row, scope,
                            position + ("right",), allow_masked=False)
            if lv is None or rv is None:
                return None
            return {
                "eq": lv == rv, "ne": lv != rv, "lt": lv < rv,
                "le": lv <= rv, "gt": lv > rv, "ge": lv >= rv,
            }[op]
        if op in ("and", "or"):
            lv = self._eval(node["left"], row, scope,
                            position + ("left",), allow_masked=False)
            rv = self._eval(node["right"], row, scope,
                            position + ("right",), allow_masked=False)
            return {"and": _three_and(lv, rv), "or": _three_or(lv, rv)}[op]
        if op == "not":
            v = self._eval(node["expr"], row, scope,
                           position + ("expr",), allow_masked=False)
            return None if v is None else (not v)
        if op == "is_null":
            v = self._eval(node["expr"], row, scope,
                           position + ("expr",), allow_masked=False)
            return v is None
        if op == "aggregate":
            raise fail("聚合只能出现在投影/HAVING 的分组求值中", position)
        raise fail(f"未知表达式算子 {op!r}", position)

    def _eval_aggregate(self, node, group_rows, scope, position):
        func = node["func"]
        if func == "count_star":
            return len(group_rows)
        arg_node = node["expr"]
        distinct = node.get("distinct", False)
        values = [
            self._eval(arg_node, r, scope, position + ("expr",),
                       allow_masked=False)
            for r in group_rows
        ]
        non_null = [v for v in values if v is not None]
        if distinct:
            non_null = list(dict.fromkeys(non_null))
        if func == "count":
            return len(non_null)
        if not non_null:
            return None
        if func == "sum":
            return sum(non_null)
        if func == "min":
            return min(non_null)
        if func == "max":
            return max(non_null)
        raise fail(f"未知聚合 {func}", position)

    def _truthy(self, node, row, scope, position):
        value = self._eval(node, row, scope, position, allow_masked=False)
        return value is True

    def _resolve(self, ref, scope, position, output_lookup=None):
        rel_alias, name = ref
        if output_lookup is not None and isinstance(name, str):
            for idx, col in enumerate(output_lookup):
                if col.output_name == name:
                    return col, idx
        matches = [
            (i, c) for i, c in enumerate(scope)
            if rel_alias in c.user_aliases and any(
                s.get("field") == name or s.get("field_name") == name
                for s in c.lineage
            )
        ]
        if not matches:
            raise fail(f"未知列引用 [{rel_alias}, {name!r}]", position)
        if len(matches) > 1:
            raise fail(f"列引用 [{rel_alias}, {name!r}] 歧义", position)
        idx, col = matches[0]
        return col, idx

    def _expr_meta(self, expr, scope, position, allow_masked):
        """与编译器同源的等级/类型推断（独立实现，避免读 SQL）。"""
        if "col" in expr:
            col, _ = self._resolve(expr["col"], scope,
                                   position + ("expr", "col"))
            if col.level == "forbidden":
                raise fail("forbidden 列禁止引用", position,
                           self._coordinate(col))
            if col.level == "masked" and not allow_masked:
                raise fail("masked 列只能在最外层直接投影",
                           position, self._coordinate(col))
            return col.level, col.lineage, col.type, col.level == "masked"
        if "literal" in expr:
            return "visible", (), expr["literal"]["type"], False
        op = expr["op"]
        if op in ("eq", "ne", "lt", "le", "gt", "ge", "and", "or",
                  "not", "is_null"):
            child_nodes = [expr.get(k) for k in ("left", "right", "expr")
                           if expr.get(k) is not None]
            metas = [
                self._expr_meta(c, scope, position, False)
                for c in child_nodes
            ]
            worst = max((m[0] for m in metas),
                        key=lambda lv: {"visible": 0, "masked": 1,
                                        "forbidden": 2}[lv])
            lineage = tuple(x for m in metas for x in m[1])
            return worst, lineage, "boolean", False
        if op == "aggregate":
            if expr["func"] == "count_star":
                return "visible", (), "integer", False
            meta = self._expr_meta(expr["expr"], scope, position, False)
            if meta[0] != "visible":
                raise fail("聚合输入含受限列，禁止先算后遮", position)
            func = expr["func"]
            vtype = "integer" if func == "count" else meta[2]
            return "visible", meta[1], vtype, False
        raise fail(f"未知表达式算子 {op!r}", position)

    def _contains_aggregate(self, node):
        if isinstance(node, dict):
            if node.get("op") == "aggregate":
                return True
            return any(self._contains_aggregate(v) for v in node.values())
        if isinstance(node, list):
            return any(self._contains_aggregate(v) for v in node)
        return False

    def _is_bare_level(self, expr, scope, level):
        if "col" not in expr:
            return False
        rel_alias, name = expr["col"]
        hits = [
            c for c in scope
            if rel_alias in c.user_aliases and any(
                s.get("field") == name or s.get("field_name") == name
                for s in c.lineage
            )
        ]
        return len(hits) == 1 and hits[0].level == level

    def _in_group_by(self, expr, group_nodes, scope, position):
        if "col" not in expr:
            return False
        col, _ = self._resolve(expr["col"], scope, position)
        coords = {(s["table"], s["field"]) for s in col.lineage
                  if "table" in s and "field" in s}
        for g in group_nodes:
            if "col" not in g:
                continue
            gc, _ = self._resolve(g["col"], scope, position)
            gcoords = {(s["table"], s["field"]) for s in gc.lineage
                       if "table" in s and "field" in s}
            if coords == gcoords:
                return True
        return False

    def _expand_stars(self, project, scope, position):
        out = []
        for i, item in enumerate(project):
            p = position + ("project", i)
            if item.get("star") is True:
                for col in scope:
                    if not col.user_aliases:
                        raise fail("星号只能展开带关系别名的输入列", p)
                    src = next(iter(col.lineage))
                    alias = next(iter(col.user_aliases))
                    out.append((
                        {"as": col.output_name or col.name,
                         "expr": {"col": [alias, src["field"]]}},
                        p,
                    ))
            else:
                out.append((item, p))
        return out

    def _coordinate(self, col):
        for s in col.lineage:
            if "table" in s and "field" in s:
                return (s["table"], s["field"])
        return None

    # ------------------------------------------------------------ 关系分发

    def relation(self, node, position):
        kind = node["kind"]
        if kind == "scan":
            return self.scan(node, position)
        if kind == "join":
            return self.join(node, position)
        if kind == "union_all":
            return self.union_all(node, position)
        if kind == "select":
            return self.select(node, position, is_root=False)
        raise fail(f"未知关系节点 {kind!r}", position)

    def finalize(self, rel: IRelation):
        mask = get_mask(self.ctx.mask_id)
        masked_rows = []
        for row in rel.rows:
            new_row = []
            for col, value in zip(rel.columns, row):
                if col.needs_mask:
                    new_row.append(mask.python_impl(value))
                else:
                    new_row.append(value)
            masked_rows.append(new_row)
        out_cols = [
            {
                "name": c.output_name or c.name,
                "type": "text" if c.needs_mask else c.type,
                "level": c.level,
                "lineage": c.lineage,
                "masked": c.needs_mask,
            }
            for c in rel.columns
        ]
        return out_cols, masked_rows, rel.rls_applied


def _three_and(a, b):
    if a is False or b is False:
        return False
    if a is True and b is True:
        return True
    return None


def _three_or(a, b):
    if a is True or b is True:
        return True
    if a is False and b is False:
        return False
    return None
