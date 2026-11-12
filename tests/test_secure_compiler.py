"""受限查询编译的编译期拒绝与来源标签传播测试。"""
import unittest

from secure_query.compiler import compile_from_document, compile_query
from secure_query.context import freeze
from secure_query.errors import CompileError
from tests.fixtures import (
    agg, base_document, col, cmp, join, lit, proj, scan, select, star,
    union_all, with_query,
)


def ctx_of(doc):
    return freeze(doc["catalog"], doc["policies"], doc["principal"],
                  doc["policy_version"], doc["schema_version"], doc["mask"])


class RejectionTests(unittest.TestCase):
    def _assert_reject(self, doc, needle, field=None):
        with self.assertRaises(CompileError) as cm:
            compile_from_document(doc, 0)
        message = str(cm.exception)
        self.assertIn(needle, message, message)
        # 拒绝必须带 AST 位置。
        self.assertTrue(cm.exception.position, message)
        if field is not None:
            self.assertEqual(cm.exception.field, field, message)

    def test_forbidden_in_projection(self):
        q = select(scan("devices", "d"),
                   [proj("s", col("d", 4))])
        self._assert_reject(with_query(base_document(), q),
                            "forbidden", ("devices", 4))

    def test_forbidden_via_star_not_silently_dropped(self):
        # 星号必须完整展开并在禁列上拒绝，而不是悄悄省略改变列序。
        q = select(scan("devices", "d"), [star("all")])
        self._assert_reject(with_query(base_document(), q),
                            "forbidden", ("devices", 4))

    def test_masked_in_where_rejected(self):
        q = select(scan("devices", "d"),
                   [proj("id", col("d", 1))],
                   where=cmp("eq", col("d", 3), lit("person-a")))
        self._assert_reject(with_query(base_document(), q),
                            "masked", ("devices", 3))

    def test_masked_in_order_rejected(self):
        q = select(scan("devices", "d"),
                   [proj("id", col("d", 1))],
                   order_by=[{"expr": col("d", 3), "direction": "asc"}])
        self._assert_reject(with_query(base_document(), q),
                            "masked", ("devices", 3))

    def test_masked_in_group_by_rejected(self):
        q = select(scan("devices", "d"),
                   [proj("owner", col("d", 3))],
                   group_by=[col("d", 3)])
        self._assert_reject(with_query(base_document(), q),
                            "masked", ("devices", 3))

    def test_masked_computation_rejected(self):
        q = select(scan("devices", "d"),
                   [proj("o", cmp("eq", col("d", 3), lit("x")))])
        self._assert_reject(with_query(base_document(), q),
                            "masked", ("devices", 3))

    def test_aggregate_over_masked_rejected(self):
        # 禁止对受限表达式先算后遮：聚合参数引用 masked，在列引用点拒绝。
        q = select(scan("devices", "d"),
                   [proj("n", agg("count", col("d", 3)))])
        self._assert_reject(with_query(base_document(), q),
                            "masked", ("devices", 3))

    def test_aggregate_over_forbidden_rejected(self):
        q = select(scan("devices", "d"),
                   [proj("n", agg("sum", col("d", 4)))])
        self._assert_reject(with_query(base_document(), q),
                            "forbidden", ("devices", 4))

    def test_masked_in_nested_subquery_rejected(self):
        # 独立子查询不在公开子集，AST 阶段即拒绝（union 分支直投另行验证合法）。
        inner = select(scan("devices", "d"),
                       [proj("id", col("d", 1)),
                        proj("owner", col("d", 3))])
        q = select(inner, [proj("id", col("d", 1))])
        self._assert_reject(with_query(base_document(), q), "子查询")

    def test_masked_passthrough_union_branch_allowed_but_masked_at_root(self):
        # union 分支允许 masked 裸列向下传递，但根输出必须脱敏，
        # 且分支内对 masked 做计算仍被拒绝。
        branch_a = select(scan("inspections", "i"),
                          [proj("k", col("i", 11)),
                           proj("v", col("i", 12))])
        branch_b = select(scan("devices", "d"),
                          [proj("k", col("d", 1)),
                           proj("v", col("d", 3))])
        plan = compile_from_document(
            with_query(base_document(), union_all(branch_a, branch_b)), 0)
        self.assertTrue(plan.columns[1].masked)

        bad_branch = select(
            scan("devices", "d"),
            [proj("k", col("d", 1)),
             proj("v", cmp("eq", col("d", 3), lit("x")))],
        )
        self._assert_reject(
            with_query(base_document(), union_all(branch_a, bad_branch)),
            "masked", ("devices", 3),
        )

    def test_duplicate_relation_alias_rejected(self):
        q = select(
            join("inner", scan("devices", "x"), scan("inspections", "x"),
                 cmp("eq", col("x", 1), col("x", 11))),
            [proj("id", col("x", 1))],
        )
        self._assert_reject(with_query(base_document(), q), "别名")

    def test_unknown_column_rejected(self):
        q = select(scan("devices", "d"), [proj("x", col("d", 999))])
        self._assert_reject(with_query(base_document(), q), "未知列引用")

    def test_unknown_table_rejected(self):
        q = select(scan("ghost", "g"), [proj("x", col("g", 1))])
        self._assert_reject(with_query(base_document(), q), "白名单")

    def test_raw_sql_fragment_rejected(self):
        q = {"kind": "select",
             "from": {"kind": "scan", "table": "devices; DROP TABLE x",
                      "alias": "d"},
             "project": [proj("id", col("d", 1))]}
        self._assert_reject(with_query(base_document(), q), "白名单")

    def test_unknown_op_rejected(self):
        q = select(scan("devices", "d"),
                   [proj("x", {"op": "evil_func",
                               "expr": col("d", 1)})])
        self._assert_reject(with_query(base_document(), q), "未知表达式算子")

    def test_extra_key_smuggling_rejected(self):
        node = {"op": "eq", "left": col("d", 1), "right": lit("x"),
                "sql": "1=1"}
        q = select(scan("devices", "d"), [proj("x", node)])
        self._assert_reject(with_query(base_document(), q), "契约外字段")

    def test_subquery_not_supported(self):
        inner = select(scan("devices", "d"), [proj("id", col("d", 1))])
        q = select(inner, [proj("id", col("d", 1))])
        self._assert_reject(with_query(base_document(), q), "子查询")


class LineageTests(unittest.TestCase):
    def test_scan_keeps_field_coordinate_and_level(self):
        q = select(scan("devices", "d"),
                   [proj("id", col("d", 1)), proj("owner", col("d", 3))])
        plan = compile_from_document(with_query(base_document(), q), 0)
        levels = {c.name: c.level for c in plan.columns}
        self.assertEqual(levels, {"id": "visible", "owner": "masked"})
        owner = plan.columns[1]
        self.assertEqual(
            [(s["table"], s["field"]) for s in owner.lineage],
            [("devices", 3)],
        )

    def test_rename_does_not_whiten_masked(self):
        # 重命名投影后再在外层概念上引用：标签仍指原字段且保持 masked。
        q = select(scan("devices", "d"),
                   [proj("renamed_owner", col("d", 3))])
        plan = compile_from_document(with_query(base_document(), q), 0)
        col0 = plan.columns[0]
        self.assertEqual(col0.level, "masked")
        self.assertTrue(col0.masked)
        self.assertEqual(col0.lineage[0]["field"], 3)

    def test_union_inherits_restriction_by_position(self):
        # 分支 A 第二列 visible，分支 B 第二列 masked；按位置对齐后，
        # 即便用全新输出名也必须继承 masked。
        branch_a = select(scan("inspections", "i"),
                          [proj("k", col("i", 11)),
                           proj("v", col("i", 12))])
        branch_b = select(scan("devices", "d"),
                          [proj("k", col("d", 1)),
                           proj("v", col("d", 2))])
        # 先确认全 visible 的对齐可编译。
        plan = compile_from_document(
            with_query(base_document(), union_all(branch_a, branch_b)), 0)
        self.assertEqual([c.level for c in plan.columns],
                         ["visible", "visible"])

        branch_b_masked = select(scan("devices", "d"),
                                 [proj("k", col("d", 1)),
                                  proj("v", col("d", 2))])
        # 把 B 的第二列换成 masked 字段 3（类型同为 text）。
        branch_b_masked["project"][1] = proj("v", col("d", 3))
        plan2 = compile_from_document(
            with_query(base_document(),
                       union_all(branch_a, branch_b_masked)), 0)
        self.assertEqual(plan2.columns[1].level, "masked")
        self.assertTrue(plan2.columns[1].masked)
        # 来源链同时含两个分支的原字段。
        coords = {(s["table"], s["field"]) for s in plan2.columns[1].lineage}
        self.assertEqual(coords, {("inspections", 12), ("devices", 3)})

    def test_union_type_mismatch_rejected(self):
        branch_a = select(scan("devices", "d"),
                          [proj("k", col("d", 1))])       # text
        branch_b = select(scan("devices", "d"),
                          [proj("k", col("d", 5))])       # integer
        with self.assertRaises(CompileError) as cm:
            compile_from_document(
                with_query(base_document(), union_all(branch_a, branch_b)), 0)
        self.assertIn("类型不一致", str(cm.exception))

    def test_union_width_mismatch_rejected(self):
        branch_a = select(scan("devices", "d"),
                          [proj("a", col("d", 1)), proj("b", col("d", 2))])
        branch_b = select(scan("devices", "d"),
                          [proj("a", col("d", 1))])
        with self.assertRaises(CompileError):
            compile_from_document(
                with_query(base_document(), union_all(branch_a, branch_b)), 0)

    def test_default_deny_for_unregistered_column(self):
        doc = base_document()
        # 策略只登记部分列，未登记列必须按 forbidden 处理。
        doc["policies"][0]["columns"] = {"1": "visible", "2": "visible"}
        q = select(scan("devices", "d"), [proj("o", col("d", 3))])
        with self.assertRaises(CompileError) as cm:
            compile_from_document(with_query(doc, q), 0)
        # 未登记列默认拒绝（forbidden），绝不默认放行。
        self.assertIn("forbidden", str(cm.exception))


class SqlSafetyTests(unittest.TestCase):
    def test_identifiers_whitelisted_and_quoted(self):
        q = select(scan("devices", "d"), [proj("id", col("d", 1))])
        plan = compile_from_document(with_query(base_document(), q), 0)
        self.assertNotIn(";", plan.sql)
        # 物理名带双引号，用户别名绝不进入 SQL 文本。
        self.assertIn('"devices"', plan.sql)
        self.assertNotIn("'d'", plan.sql)

    def test_literals_are_parameterized(self):
        q = select(scan("devices", "d"),
                   [proj("id", col("d", 1))],
                   where=cmp("eq", col("d", 1), lit("d1")))
        plan = compile_from_document(with_query(base_document(), q), 0)
        self.assertNotIn("'d1'", plan.sql)
        self.assertIn("?", plan.sql)
        self.assertIn("d1", plan.params)

    def test_placeholder_order_matches_text_order(self):
        # 根层脱敏盐位在 SQL 文本上先于内层行谓词出现，
        # 参数必须按文本顺序绑定，不能按编译顺序。
        q = select(scan("devices", "d"),
                   [proj("id", col("d", 1)),
                    proj("owner", col("d", 3))],
                   where=cmp("eq", col("d", 1), lit("d1")))
        plan = compile_from_document(with_query(base_document(), q), 0)
        first_q = plan.sql.index("?")
        # 盐位（None）是第一个占位符。
        self.assertIsNone(plan.params[0])
        self.assertIn("mask_prefix_sha256", plan.sql[:first_q + 1])
        self.assertEqual(plan.params.count("d1"), 1)
        self.assertEqual(plan.sql.count("?"), len(plan.params))


if __name__ == "__main__":
    unittest.main()
