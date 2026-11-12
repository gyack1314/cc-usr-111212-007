"""边界语义与来源/策略说明的补充测试。"""
import os
import tempfile
import unittest

from secure_query.compiler import compile_from_document
from secure_query.context import freeze
from secure_query.errors import CompileError
from secure_query.executor import execute_plan, open_readonly
from secure_query.interpreter import interpret
from secure_query.plan import deserialize, serialize
from secure_query.testdb import build_sqlite_db
from tests.fixtures import (
    agg, base_document, col, cmp, join, lit, proj, scan, select, star,
    union_all, with_query,
)


def run_both(doc, query):
    doc = with_query(doc, query)
    plan = compile_from_document(doc, 0)
    plan_dict = deserialize(serialize(plan))
    conn = build_sqlite_db(doc)
    cols, sql_rows = execute_plan(
        conn, plan_dict,
        policy_version=doc["policy_version"],
        schema_version=doc["schema_version"],
        principal=doc["principal"],
        mask_id=doc["mask"],
    )
    ctx = freeze(doc["catalog"], doc["policies"], doc["principal"],
                 doc["policy_version"], doc["schema_version"], doc["mask"])
    table_rows = {t["name"]: t["rows"] for t in doc["catalog"]}
    i_cols, i_rows, _ = interpret(ctx, query, table_rows, ("queries", 0))
    assert cols == [c["name"] for c in i_cols]
    assert sql_rows == i_rows
    return plan, sql_rows


class NullSemanticsTests(unittest.TestCase):
    def test_eq_attr_null_not_equal(self):
        # 造一台 unit 为 null 的设备：null 不满足 eq_attr，必须被过滤。
        doc = base_document()
        doc["catalog"][0]["rows"].append(["d9", None, "x", "s9", 9])
        q = select(scan("devices", "d"), [proj("id", col("d", 1))])
        _, rows = run_both(doc, q)
        self.assertNotIn(["d9"], rows)

    def test_is_null_on_visible_column(self):
        # d3 的 owner 为 null；owner 是 masked，改用对可见列的 is_null：
        # 给 inspections 加一条 device 为 null 的行并过滤。
        doc = base_document()
        doc["catalog"][1]["rows"].append(["i9", None, "u1"])
        q = select(
            scan("inspections", "i"),
            [proj("id", col("i", 11))],
            where={"op": "is_null", "expr": col("i", 12)},
        )
        _, rows = run_both(doc, q)
        self.assertEqual(rows, [["i9"]])

    def test_masked_null_preserved(self):
        # masked 列为 null 时脱敏结果仍为 null，而不是 mask: 字符串。
        q = select(
            scan("devices", "d"),
            [proj("id", col("d", 1)), proj("owner", col("d", 3))],
            where=cmp("eq", col("d", 1), lit("d3")),
        )
        _, rows = run_both(base_document(), q)
        self.assertEqual(rows, [["d3", None]])


class StarTests(unittest.TestCase):
    def test_star_expands_all_visible_in_order(self):
        # 对只有 visible 列的表使用星号：完整展开、列序与 schema 一致。
        q = select(scan("inspections", "i"), [star("all")])
        plan, rows = run_both(base_document(), q)
        self.assertEqual([c.name for c in plan.columns],
                         ["id", "device", "unit"])
        # 数据列顺序也与基表一致。
        self.assertTrue(all(len(r) == 3 for r in rows))

    def test_star_keeps_order_before_rejecting_forbidden(self):
        # devices 含 forbidden 列，星号必须拒绝而非悄悄省略；
        # 拒绝位置指向禁列原字段。
        q = select(scan("devices", "d"), [star("all")])
        with self.assertRaises(CompileError) as cm:
            compile_from_document(with_query(base_document(), q), 0)
        self.assertEqual(cm.exception.field, ("devices", 4))


class HavingGuardTests(unittest.TestCase):
    def test_having_rejects_masked(self):
        q = select(
            scan("devices", "d"),
            [proj("unit", col("d", 2)),
             proj("n", agg("count_star"))],
            group_by=[col("d", 2)],
            having=cmp("gt", col("d", 3), lit("x")),
        )
        with self.assertRaises(CompileError) as cm:
            compile_from_document(with_query(base_document(), q), 0)
        self.assertIn("masked", str(cm.exception))

    def test_having_requires_group_by(self):
        q = select(
            scan("devices", "d"),
            [proj("n", agg("count_star"))],
            having=cmp("gt", agg("count_star"), lit(0, "integer")),
        )
        # HAVING 无 GROUP BY：当前实现要求 GROUP BY，明确拒绝而非猜测。
        with self.assertRaises(CompileError):
            compile_from_document(with_query(base_document(), q), 0)


class SelfJoinTests(unittest.TestCase):
    def test_self_join_two_scans_each_filtered(self):
        # 同表自连接：两次扫描各自套用行谓词，参数键不冲突。
        q = select(
            join("inner",
                 scan("devices", "a"), scan("devices", "b"),
                 cmp("eq", col("a", 1), col("b", 1))),
            [proj("id", col("a", 1))],
        )
        plan, rows = run_both(base_document(), q)
        # u1 可见 d1、d3，自连接等值各匹配自身。
        self.assertEqual(sorted(r[0] for r in rows), ["d1", "d3"])
        # 两个扫描都有行过滤说明，参数索引互不相同且有效。
        indices = [f["bound_param_index"] for f in plan.rls_filters]
        self.assertEqual(len(indices), 2)
        self.assertEqual(len(set(indices)), 2)
        for i in indices:
            self.assertIsNotNone(i)
            self.assertEqual(plan.params[i], "u1")


class PolicyExplanationTests(unittest.TestCase):
    def test_rls_filter_explanation_points_to_field(self):
        q = select(scan("devices", "d"), [proj("id", col("d", 1))])
        plan = compile_from_document(with_query(base_document(), q), 0)
        self.assertEqual(len(plan.rls_filters), 1)
        info = plan.rls_filters[0]
        self.assertEqual(info["table"], "devices")
        self.assertEqual(info["field"], 2)
        self.assertEqual(info["attribute"], "unit")
        self.assertEqual(info["op"], "eq_attr")
        self.assertIsInstance(info["bound_param_index"], int)

    def test_output_lineage_identifies_origin(self):
        q = select(scan("devices", "d"),
                   [proj("kwh", col("d", 5))])
        plan = compile_from_document(with_query(base_document(), q), 0)
        origin = plan.columns[0].lineage[0]
        self.assertEqual((origin["table"], origin["field"]),
                         ("devices", 5))


class PlanRoundTripTests(unittest.TestCase):
    def test_serialize_roundtrip_binding_keys(self):
        q = select(scan("devices", "d"),
                   [proj("id", col("d", 1)),
                    proj("owner", col("d", 3))])
        plan = compile_from_document(with_query(base_document(), q), 0)
        raw = serialize(plan)
        restored = deserialize(raw)
        self.assertEqual(restored["sql"], plan.sql)
        self.assertEqual(restored["params"], plan.params)
        self.assertEqual(restored["plan_digest"], plan.plan_digest)
        # 序列化不含任何数据行，只有结构与绑定。
        self.assertNotIn("person-a", raw)

    def test_file_based_readonly_execution(self):
        doc = with_query(base_document(),
                         select(scan("devices", "d"),
                                [proj("id", col("d", 1))]))
        tmp = tempfile.mkdtemp()
        path = os.path.join(tmp, "warehouse.db")
        build_sqlite_db(doc, path)
        plan_dict = deserialize(serialize(compile_from_document(doc, 0)))
        conn = open_readonly(path)
        cols, rows = execute_plan(
            conn, plan_dict,
            policy_version=doc["policy_version"],
            schema_version=doc["schema_version"],
            principal=doc["principal"],
            mask_id=doc["mask"],
        )
        self.assertEqual(sorted(r[0] for r in rows), ["d1", "d3"])
        conn.close()


class OrderByTests(unittest.TestCase):
    def test_order_by_input_column_emitted_at_root(self):
        # 回归：ORDER BY 引用输入列时必须在根层按输出列名发射，
        # 不能在内层 select 引用外层根别名导致作用域错位。
        q = select(
            scan("devices", "d"),
            [proj("kid", col("d", 1)), proj("power", col("d", 5))],
            order_by=[{"expr": col("d", "power"), "direction": "desc"}],
        )
        plan, rows = run_both(base_document(), q)
        self.assertEqual(rows, [["d3", 30], ["d1", 10]])
        # ORDER BY 出现在最外层，且引用投影输出名。
        order_clause = plan.sql[plan.sql.rindex("ORDER BY"):]
        self.assertIn('"power" DESC', order_clause)
        # 内层派生关系不含 ORDER BY。
        inner = plan.sql[:plan.sql.rindex("ORDER BY")]
        self.assertNotIn("ORDER BY", inner)

    def test_order_by_output_alias(self):
        q = select(
            scan("devices", "d"),
            [proj("kid", col("d", 1))],
            order_by=[{"expr": col("d", "kid"), "direction": "asc"}],
        )
        _, rows = run_both(base_document(), q)
        self.assertEqual(rows, [["d1"], ["d3"]])

    def test_order_by_unprojected_input_column_rejected(self):
        q = select(
            scan("devices", "d"),
            [proj("kid", col("d", 1))],
            order_by=[{"expr": col("d", 5), "direction": "asc"}],
        )
        with self.assertRaises(CompileError) as cm:
            compile_from_document(with_query(base_document(), q), 0)
        self.assertIn("投影输出列", str(cm.exception))

    def test_grouped_order_by_aggregate_output(self):
        q = select(
            scan("devices", "d"),
            [proj("u", col("d", 2)), proj("n", agg("count_star"))],
            group_by=[col("d", 2)],
            order_by=[{"expr": col("d", "n"), "direction": "asc"}],
        )
        _, rows = run_both(base_document(), q)
        self.assertEqual(rows, [["u1", 2]])


class LiteralTypingTests(unittest.TestCase):
    def test_integer_literal_parameterized(self):
        q = select(
            scan("devices", "d"),
            [proj("id", col("d", 1))],
            where=cmp("ge", col("d", 5), lit(20, "integer")),
        )
        plan, rows = run_both(base_document(), q)
        # 仅 d3(kwh=30) 满足；d2 无权不可见。
        self.assertEqual(rows, [["d3"]])
        self.assertIn(20, plan.params)

    def test_comparing_text_to_integer_rejected(self):
        q = select(
            scan("devices", "d"),
            [proj("id", col("d", 1))],
            where=cmp("eq", col("d", 5), lit("x")),
        )
        with self.assertRaises(CompileError):
            compile_from_document(with_query(base_document(), q), 0)


if __name__ == "__main__":
    unittest.main()
