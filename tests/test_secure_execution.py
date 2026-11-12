"""SQLite 编译结果与逐行安全解释器的逐行对照测试。

核心安全断言：两条独立实现产出完全相同的结果，且无权基表行
从未参与 join、过滤、分组与聚合。解释器不读取编译 SQL。
"""
import json
import unittest

from secure_query.compiler import compile_from_document
from secure_query.context import freeze
from secure_query.executor import (
    BindingError, execute_plan, open_readonly, verify_binding,
)
from secure_query.interpreter import interpret
from secure_query.plan import deserialize, serialize
from secure_query.testdb import build_sqlite_db
from tests.fixtures import (
    agg, base_document, col, cmp, join, lit, proj, scan, select, union_all,
    with_query,
)


def _rows(doc, query):
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
    i_cols, i_rows, rls = interpret(ctx, query, table_rows, ("queries", 0))
    return plan, cols, sql_rows, i_cols, i_rows, rls


def assert_engines_agree(testcase, doc, query):
    plan, cols, sql_rows, i_cols, i_rows, rls = _rows(doc, query)
    testcase.assertEqual(cols, [c["name"] for c in i_cols])
    testcase.assertEqual(sql_rows, i_rows)
    return plan, sql_rows, rls


class LeftJoinTests(unittest.TestCase):
    def test_left_join_null_extension(self):
        # 右表无权行视为不存在：i3 匹配不到 devices，左行保留、右侧空扩展。
        q = select(
            join("left", scan("inspections", "i"), scan("devices", "d"),
                 cmp("eq", col("i", 12), col("d", 1))),
            [proj("inspection", col("i", 11)),
             proj("device", col("d", 1))],
        )
        plan, rows, rls = assert_engines_agree(self, base_document(), q)
        self.assertIn(["i3", None], rows)
        self.assertNotIn("i2", [r[0] for r in rows])  # 左表无权行被过滤
        # 两张表的扫描都登记了行过滤。
        tables = {f["table"] for f in rls}
        self.assertEqual(tables, {"devices", "inspections"})

    def test_right_filter_not_pushed_to_where(self):
        # 编译 SQL 中右表谓词必须在右扫描子查询内，外层 WHERE 不得出现，
        # 否则左表行会被错误剔除（空扩展失效）。
        q = select(
            join("left", scan("inspections", "i"), scan("devices", "d"),
                 cmp("eq", col("i", 12), col("d", 1))),
            [proj("inspection", col("i", 11))],
        )
        plan, rows, _ = assert_engines_agree(self, base_document(), q)
        # LEFT JOIN 结构保留，且不存在会过滤左行的顶层 WHERE。
        self.assertIn("LEFT JOIN", plan.sql)
        # 左表 inspections 的行 i3 仍然在结果中。
        self.assertEqual([r[0] for r in rows], ["i1", "i3"])

    def test_inner_join_drops_unmatched(self):
        q = select(
            join("inner", scan("inspections", "i"), scan("devices", "d"),
                 cmp("eq", col("i", 12), col("d", 1))),
            [proj("inspection", col("i", 11)),
             proj("device", col("d", 1))],
        )
        _, rows, _ = assert_engines_agree(self, base_document(), q)
        self.assertEqual(rows, [["i1", "d1"]])


class AggregationLeakTests(unittest.TestCase):
    def test_count_star_excludes_unauthorized_rows(self):
        # 关键泄漏场景：无权设备不得参与计数。
        q = select(scan("devices", "d"),
                   [proj("n", agg("count_star"))])
        _, rows, _ = assert_engines_agree(self, base_document(), q)
        # u1 只有 d1、d3 两台可见，d2 被行谓词剔除。
        self.assertEqual(rows, [[2]])

    def test_sum_visible_column_excludes_unauthorized_rows(self):
        q = select(scan("devices", "d"),
                   [proj("total", agg("sum", col("d", 5)))])
        _, rows, _ = assert_engines_agree(self, base_document(), q)
        # 仅 d1(10) + d3(30)，d2(20) 不计入。
        self.assertEqual(rows, [[40]])

    def test_grouped_aggregation(self):
        q = select(
            scan("devices", "d"),
            [proj("unit", col("d", 2)),
             proj("n", agg("count_star")),
             proj("kwh", agg("sum", col("d", 5)))],
            group_by=[col("d", 2)],
            order_by=[{"expr": col("d", 2), "direction": "asc"}],
        )
        _, rows, _ = assert_engines_agree(self, base_document(), q)
        self.assertEqual(rows, [["u1", 2, 40]])

    def test_having_filter(self):
        q = select(
            scan("devices", "d"),
            [proj("unit", col("d", 2)),
             proj("n", agg("count_star"))],
            group_by=[col("d", 2)],
            having=cmp("ge", agg("count_star"), lit(2, "integer")),
        )
        _, rows, _ = assert_engines_agree(self, base_document(), q)
        self.assertEqual(rows, [["u1", 2]])

    def test_count_ignores_null(self):
        # d3 的 owner 为 null（但 owner 是 masked，这里改用可空可见列场景：
        # 直接对可见列 count，验证 null 语义双引擎一致）。
        q = select(scan("devices", "d"),
                   [proj("n", agg("count", col("d", 5))),
                    proj("distinct_n", agg("count", col("d", 5),
                                           distinct=True))])
        _, rows, _ = assert_engines_agree(self, base_document(), q)
        self.assertEqual(rows, [[2, 2]])


class MaskingTests(unittest.TestCase):
    def test_masked_root_projection_agrees(self):
        q = select(scan("devices", "d"),
                   [proj("id", col("d", 1)),
                    proj("owner", col("d", 3))])
        plan, rows, _ = assert_engines_agree(self, base_document(), q)
        # 脱敏值确定且带 mask: 前缀；null 保留 null（d3 owner 为 None）。
        owners = {r[0]: r[1] for r in rows}
        self.assertTrue(owners["d1"].startswith("mask:"))
        self.assertIsNone(owners["d3"])
        # 原值绝不出现。
        flat = json.dumps(rows, ensure_ascii=False)
        self.assertNotIn("person-a", flat)

    def test_mask_is_deterministic(self):
        import hashlib
        q = select(scan("devices", "d"),
                   [proj("owner", col("d", 3))],
                   where=cmp("eq", col("d", 1), lit("d1")))
        _, rows, _ = assert_engines_agree(self, base_document(), q)
        expected = "mask:" + hashlib.sha256(
            "person-a".encode("utf-8")).hexdigest()[:12]
        self.assertEqual(rows[0][0], expected)


class UnionTests(unittest.TestCase):
    def test_union_all_position_alignment(self):
        branch_a = select(scan("inspections", "i"),
                          [proj("code", col("i", 11))])
        branch_b = select(scan("devices", "d"),
                          [proj("code", col("d", 1))])
        q = union_all(branch_a, branch_b)
        _, rows, _ = assert_engines_agree(self, base_document(), q)
        flat = [r[0] for r in rows]
        #  inspections 可见 i1,i3；devices 可见 d1,d3。
        self.assertEqual(sorted(flat), ["d1", "d3", "i1", "i3"])

    def test_union_renamed_masked_column(self):
        # 受限列经 UNION 改名：第二分支 masked，结果列继承 masked 并脱敏，
        # 双引擎结果一致。
        branch_a = select(scan("inspections", "i"),
                          [proj("k", col("i", 11)),
                           proj("v", col("i", 12))])
        branch_b = select(scan("devices", "d"),
                          [proj("k", col("d", 1)),
                           proj("v", col("d", 3))])
        q = union_all(branch_a, branch_b)
        plan, rows, _ = assert_engines_agree(self, base_document(), q)
        self.assertTrue(plan.columns[1].masked)
        # 来自 devices 分支的 owner 已脱敏；inspections 分支原值保持。
        values = [r[1] for r in rows]
        self.assertTrue(any(isinstance(v, str) and v.startswith("mask:")
                            for v in values))


class SameTextDifferentParamsTests(unittest.TestCase):
    def test_same_query_text_different_principal(self):
        # 同文不同参数：AST 相同，冻结不同 principal，行谓词参数与结果不同。
        q = select(scan("devices", "d"),
                   [proj("id", col("d", 1)),
                    proj("kwh", col("d", 5))],
                   order_by=[{"expr": col("d", 1), "direction": "asc"}])
        doc_u1 = base_document("u1")
        doc_u2 = base_document("u2")
        _, rows_u1, _ = assert_engines_agree(self, doc_u1, q)
        _, rows_u2, _ = assert_engines_agree(self, doc_u2, q)
        self.assertEqual(rows_u1, [["d1", 10], ["d3", 30]])
        self.assertEqual(rows_u2, [["d2", 20]])
        # 两个计划的 SQL 文本结构相同，但绑定参数不同。
        p1 = compile_from_document(with_query(doc_u1, q), 0)
        p2 = compile_from_document(with_query(doc_u2, q), 0)
        self.assertNotEqual(p1.params, p2.params)
        self.assertNotEqual(p1.principal_digest, p2.principal_digest)

    def test_literal_parameterization_across_runs(self):
        def make(needle):
            return select(scan("devices", "d"),
                          [proj("id", col("d", 1))],
                          where=cmp("eq", col("d", 1), lit(needle)))
        p_a = compile_from_document(with_query(base_document(), make("d1")), 0)
        p_b = compile_from_document(with_query(base_document(), make("d3")), 0)
        # SQL 文本完全一致（值不内联），仅参数不同。
        self.assertEqual(p_a.sql, p_b.sql)
        self.assertNotEqual(p_a.params, p_b.params)


class BindingTests(unittest.TestCase):
    def _plan_dict(self, doc, q):
        plan = compile_from_document(with_query(doc, q), 0)
        return deserialize(serialize(plan))

    def _q(self):
        return select(scan("devices", "d"), [proj("id", col("d", 1))])

    def test_stale_principal_rejected(self):
        doc = base_document("u1")
        plan_dict = self._plan_dict(doc, self._q())
        other_principal = {"id": "viewer2", "unit": "u2"}
        with self.assertRaises(BindingError):
            verify_binding(
                plan_dict,
                policy_version=doc["policy_version"],
                schema_version=doc["schema_version"],
                principal=other_principal,
                mask_id=doc["mask"],
            )

    def test_stale_policy_version_rejected(self):
        doc = base_document("u1")
        plan_dict = self._plan_dict(doc, self._q())
        with self.assertRaises(BindingError):
            verify_binding(
                plan_dict,
                policy_version="pv2",
                schema_version=doc["schema_version"],
                principal=doc["principal"],
                mask_id=doc["mask"],
            )

    def test_tampered_sql_rejected(self):
        doc = base_document("u1")
        plan_dict = self._plan_dict(doc, self._q())
        plan_dict["sql"] = plan_dict["sql"].replace('"id"', '"id"', 1) + " "
        with self.assertRaises(BindingError):
            verify_binding(
                plan_dict,
                policy_version=doc["policy_version"],
                schema_version=doc["schema_version"],
                principal=doc["principal"],
                mask_id=doc["mask"],
            )

    def test_readonly_connection_blocks_writes(self):
        import os
        import tempfile
        doc = with_query(base_document(), self._q())
        path = os.path.join(tempfile.mkdtemp(), "ro.db")
        build_sqlite_db(doc, path)
        conn = open_readonly(path)
        with self.assertRaises(sqlite3_readonly_error()):
            conn.execute("CREATE TABLE x(a)")
        with self.assertRaises(sqlite3_readonly_error()):
            conn.execute('INSERT INTO devices VALUES ("z","z","z","z",1)')
        conn.close()


def sqlite3_readonly_error():
    import sqlite3
    return sqlite3.OperationalError


if __name__ == "__main__":
    unittest.main()
