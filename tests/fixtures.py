"""测试用合成目录/策略/AST 构造器。

全部数据虚构，与 data/ 下的夹具同构，便于在内存中拼出
左连接空扩展、别名遮蔽、UNION 改名等边界场景。
"""
from __future__ import annotations

import copy


def base_document(principal_unit="u1"):
    return {
        "catalog": [
            {
                "name": "devices",
                "columns": [
                    {"id": 1, "name": "id", "type": "text"},
                    {"id": 2, "name": "unit", "type": "text"},
                    {"id": 3, "name": "owner", "type": "text"},
                    {"id": 4, "name": "secret", "type": "text"},
                    {"id": 5, "name": "kwh", "type": "integer"},
                ],
                "rows": [
                    ["d1", "u1", "person-a", "s1", 10],
                    ["d2", "u2", "person-b", "s2", 20],
                    ["d3", "u1", None, "s3", 30],
                ],
            },
            {
                "name": "inspections",
                "columns": [
                    {"id": 11, "name": "id", "type": "text"},
                    {"id": 12, "name": "device", "type": "text"},
                    {"id": 13, "name": "unit", "type": "text"},
                ],
                "rows": [
                    ["i1", "d1", "u1"],
                    ["i2", "d2", "u2"],
                    ["i3", "d2", "u1"],
                ],
            },
        ],
        "policies": [
            {
                "table": "devices",
                "row": {"op": "eq_attr", "field": 2, "attribute": "unit"},
                "columns": {
                    "1": "visible", "2": "visible", "3": "masked",
                    "4": "forbidden", "5": "visible",
                },
            },
            {
                "table": "inspections",
                "row": {"op": "eq_attr", "field": 13, "attribute": "unit"},
                "columns": {"11": "visible", "12": "visible",
                            "13": "visible"},
            },
        ],
        "principal": {"id": "viewer1", "unit": principal_unit},
        "policy_version": "pv1",
        "schema_version": "sv1",
        "mask": "prefix-sha256",
        "queries": [],
    }


def col(alias, ref):
    return {"col": [alias, ref]}


def lit(value, t="text"):
    return {"literal": {"type": t, "value": value}}


def cmp(op, left, right):
    return {"op": op, "left": left, "right": right}


def agg(func, expr=None, distinct=False):
    node = {"op": "aggregate", "func": func, "distinct": distinct}
    if expr is not None:
        node["expr"] = expr
    return node


def scan(table, alias):
    return {"kind": "scan", "table": table, "alias": alias}


def join(join_type, left, right, on):
    return {"kind": "join", "join_type": join_type,
            "left": left, "right": right, "on": on}


def select(from_rel, project, *, where=None, group_by=None, having=None,
           order_by=None):
    node = {"kind": "select", "from": from_rel, "project": project}
    if where is not None:
        node["where"] = where
    if group_by is not None:
        node["group_by"] = group_by
    if having is not None:
        node["having"] = having
    if order_by is not None:
        node["order_by"] = order_by
    return node


def proj(as_name, expr):
    return {"as": as_name, "expr": expr}


def star(as_name):
    return {"as": as_name, "star": True}


def union_all(*branches):
    return {"kind": "union_all", "inputs": list(branches)}


def with_query(document, query):
    doc = copy.deepcopy(document)
    doc["queries"] = [query]
    return doc
