"""受限查询编译检查入口（只读）。

打印编译产出的参数化 SQL、绑定参数、来源/权限列说明与行过滤说明，
不连接数据库、不执行查询。用于在部署前人工复核策略是否在正确关系层生效。
"""
from __future__ import annotations

import argparse
import json

from .compiler import compile_from_document
from .errors import CompileError
from .plan import serialize
from lake_data.io import load


def main() -> int:
    parser = argparse.ArgumentParser(
        description="编译受限查询并打印 SQL 与策略说明（不执行）",
    )
    parser.add_argument("file", help="含 catalog/policies/principal/queries 的 JSON")
    parser.add_argument("--index", type=int, default=0, help="查询索引")
    parser.add_argument("--json", action="store_true", help="输出完整计划 JSON")
    args = parser.parse_args()

    document, source_digest = load(args.file)
    try:
        plan = compile_from_document(document, args.index)
    except CompileError as exc:
        print(json.dumps(
            {"rejected": True, "error": exc.message,
             "position": list(exc.position), "field": exc.field},
            ensure_ascii=False, indent=2,
        ))
        return 2

    if args.json:
        print(serialize(plan))
        return 0

    lines = [
        f"source_sha256: {source_digest}",
        f"policy_version: {plan.policy_version} schema_version: {plan.schema_version}",
        f"principal: {plan.principal_id} principal_digest: {plan.principal_digest[:16]}…",
        f"plan_digest: {plan.plan_digest[:16]}…",
        "SQL:",
        "  " + plan.sql,
        f"params ({len(plan.params)}): {plan.params!r}",
        "outputs:",
    ]
    for col in plan.columns:
        origin = ",".join(
            f"{s.get('table')}.{s.get('field')}" for s in col.lineage
            if "table" in s
        )
        lines.append(
            f"  - {col.name}: type={col.type} level={col.level} "
            f"masked={col.masked} origin=[{origin}]"
        )
    lines.append("row_filters:")
    for f in plan.rls_filters:
        lines.append(
            f"  - {f['table']}.{f['field_name']} {f['op']} "
            f"principal.{f['attribute']} -> param[{f['bound_param_index']}]"
        )
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
