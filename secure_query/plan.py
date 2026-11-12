"""编译计划的序列化与绑定摘要。

执行入口只信任携带绑定的计划：policy_version / schema_version /
principal 摘要 / 计划摘要全部在编译时冻结，执行时逐项复核，
过期计划不能换个 principal 继续跑。
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from .compiler import CompiledQuery


def serialize(plan: CompiledQuery) -> str:
    return json.dumps(asdict(plan), ensure_ascii=False, indent=2,
                      allow_nan=False, default=_default)


def deserialize(raw: str) -> dict:
    # parse_constant 拒绝 NaN/Infinity，与资料读取口径一致。
    return json.loads(
        raw,
        parse_constant=lambda x: (_ for _ in ()).throw(
            ValueError("不接受非有限常量")),
    )


def binding_keys(plan: CompiledQuery) -> dict:
    return {
        "policy_version": plan.policy_version,
        "schema_version": plan.schema_version,
        "principal_id": plan.principal_id,
        "principal_digest": plan.principal_digest,
        "plan_digest": plan.plan_digest,
        "mask_id": plan.mask_id,
    }


def recompute_plan_digest(plan_dict: dict) -> str:
    body = {
        "sql": plan_dict["sql"],
        "params": plan_dict["params"],
        "policy_version": plan_dict["policy_version"],
        "schema_version": plan_dict["schema_version"],
        "mask": plan_dict["mask_id"],
        "principal": plan_dict["policy_snapshot"]["principal"],
    }
    raw = json.dumps(body, ensure_ascii=False, sort_keys=True,
                     allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _default(o):
    if isinstance(o, tuple):
        return list(o)
    if isinstance(o, frozenset):
        return sorted(o)
    raise TypeError(f"不可序列化对象 {type(o)!r}")
