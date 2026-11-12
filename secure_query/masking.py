"""可信脱敏函数注册表。

脱敏表达式只能来自这里的可信代码：编译期只负责把列包进注册函数，
绝不执行用户提供的函数。每个注册项同时给出：
- sqlite_name: 生成 SQL 中发射的可信函数名（白名单常量）
- python_impl: 逐行参考解释器使用的同源 Python 实现
- output_type: 脱敏后的输出类型（契约规定为 text）

prefix-sha256 口径（docs/data-contract.md）：
UTF8 SHA256 前 12 个 hex，加 ``mask:`` 前缀；null 保留 null。
不声称抗字典攻击。
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Callable


@dataclass(frozen=True)
class MaskFunc:
    mask_id: str
    sqlite_name: str
    output_type: str
    python_impl: Callable[[Any], Any]
    # 保留盐位：当前恒为 None 并以绑定参数传递；将来引入受管盐值时
    # 函数签名与 AST/编译流程都无需改变。
    takes_salt: bool = True


def prefix_sha256(value: Any) -> Any:
    if value is None:
        return None
    if not isinstance(value, str):
        # 该脱敏只登记给 text 列；类型在编译期已对齐，走到这里属内部错误。
        raise ValueError("prefix-sha256 只能作用于 text")
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"mask:{digest}"


def sqlite_prefix_sha256(_salt: Any, value: Any) -> Any:
    # SQLite 侧注册的可信函数；盐位保留，当前恒为 None。
    return prefix_sha256(value)


MASK_FUNCTIONS = {
    "prefix-sha256": MaskFunc(
        mask_id="prefix-sha256",
        sqlite_name="mask_prefix_sha256",
        output_type="text",
        python_impl=prefix_sha256,
    ),
}

# 供 executor 注册到 SQLite 连接：(sqlite函数名, 实现, 参数个数)。
SQLITE_FUNCTIONS = [
    ("mask_prefix_sha256", sqlite_prefix_sha256, 2),
]


def get_mask(mask_id: str) -> MaskFunc:
    try:
        return MASK_FUNCTIONS[mask_id]
    except KeyError:
        raise ValueError(f"未登记的脱敏函数 {mask_id!r}") from None
