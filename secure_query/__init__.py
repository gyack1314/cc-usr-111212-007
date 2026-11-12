"""策略绑定的受限查询编译、逐行解释与只读执行。

模块划分：
- errors:     带 AST 位置与原字段的编译拒绝
- ast_nodes:  公开 AST 子集的严格形状校验，不接受原始 SQL 片段
- context:    目录、策略、principal 属性的一次冻结
- masking:    可信脱敏函数注册表（SQL 发射与 Python 参考实现同源）
- compiler:   关系层权限编译与标签传播，产出 CompiledQuery
- interpreter:逐行安全参考解释器，不读取编译 SQL
- executor:   绑定校验后的 SQLite 只读执行
- plan:       编译计划的序列化与绑定摘要
"""
