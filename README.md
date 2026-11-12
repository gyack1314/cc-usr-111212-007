# 受限查询中的行权限与掩码列传播

本项目保存湖仓治理的合成资料与原始配置。`lake_data.io`读取JSON清单和资产身份，`lake_data.domain`检查基本字段并给数量概况，`lake_data.cli`输出原资料摘要。字段、数据类型、时间和版本口径见[资料约定](docs/data-contract.md)。数据中的设备、班组、主体和电量均为虚构，不连接电网、生产数仓或人员系统。

Python 3.11及以上，无第三方Python依赖。在项目根目录运行：

```sh
python -m unittest discover -s tests -v
python -m compileall -q lake_data secure_query tests
python -m lake_data.cli inspect data/normal.json
python -m secure_query.cli data/normal.json
```

## 受限查询编译（secure_query）

多个保障单位共用数仓时，仅在最终结果过滤单位列挡不住汇总泄漏：无权设备先参与了计数，隐藏单位列后总数仍含它。`secure_query`实现策略绑定的受限查询编译，把权限下沉到正确的关系层：

- 行过滤在各表**扫描处**生效；left join右表无权行视为不存在（左行空扩展），右侧谓词不上提到WHERE。
- 每列携带`(表,字段ID,权限等级)`来源链，重命名、重复别名、UNION按位置对齐都不能洗白受限列，UNION任一分支受限即继承。
- ON/WHERE/GROUP BY/HAVING/ORDER BY/聚合参数仅visible；masked只允许最外层（含union分支直传）裸列投影并由可信函数脱敏；forbidden引用即拒绝；禁止对受限表达式先算后遮。
- 产出白名单引号、全字面量参数化的只读SQLite SQL及来源/策略说明；编译期拒绝并指到AST位置与原字段。
- 执行入口绑定policy/schema版本、principal摘要与计划摘要，过期计划不能换principal复用；`mode=ro`与`query_only`双保险。
- `interpreter.py`是不读取编译SQL的逐行安全解释器，测试用它与SQLite结果逐行对照，覆盖左连接空扩展、别名遮蔽、受限列经UNION改名、同文不同参数，确认无权基表行从未参与聚合。

设计口径见[查询AST与策略](docs/data-contract.md)。

`inspect`只显示原字段概况，不修改源资料。`invalid-config.json`是基本配置错误，其余JSON为有效清单但可含需要领域操作判断的边界资料。null与缺字段应按各字段约定区分，原文件摘要绑定实际字节。

Dockerfile固定Linux基础镜像。`docker build -t lake-material .`构建，`docker run --rm lake-material`读取正常清单；`docker run --rm lake-material python -m unittest discover -s tests -v`执行已有检查。所有资料本地可读，无需账号和在线来源。
