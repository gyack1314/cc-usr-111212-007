# 查询AST与策略

关系节点scan(table,alias)、join(join_type=inner/left,left,right,on)、union_all(inputs)；select包含from、可选where、group_by、having、order_by及project。表达式col=[可见关系别名,字段ID或输出列名]、literal={type,value}、比较eq/ne/lt/le/gt/ge、and/or/not/is_null、聚合count_star/count/sum/min/max；不支持子查询、窗口、任意函数、相关引用、LIMIT探测或原始SQL。每层别名唯一，未知/歧义引用拒绝。select输出别名唯一，后续节点保留来源权限；union_all各输入列数和类型须同且按位置对齐，以首分支列名输出。

顶层直接列投影可masked，可信脱敏为字符串UTF8 SHA256前12个hex加mask:前缀，null保留null，不声称抗字典攻击。中间masked列只传递原值及标签，不执行可观察运算；最外层遇masked传播列只允许直接投影脱敏。forbidden引用即拒绝，包括星号展开。行策略eq_attr可见性以原行字段与冻结principal属性SQL等值比较，null不相等；策略所需字段可信扫描内部可用，不赋给用户visible权限。

解释器对基表先行过滤再关系运算，不读取编译SQL作为期望答案。编译SQL使用可信目录物理名并安全引号，所有用户常量参数化。执行在另建SQLite只读连接上验证，初始资料读取工具不连接数据库。

## secure_query 受限查询编译包

策略绑定的受限查询编译，权限在关系层生效，不靠查询结束后删列。

- `ast_nodes.py`：公开AST子集严格形状校验，拒绝契约外字段与原始SQL片段；`select`只能作语句根或`union_all`分支。
- `context.py`：一次编译冻结catalog/policy/principal；物理名过白名单标识符正则并双引号转义；列未登记默认forbidden；无策略表默认全拒。
- `relations.py`：scan/join/union编译与来源标签传播。行谓词在各表扫描子查询内生效，物理表别名（`b_`）与派生子查询别名（`s_`）分离，避免谓词被绑定到同名全量派生表。left join右表无权行不参与ON匹配，左行只做空扩展，右侧谓词绝不上提到WHERE。
- `expr_compiler.py`：ON/WHERE/GROUP BY/HAVING/ORDER BY/聚合参数仅visible；masked只允许根投影或union分支裸列直传（根层统一脱敏）；forbidden任何引用即拒绝；聚合输入非visible直接拒绝，禁止先算后遮。
- `masking.py`：可信脱敏注册表，SQL发射与Python参考实现同源；不执行用户函数。
- `compiler.py`：每列保留`(表,字段ID,等级)`来源链，重命名/重复别名/UNION按位置对齐均不能洗白，UNION任一分支受限即继承最严格等级。命名占位符在最终SQL上按出现顺序重写为`?`并排参（根层盐位先于内层行谓词出现）。星号先按schema完整展开再走统一规则检查，forbidden在展开项上拒绝而非省略。
- `interpreter.py`：独立逐行参考解释器，不读取编译SQL；基表先行过滤再关系运算，left join空扩展、三值逻辑、分组/HAVING/排序独立实现。
- `plan.py`/`executor.py`：计划序列化与绑定（policy/schema版本、principal摘要、plan摘要）；执行前逐项复核，过期计划不能换principal复用，篡改SQL/参数即摘要不符；`mode=ro`加`PRAGMA query_only=ON`双保险。

拒绝一律在编译期抛出并带AST位置与原字段坐标`(表,字段ID)`，不依赖执行期报错。侧信道（报错文本差异、时序）不在消除目标内。

### 运行

```sh
python -m unittest discover -s tests -v
python -m compileall -q lake_data secure_query tests
python -m secure_query.cli data/normal.json          # 只编译不执行，打印SQL与策略说明
python -m secure_query.cli data/masked-filter-reject.json   # 编译期拒绝，退出码2
```

