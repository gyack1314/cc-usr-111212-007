# 查询AST与策略

关系节点scan(table,alias)、join(join_type=inner/left,left,right,on)、union_all(inputs)；select包含from、可选where、group_by、having、order_by及project。表达式col=[可见关系别名,字段ID或输出列名]、literal={type,value}、比较eq/ne/lt/le/gt/ge、and/or/not/is_null、聚合count_star/count/sum/min/max；不支持子查询、窗口、任意函数、相关引用、LIMIT探测或原始SQL。每层别名唯一，未知/歧义引用拒绝。select输出别名唯一，后续节点保留来源权限；union_all各输入列数和类型须同且按位置对齐，以首分支列名输出。

顶层直接列投影可masked，可信脱敏为字符串UTF8 SHA256前12个hex加mask:前缀，null保留null，不声称抗字典攻击。中间masked列只传递原值及标签，不执行可观察运算；最外层遇masked传播列只允许直接投影脱敏。forbidden引用即拒绝，包括星号展开。行策略eq_attr可见性以原行字段与冻结principal属性SQL等值比较，null不相等；策略所需字段可信扫描内部可用，不赋给用户visible权限。

解释器对基表先行过滤再关系运算，不读取编译SQL作为期望答案。编译SQL使用可信目录物理名并安全引号，所有用户常量参数化。执行在另建SQLite只读连接上验证，初始资料读取工具不连接数据库。
