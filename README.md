# Policy Gate

A dependency-free Python reference implementation for security, policy-as-code, rbac.

Run with: python3 demo.py
Tests: python3 -m unittest discover -s tests -v

## Scope

实现一个无网络的策略判定器，按主体、动作、资源和标签匹配规则并返回可解释的 allow 或 deny 决策。规则优先级、显式拒绝、默认拒绝、通配匹配和冲突处理必须有稳定定义；判定结果要包含命中的规则和原因，配置错误在加载阶段失败，便于在发布前做离线安全检查。

## 发布前审计

`PolicyGate.audit()` 对已加载的规则做纯离线静态检查（不接收请求、无 I/O、不修改规则或后续判定），返回 `{"findings": [...], "summary": {"total", "error", "warning"}}`：

- 按声明顺序检查每对规则；主体/动作/资源模式按 `fnmatch.fnmatchcase` 真实语义判断是否存在共同匹配字符串，标签约束仅在同键不同值时冲突。
- 非等价选择器且 effect 不同的重叠产生一条 `effect_overlap`（error），`winner` 为重叠范围内获胜的 deny 规则（显式拒绝覆盖 allow，priority 不改变结果）。
- 三个模式文本和标签完全相同的选择器产生一条 `shadowed_rule`：allow 被 deny 遮蔽为 error，相同 effect 为 warning（按优先级再按声明顺序确定被遮蔽方）。
- 相同 effect 的部分重叠不算冲突。每条 finding 固定含 `code`、`severity`、`rule`、`other_rule`、`winner`、`shadowed`、`reason`；无法完全遮蔽时 `shadowed` 为 `None`。无重叠选择器时返回空报告。
