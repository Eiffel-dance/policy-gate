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

## 可复核策略快照

`PolicyGate.to_json()` 把已加载规则导出为规范的严格 JSON 文本，供发布前离线比较；`fingerprint()` 返回同一快照 UTF-8 字节的 SHA-256 小写十六进制摘要（固定 64 字符）。

- 根为数组，规则保持声明顺序；每条规则按固定顺序写出归一化后实际生效的 `id`、`effect`、`priority`、`subject`、`action`、`resource`、`tags`，默认值显式出现，内部 `_index` 不泄露。
- `tags` 及其任意层级嵌套对象的键按 Unicode 码位排序；使用紧凑分隔符（无空白），非 ASCII 字符原样保留（不转义）。空规则导出 `[]`；规则不变时重复调用得到逐字节相同的文本。
- 导出文本可由 `from_json` 无损重新加载，重载后的 `decide`、`explain`、`decide_many`、`audit` 与原实例完全一致；导出不修改规则或调用方提供的映射。
- 直接构造的规则若含不能无损表示为严格 JSON 的值（元组、集合、非有限数字、含非字符串键的嵌套映射，或无法 UTF-8 编码的孤立代理项），`to_json` 与 `fingerprint` 均抛出消息含固定标识 `non_json_value` 的 `ValueError`，且不返回任何部分文本。
- 快照功能纯离线：无文件、网络或其他外部 I/O。

## 请求覆盖报告

`PolicyGate.coverage(requests)` 让调用方用一批请求检查每条规则是否参与判定、最终赢了多少次，不改任何判定结果。

- `requests` 沿用 `decide_many` 的 list/tuple 与请求映射；`subject`、`action`、`resource` 为必填字符串，`tags` 可省略、为 `None` 或 mapping。整批先完整校验容器、元素、未知键、缺失键和类型，沿用 `PolicyBatchError` 的 `code`、`index`、`field`；第一处错误立即终止，不返回部分报告。
- 返回 `{"rules": [...], "summary": {"total", "allow", "explicit_deny", "default_deny", "matched_request"}}`。`rules` 按声明顺序为每条规则给出 `id`、`effect`、`matched`、`winner`：`matched` 是选择器与该请求匹配的次数，`winner` 是经显式拒绝、priority 和声明顺序决胜后最终由该规则赢得的次数。
- 同一请求命中多条规则时，所有命中规则的 `matched` 各加一，只有最终规则的 `winner` 加一；默认拒绝不给任何规则增加 `winner`。
- `summary` 中 `total` 为请求数，`allow` 为最终效果 allow 的请求数，`explicit_deny` 为 deny 规则赢得的请求数，`default_deny` 为未命中任何规则而落入默认拒绝的请求数，`matched_request` 为至少命中一条规则的请求数。空批次全部计数为零（仍列出全部规则）；空规则集按请求数统计 `default_deny`。
- 匹配口径与 `decide` 完全一致（`fnmatch.fnmatchcase` 与标签精确约束、显式 deny 优先、同效果按 priority 再按声明顺序决胜、默认 deny）。报告只读且纯离线：不修改规则或调用方映射，无 I/O，重复调用结果相同。

## 策略版本回归比较

`PolicyGate.compare(candidate, requests)` 把调用对象作为基线、`candidate`（必须为 `PolicyGate`，否则抛 `TypeError`）作为候选，对同一批请求分别按各自既有的通配、显式 deny、priority、声明顺序和默认 deny 规则判定，定位候选改动。

- `requests` 沿用 `decide_many` 的 list/tuple 与请求映射；`subject`、`action`、`resource` 为必填字符串，`tags` 可省略、为 `None` 或 mapping。比较前完整校验容器、元素、未知键、缺失键和类型，沿用 `PolicyBatchError` 的 `code`、`index`、`field`；第一处错误立即终止，不返回部分结果。空批次返回全零汇总。
- 返回 `{"changes": [...], "summary": {"total", "unchanged", "changed", "allow_to_deny", "deny_to_allow", "winner_changed"}}`；`total` 为请求数，`changed` 等于三类变化计数之和。
- `changes` 按输入顺序列出完整 `decide` 结果不同的请求，每项含 `index`、`before`、`after`、`kind`：effect 从 allow 变 deny / deny 变 allow 时 `kind` 分别为 `allow_to_deny` / `deny_to_allow`；effect 相同但 `rule` 或 `reason` 改变时为 `winner_changed`；完全相同只计入 `unchanged`。
- 比较只读且纯离线：不修改任一 gate、请求或标签映射，无 I/O，重复调用结果相同；不改变 `decide`、`decide_many`、`explain`、`audit`、`from_json`、`to_json`、`fingerprint` 的既有行为。

