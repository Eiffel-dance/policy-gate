# Policy Gate

A dependency-free Python reference implementation for security, policy-as-code, rbac.

Run with: python3 demo.py
Tests: python3 -m unittest discover -s tests -v

## Scope

实现一个无网络的策略判定器，按主体、动作、资源和标签匹配规则并返回可解释的 allow 或 deny 决策。规则优先级、显式拒绝、默认拒绝、通配匹配和冲突处理必须有稳定定义；判定结果要包含命中的规则和原因，配置错误在加载阶段失败，便于在发布前做离线安全检查。

## 发布前审计

`PolicyGate.audit()` 对已加载的规则做纯离线静态检查（不接收请求、无 I/O、不修改规则或后续判定），返回 `{"findings": [...], "summary": {"total", "error", "warning"}}`：

- 先按声明顺序对每条规则单独做可达性检查：某维度的正向模式无任何可匹配字符串、声明的 `subject_exclude`/`action_exclude`/`resource_exclude` 排除了正向模式的全部匹配值，或某个 `tag_patterns` 模式无可匹配字符串时，该规则不可达，产生一条 `unsatisfiable_rule`（error）。精确 `tags`、`tag_presence` 与 `tag_exclude_patterns` 单独不会导致不可达（仅被排除约束的键可以缺席）。每条不可达规则只报告一次，`reason` 指出首个失败字段（按 `subject`、`action`、`resource`、`tag_patterns` 键名的 Unicode 码点顺序，即 action、resource、subject、tag_patterns）并区分“无正向匹配值”与“全部匹配值被排除”；`rule` 为该规则 id，`other_rule`、`winner`、`shadowed`、`witness` 均为 `None`。单规则 finding 按声明顺序排在所有成对 finding 之前，并计入 `summary` 的 `total`/`error`/`warning`；没有不可达规则时报告与既有成对审计完全一致。
- 按声明顺序检查每对规则；主体/动作/资源模式按 `fnmatch.fnmatchcase` 真实语义判断是否存在共同匹配字符串，标签约束仅在同键不同值时冲突。
- 非等价选择器且 effect 不同的重叠产生一条 `effect_overlap`（error），`winner` 为重叠范围内获胜的 deny 规则（显式拒绝覆盖 allow，priority 不改变结果）。
- 三个模式文本和标签完全相同的选择器产生一条 `shadowed_rule`：allow 被 deny 遮蔽为 error，相同 effect 为 warning（按优先级再按声明顺序确定被遮蔽方）。
- 相同 effect 的部分重叠不算冲突。每条 finding 固定含 `code`、`severity`、`rule`、`other_rule`、`winner`、`shadowed`、`reason`、`witness`；无法完全遮蔽时 `shadowed` 为 `None`。无重叠选择器时返回空报告。
- `witness` 是一个确实能触发该 finding 的最小见证请求，固定含 `subject`、`action`、`resource`、`tags` 四个键：把它交回 `decide`/`explain` 必然同时命中该对规则（`effect_overlap` 下 deny 必然最终生效）。三个字符串字段各自独立地取所有同时匹配两条规则 `fnmatch.fnmatchcase` 模式的字符串中最短者，长度相同取 Unicode 码点字典序最小者，允许空字符串；`tags` 只合并两条规则的标签约束（共享键值在产生 finding 时必相同，互不冲突的键全部保留，键按 Unicode 码点顺序输出，不凭空添加标签）。直接构造与 `from_json` 得到的相同规则生成完全相同的 witness，重复调用返回相等结果，修改返回的报告不影响后续调用。

## 可复核策略快照

`PolicyGate.to_json()` 把已加载规则导出为规范的严格 JSON 文本，供发布前离线比较；`fingerprint()` 返回同一快照 UTF-8 字节的 SHA-256 小写十六进制摘要（固定 64 字符）。

- 根为数组，规则保持声明顺序；每条规则按固定顺序写出归一化后实际生效的 `id`、`effect`、`priority`、`subject`、`action`、`resource`、`tags`，默认值显式出现，内部 `_index` 不泄露。
- `tags` 及其任意层级嵌套对象的键按 Unicode 码位排序；使用紧凑分隔符（无空白），非 ASCII 字符原样保留（不转义）。空规则导出 `[]`；规则不变时重复调用得到逐字节相同的文本。
- 导出文本可由 `from_json` 无损重新加载，重载后的 `decide`、`explain`、`decide_many`、`audit` 与原实例完全一致；导出不修改规则或调用方提供的映射。
- 直接构造的规则若含不能无损表示为严格 JSON 的值（元组、集合、非有限数字、含非字符串键的嵌套映射，或无法 UTF-8 编码的孤立代理项），`to_json` 与 `fingerprint` 均抛出消息含固定标识 `non_json_value` 的 `ValueError`，且不返回任何部分文本。
- 快照功能纯离线：无文件、网络或其他外部 I/O。

## 版本化策略文档

`PolicyGate.from_json` 除旧根数组外，同时接受版本化根对象，让发布前加载时确认文档格式与策略身份。根对象只允许 `version`、`rules`、`fingerprint` 三个键：`version` 必填且必须为整数 `1`；`rules` 必填且必须为规则数组（规则字段校验与旧数组完全一致）；`fingerprint` 可省略，提供时必须是 64 位小写十六进制 SHA-256，且等于 `rules` 规范快照的指纹（即 `fingerprint()` 的返回值）。

- 根值既非数组也非对象时报 `root_not_array_or_object`；对象封装错误按固定优先级报告首个问题：未知键 `unknown_document_field`、缺失 version `missing_version`、version 类型错误 `invalid_version`、版本不支持 `unsupported_version`、缺失 rules `missing_rules`、rules 类型错误 `rules_not_array`、摘要格式错误 `invalid_fingerprint`、摘要不匹配 `fingerprint_mismatch`。以上均在加载阶段抛出带 `code` 的 `PolicyConfigError`；重复键、非法 JSON、元素非对象和规则字段语义错误沿用既有校验（后两者分别为 `duplicate_key`/`invalid_json`/`rule_not_object` 与 plain `ValueError`）。
- 版本化加载成功后 `document_version` 为 `1`；旧数组加载和直接构造的 gate `document_version` 为 `None`。
- 版本化 gate 的 `to_json()` 按 `version`、`rules`、`fingerprint` 固定顺序输出规范对象：`rules` 是与旧格式逐字节相同的规范规则数组，`fingerprint` 为规则快照摘要，输入提供的摘要因此被原样保留；省略摘要加载时输出自动补全的计算值。旧数组与直接构造仍输出既有的规范数组。
- `fingerprint()` 始终对规范规则数组（不含封装）取 SHA-256，三种来源的等价规则得到相同指纹；`from_json(to_json())` 往返后 `decide`、`explain`、`trace`、`diagnose`、`audit`、`coverage`、`compare`、`verify` 等所有结果逐值相同，版本化导出逐字节稳定。
- 加载与导出保持离线、只读：不修改调用方映射，无文件、网络或其他外部 I/O；空规则、显式拒绝、优先级、通配和默认拒绝语义不变。

## 策略版本回归比较

`PolicyGate.compare(candidate, requests)` 把调用对象作为基线、`candidate`（必须为 `PolicyGate`，否则抛 `TypeError`）作为候选，对同一批请求分别按各自既有的通配、显式 deny、priority、声明顺序和默认 deny 规则判定，定位候选改动。

- `requests` 沿用 `decide_many` 的 list/tuple 与请求映射；`subject`、`action`、`resource` 为必填字符串，`tags` 可省略、为 `None` 或 mapping。比较前完整校验容器、元素、未知键、缺失键和类型，沿用 `PolicyBatchError` 的 `code`、`index`、`field`；第一处错误立即终止，不返回部分结果。空批次返回全零汇总。
- 返回 `{"changes": [...], "summary": {"total", "unchanged", "changed", "allow_to_deny", "deny_to_allow", "winner_changed"}}`；`total` 为请求数，`changed` 等于三类变化计数之和。
- `changes` 按输入顺序列出完整 `decide` 结果不同的请求，每项含 `index`、`before`、`after`、`kind`：effect 从 allow 变 deny / deny 变 allow 时 `kind` 分别为 `allow_to_deny` / `deny_to_allow`；effect 相同但 `rule` 或 `reason` 改变时为 `winner_changed`；完全相同只计入 `unchanged`。
- 比较只读且纯离线：不修改任一 gate、请求或标签映射，无 I/O，重复调用结果相同；不改变 `decide`、`decide_many`、`explain`、`audit`、`from_json`、`to_json`、`fingerprint` 的既有行为。

## 规则变更报告

`PolicyGate.rule_change_report(candidate)` 在发布审查时按规则 `id` 对齐两份**已校验**配置：调用对象为基线，`candidate`（必须为 `PolicyGate`，否则抛 `TypeError`，不产生部分报告）为候选。接口纯离线、只读：不修改任一 gate 或输入对象、无 I/O，重复调用返回相等结果，修改返回报告不影响后续调用；不改变 `decide`、`explain`、`audit`、`compare`、`to_json`、`fingerprint` 的既有结果。

- 返回固定结构 `{"added": [...], "removed": [...], "changed": [...], "unchanged": [...], "summary": {...}}`。
- `added` 按候选声明顺序给出仅候选拥有的规则，`removed` 按基线声明顺序给出仅基线拥有的规则；两者使用与 `to_json` 相同的不含 `_index` 的规则快照——字段、固定字段顺序与嵌套标签键的 Unicode 码位排序完全一致（空的可选映射与未提供的排除字段同样省略）。
- `unchanged` 按基线声明顺序给出两边配置完全相同的 id；嵌套映射仅以归一化内容比较，输入时的键插入顺序不影响判定。
- `changed` 按基线声明顺序排列，每项固定含 `id`、`before`、`after`、`fields`、`before_index`、`after_index`：`before`/`after` 为基线/候选的规则快照，`before_index`/`after_index` 为两侧声明位置。`fields` 按固定顺序列出变化字段：`effect`、`priority`、`subject`、`action`、`resource`、`subject_exclude`、`action_exclude`、`resource_exclude`、`tags`、`tag_patterns`、`tag_exclude_patterns`、`tag_presence`；声明位置变化记为末尾的 `declaration_order`。仅位置变化（其余字段全同）也必须进入 `changed`，此时 `fields == ["declaration_order"]`。排除字段按归一化值比较（省略为 `null`，快照中不写出该键）。
- `summary` 固定含 `baseline_total`、`candidate_total`、`added`、`removed`、`changed`、`unchanged`，后四个计数与对应数组一致；两份空配置给出全零汇总。
- 任一快照无法按既有严格 JSON 语义表达（元组、集合、非有限数字、非字符串映射键、孤立代理项等，同直接构造后调用 `to_json` 的边界）时抛出消息含固定标记 `non_json_value` 的 `ValueError`，不返回部分报告。

## 请求覆盖报告

`PolicyGate.coverage(requests)` 用一批请求检查每条规则是否参与判定及赢得多少次，纯离线、只读，不改变任何判定结果。

- `requests` 沿用 `decide_many` 的边界：只接受 list 或 tuple，每项是含 `subject`、`action`、`resource` 字符串、可选 `tags` 的映射。整批先校验；未知字段、缺少字段、字段类型错误、非映射元素或批次容器错误均抛 `PolicyBatchError`（保留 `code`、`index`、`field`），不返回部分报告。
- 返回 `{"rules": [...], "summary": {...}}`。`rules` 按声明顺序列出每条规则的 `id`、`effect`、`matched`、`winner`：`matched` 是选择器（`fnmatch.fnmatchcase` 通配 + 标签精确约束）与请求匹配的次数，`winner` 是经显式 deny 优先、同效果按 priority 再按声明顺序决胜后最终胜出的次数。同一请求命中多条规则时所有命中规则的 `matched` 都计数，只有最终规则的 `winner` 计数；落入默认拒绝不增加任何规则的 `winner`。
- `summary` 固定含 `total`、`allow`、`explicit_deny`、`default_deny`、`matched_request`：`allow` 为最终效果为 allow 的请求数，`explicit_deny` 为由 deny 规则赢得的请求数，`default_deny` 为无匹配规则落入默认拒绝的请求数，`matched_request` 为至少命中一条规则的请求数。空批次返回全零计数；空规则集按请求数统计 `default_deny`。
- 报告结构及字段顺序稳定，重复调用得到相同值；不修改规则或调用方映射，不进行 I/O。

## 逐规则判定追踪

`PolicyGate.trace(subject, action, resource, tags=None)` 在保留 `decide` 判定结果的基础上，附带给定请求对每条规则的逐项匹配细节，供离线审查；`PolicyGate.trace_many(requests)` 生成批量追踪。

- 输入校验与 `decide` 完全一致（非法主体/动作/资源/标签类型抛同样的 `TypeError`）；返回映射的根级 `effect`、`rule`、`reason` 与 `decide` 结果逐项相等，并附 `evaluations` 数组。
- `evaluations` 按声明顺序覆盖所有规则，每项按固定顺序给出 `id`、`effect`、`priority`、`subject_match`、`action_match`、`resource_match`、`tags_match`、`matched`、`selected`：前三项用 `fnmatch.fnmatchcase` 比较，`tags_match` 使用现有标签精确约束（`tags=None` 视为空映射），`matched` 为四项合取，`selected` 仅最终胜出规则为真；默认拒绝时 `rule` 为 `None` 且所有 `selected` 为假。显式 deny、同效果的 priority 与声明顺序决胜、默认 deny 均沿用现有规则。
- `trace_many` 的 `requests` 沿用 `decide_many` 的边界，整批先校验，首个错误抛原有 `PolicyBatchError`（带 `code`、`index`、`field`），不返回部分结果；成功返回 `{"traces": [...], "summary": {"total", "allow", "deny"}}`，`traces` 按输入顺序排列，计数与 `decide_many` 相同，空批次为全零。
- 两个入口只读、纯离线：不修改规则或调用方映射，无网络和其他 I/O；直接构造和 `from_json` 加载的规则具有相同追踪语义，且不影响 `decide`、`decide_many`、`explain`、`audit`、`coverage`、`compare`、`from_json`、`to_json`、`fingerprint` 的既有行为。

## 发布前固定用例核验

`PolicyGate.verify(cases)` 在发布前按一组固定用例核对规则的最终决策，纯离线、只读，不改变规则或输入。

- `cases` 只接受 list 或 tuple；每项是映射，只允许 `subject`、`action`、`resource`、`tags`、`expected` 五个键。前三项为必填字符串，`tags` 可省略、为 `None` 或 mapping，匹配完全沿用 `decide` 的 `fnmatch.fnmatchcase` 通配、标签精确约束、显式 deny、priority、声明顺序和默认 deny。
- `expected` 必填，是只含 `effect`、`rule` 的映射：`effect` 必须为 `allow` 或 `deny`，`rule` 为字符串或 `null`；默认拒绝必须写成 `{"effect": "deny", "rule": None}`。
- 整批先校验再判定，任何错误都抛 `PolicyVerificationError`（带 `code`、`index`、`field`）且不返回部分结果。错误类别依次为：批次容器错误 `invalid_cases`（`index`/`field` 为 `None`）、元素非映射 `item_not_mapping`、未知字段 `unknown_field`、缺失字段 `missing_field`、字段类型错误 `invalid_field_type`、`expected` 取值非法 `invalid_expectation`；`expected` 的嵌套字段写作 `expected.effect`、`expected.rule`。
- 校验通过后按输入顺序调用既有 `decide`：仅 `effect` 和 `rule` 同时相等才算通过，`reason` 不参与比较。
- 返回固定结构 `{"ok", "failures", "summary"}`：`summary` 含 `total`、`passed`、`failed`；`failures` 按输入顺序给出 `index`、`expected`、`actual`，`actual` 是完整决策（含 `reason`）。`failed` 为零时 `ok` 为 `true`；空批次返回空 `failures`、全零汇总和 `true`。
- 返回内容为独立深拷贝，修改返回值不影响后续调用；重复调用、直接构造与 `from_json` 加载的同一规则结果相同。`verify` 不修改任何规则或输入、不产生外部 I/O，也不改变既有公开 API 的校验、字段、优先级与异常行为。

## 标签模式约束

规则可携带可选的 `tag_patterns` 映射，为一组环境或资源表达标签值的字符串模式，避免重复复制规则；不改变既有规则和任何返回结构。

- `tag_patterns` 的键必须是字符串，值是按 `fnmatch.fnmatchcase` 语义解释的字符串模式；同一键不能同时出现在 `tags` 和 `tag_patterns` 中。形状错误在 `PolicyGate` 构造和 `from_json` 加载阶段统一抛出 `ValueError`，消息前缀固定为 `invalid_tag_patterns`（非映射、非字符串键或值）或 `tag_constraint_conflict`（键冲突），不会延迟到 `decide`。未提供该字段按空映射处理，旧规则的决定、批量行为和异常边界保持不变。
- 请求的 `tags` 可省略或为任意 mapping；对 `tag_patterns` 而言，缺少键或对应值不是字符串只表示该规则不匹配。规则须同时满足主体、动作、资源、精确标签和所有模式标签，随后继续使用现有的显式 deny、priority、声明顺序和默认拒绝语义。
- `explain` 与 `trace` 的字段保持不变，其中 `trace` 的 `tags_match` 反映精确与模式两类标签约束的合取；`decide_many`、`verify`、`coverage`、`compare` 的输出形状和错误码沿用当前定义。
- `audit` 把模式标签纳入重叠、遮蔽和 witness 判断：同一键的两个模式只有存在共同字符串才算可满足，精确值与模式同时出现时精确值必须匹配该模式。`witness.tags` 只包含两条规则的约束并按 Unicode 键序输出；每个模式标签取同时满足约束的最短字符串，长度相同按 Unicode 码点字典序，且 witness 能重放 finding。
- `to_json` 在规则使用 `tag_patterns` 时按固定顺序紧跟 `tags` 导出该字段，`fingerprint` 随其变化；完全未使用新字段的规则，其 `to_json` 和 `fingerprint` 保持既有字节级结果。经 `from_json` 往返后所有公开方法给出相同结果，功能继续无网络、无外部 I/O。

## 标签排除模式约束

规则可携带可选的 `tag_exclude_patterns` 映射，声明某个标签值不得命中指定模式，从而表达“允许生产资源但排除临时环境”一类的反向约束；不改变既有规则和任何返回结构。

- `tag_exclude_patterns` 的键必须是字符串，值是按 `fnmatch.fnmatchcase` 语义解释的字符串模式；同一键不能同时出现在 `tags`、`tag_patterns` 与 `tag_exclude_patterns` 的任意两个之中。形状错误在 `PolicyGate` 构造和 `from_json` 加载阶段统一抛出 `ValueError`，消息前缀固定为 `invalid_tag_exclude_patterns`（非映射、非字符串键或值）或 `tag_constraint_conflict`（键冲突），不会延迟到 `decide`。未提供该字段或为空映射时按无排除约束处理，旧规则的判定、批量行为、审计结果和 `to_json` 字节保持不变。
- 判定时排除约束逐键生效：缺少该键、对应值不是字符串或值不匹配排除模式都视为通过，只有值实际命中排除模式才使该规则不匹配。主体、动作、资源、精确标签、模式标签以及显式 deny、priority、声明顺序和默认拒绝语义完全沿用。
- `explain` 与 `trace` 的字段保持不变，其中 `trace` 的 `tags_match` 反映精确、模式与排除三类标签约束的合取；`decide_many`、`verify`、`coverage`、`compare`、`trace_many` 的输出形状和错误码沿用当前定义。
- `audit` 把排除模式纳入重叠、`shadowed_rule`、`effect_overlap` 和 witness 判断：只有存在同时满足双方正向约束且避开双方排除模式的标签值时才报告 finding。`witness.tags` 只包含两条规则声明过的键（含仅出现在 `tag_exclude_patterns` 中的键），按键的 Unicode 码点序输出；每个键取能重放 finding 的最短字符串，长度相同按 Unicode 码点字典序，某键无可选值时不生成该 finding。
- `to_json` 在规则使用 `tag_exclude_patterns` 时按固定位置在 `tags`（及 `tag_patterns`）之后导出该字段，键递归按 Unicode 码点排序，`fingerprint` 随其变化；空映射不改变旧快照。经 `from_json` 往返后所有公开方法给出相同结果，功能继续无网络、无外部 I/O。

## 标签键存在性约束

规则可携带可选的 `tag_presence` 映射，声明某个标签键必须存在或必须不存在，从而区分“标签缺失”与“标签值不匹配”；不改变既有规则和任何返回结构。

- `tag_presence` 必须是对象，键必须是字符串，值只能是布尔值：`true` 要求请求 `tags` 包含该键（值可为任意类型），`false` 要求该键不存在。同一键不能同时出现在 `tags`、`tag_patterns` 或 `tag_exclude_patterns` 与 `tag_presence` 之中。形状错误在 `PolicyGate` 构造和 `from_json` 加载阶段统一抛出 `ValueError`，消息前缀固定为 `invalid_tag_presence`（非对象、非字符串键或非布尔值）或 `tag_presence_conflict`（键冲突），不会延迟到 `decide`。省略该字段或为空对象时按无存在性约束处理，旧规则的判定、批量行为、审计结果和 `to_json` 字节保持不变。
- 判定时 `tags=None` 仍按空映射处理；规则须同时满足存在性约束、已有精确/模式/排除标签约束、主体、动作和资源模式，显式 deny、priority、声明顺序及默认拒绝语义完全沿用。`decide`、`explain`、`trace`、`decide_many`、`trace_many`、`verify`、`coverage`、`compare` 的输出形状和错误码沿用当前定义，其中 `trace` 的 `tags_match` 反映存在性与其余标签条件的合取。
- `audit` 把存在性条件纳入重叠、`shadowed_rule`、`effect_overlap` 与 witness 判断：要求存在与要求缺失的同键（或要求缺失的键被另一规则的精确/模式约束钉住）视为不可满足，不生成 finding；仅被排除模式约束的缺失键因缺席而通过排除。`witness.tags` 只包含两条规则声明的键并按 Unicode 码点排序；要求缺失的键不写入，仅要求存在且无其他值约束的键取满足双方条件的最短字符串（长度相同取 Unicode 码点字典序最小者），其余精确、模式和排除约束沿用既有见证规则。
- `to_json` 在规则使用 `tag_presence` 时按固定位置在 `tags`、`tag_patterns`、`tag_exclude_patterns` 之后导出该字段，键递归按 Unicode 码点排序，`fingerprint` 随其变化；空字段不改变旧快照。经 `from_json` 往返后所有公开方法给出相同结果，功能继续无网络、无外部 I/O。

## 选择器排除模式

规则可携带可选的 `subject_exclude`、`action_exclude`、`resource_exclude` 三个字符串字段，声明对应维度不得命中的 `fnmatch.fnmatchcase` 模式，从而表达“允许所有读操作但排除批量导出”一类的反向选择器；不改变既有规则和任何返回结构。

- 三个字段各自独立：未提供表示该维度无排除；提供后必须是字符串，空字符串也按 `fnmatch.fnmatchcase` 真实语义处理（仅排除空字符串）。类型错误在 `PolicyGate` 构造和 `from_json` 加载阶段统一抛出 `ValueError`，消息前缀固定为 `invalid_selector_exclusion` 并带规则索引与字段名，不会延迟到 `decide`；未知字段、其他配置错误和异常优先级沿用既有定义。
- 请求只有在正向选择器匹配且未命中该维度排除模式时才命中规则，三个维度与标签约束合取；默认拒绝、显式 deny 优先、同效果按 priority 与声明顺序决胜完全沿用。`decide`、`explain`、`trace`、`decide_many`、`trace_many`、`verify`、`coverage`、`compare` 的输出形状和错误码不变，其中 `trace` 的 `subject_match`、`action_match`、`resource_match` 分别表示正向匹配与排除检查的合取。
- `audit` 把排除模式纳入重叠、`shadowed_rule`、`effect_overlap` 与选择器相同性判断：只有存在同时满足双方正向模式且避开双方排除模式的主体/动作/资源字符串时才报告 finding；任一维度无可满足字符串就不生成 finding。`witness` 的三个字符串字段各自独立地取满足上述条件的最短字符串，长度相同按 Unicode 码点字典序取小，交回 `decide`/`explain` 仍同时命中两条规则；重复审计结果稳定，修改返回报告不影响后续调用。
- `to_json` 在规则使用这些字段时按 `subject_exclude`、`action_exclude`、`resource_exclude` 的固定顺序紧跟 `resource` 导出（仅导出实际提供的字段，显式空字符串照常写出），`fingerprint` 随其变化；完全未使用新字段的规则，其判定、审计结果、`to_json` 字节和 `fingerprint` 保持既有结果。经 `from_json` 往返后所有公开方法给出相同结果，功能继续无网络、无外部 I/O。

## 规则说明文字

规则可携带可选的 `description` 字符串字段，为命中的规则提供面向审查者的稳定说明；说明只用于展示，不参与任何判定。

- `description` 必须是字符串，允许空字符串；省略时规则与旧规则完全相同。非字符串在 `PolicyGate` 构造和 `from_json` 加载阶段统一抛出 `ValueError`，消息前缀固定为 `invalid_description` 并标明规则索引与字段名，不会延迟到 `decide`；未知字段与其他配置错误的检查顺序保持不变。
- 说明不参与 `fnmatch` 匹配、标签约束、显式 deny、priority、声明顺序或默认 deny：`decide`、`decide_many`、`trace`、`diagnose`、`coverage`、`compare`、`verify` 和 `audit` 的结果、异常边界与只读性完全沿用既有定义。
- `explain` 返回的 `matched_rules` 中，仅实际提供 `description` 的规则增加同名键（空字符串照常写出），没有说明的规则保持原有返回结构；返回值可安全修改而不影响 gate。
- `to_json` 在规则提供 `description` 时把它写在 `resource` 之后、选择器排除字段与 `tags` 之前，`fingerprint` 随说明文字变化；省略该字段的规则继续产生原来的 JSON 字节。经 `from_json` 往返后决定、审计与快照完全一致，重复调用、直接构造与 `from_json` 构造得到相同说明。
- `rule_change_report` 对同一 id 的说明变化把 `description` 列入 `changed.fields`（固定字段顺序中位于 `resource` 之后），`before`/`after` 各自给出独立快照副本；新增或移除规则的快照同样保留该字段。


