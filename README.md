# Policy Gate

A dependency-free Python reference implementation for security, policy-as-code, rbac.

Run with: python3 demo.py
Tests: python3 -m unittest discover -s tests -v

## Scope

实现一个无网络的策略判定器，按主体、动作、资源和标签匹配规则并返回可解释的 allow 或 deny 决策。规则优先级、显式拒绝、默认拒绝、通配匹配和冲突处理必须有稳定定义；判定结果要包含命中的规则和原因，配置错误在加载阶段失败，便于在发布前做离线安全检查。
