import fnmatch

_ALLOWED_FIELDS = frozenset(
    {"id", "effect", "priority", "subject", "action", "resource", "tags"}
)
_EFFECTS = ("allow", "deny")


class PolicyGate:
    """离线策略判定器：按 subject/action/resource/tags 匹配规则，
    显式 deny 优先，同 effect 内按 priority 降序、声明顺序升序裁决。"""

    def __init__(self, rules):
        if not isinstance(rules, (list, tuple)):
            raise ValueError(
                "invalid rules: expected a sequence (list/tuple) of rule "
                "mappings, got %s" % type(rules).__name__
            )
        normalized = []
        seen_ids = set()
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise ValueError(
                    "invalid rule at index %d: rule must be a mapping" % i
                )

            effect = rule.get("effect")
            if effect not in _EFFECTS:
                raise ValueError(
                    "invalid rule at index %d: field 'effect' must be one of "
                    "'allow' or 'deny'" % i
                )

            rule_id = rule.get("id", str(i))
            if not isinstance(rule_id, str) or not rule_id:
                raise ValueError(
                    "invalid rule at index %d: field 'id' must be a non-empty "
                    "string" % i
                )
            if rule_id in seen_ids:
                raise ValueError(
                    "invalid rule at index %d: field 'id' duplicates an "
                    "earlier rule id %r" % (i, rule_id)
                )

            priority = rule.get("priority", 0)
            if isinstance(priority, bool) or not isinstance(priority, int):
                raise ValueError(
                    "invalid rule at index %d: field 'priority' must be a "
                    "non-boolean integer" % i
                )

            for field in ("subject", "action", "resource"):
                value = rule.get(field, "*")
                if not isinstance(value, str):
                    raise ValueError(
                        "invalid rule at index %d: field %r must be a string"
                        % (i, field)
                    )

            tags = rule.get("tags", {})
            if not isinstance(tags, dict) or not all(
                isinstance(key, str) for key in tags
            ):
                raise ValueError(
                    "invalid rule at index %d: field 'tags' must be a mapping "
                    "with string keys" % i
                )

            unsupported = sorted(set(rule) - _ALLOWED_FIELDS)
            if unsupported:
                raise ValueError(
                    "invalid rule at index %d: unsupported field %r"
                    % (i, unsupported[0])
                )

            seen_ids.add(rule_id)
            normalized.append(
                {
                    "id": rule_id,
                    "effect": effect,
                    "priority": priority,
                    "subject": rule.get("subject", "*"),
                    "action": rule.get("action", "*"),
                    "resource": rule.get("resource", "*"),
                    "tags": dict(tags),
                    "_index": i,
                }
            )
        self.rules = normalized

    def decide(self, subject, action, resource, tags=None):
        for name, value in (
            ("subject", subject),
            ("action", action),
            ("resource", resource),
        ):
            if not isinstance(value, str):
                raise TypeError("%s must be a string" % name)
        if tags is None:
            request_tags = {}
        elif not isinstance(tags, dict):
            raise TypeError("tags must be a mapping or None")
        else:
            request_tags = tags

        matches = [
            rule
            for rule in self.rules
            if fnmatch.fnmatchcase(subject, rule["subject"])
            and fnmatch.fnmatchcase(action, rule["action"])
            and fnmatch.fnmatchcase(resource, rule["resource"])
            and all(request_tags.get(k) == v for k, v in rule["tags"].items())
        ]
        if not matches:
            return {"effect": "deny", "rule": None, "reason": "default deny"}

        # deny 始终优先；同 effect 内 priority 降序、原始下标升序。
        winner = min(
            matches,
            key=lambda r: (
                0 if r["effect"] == "deny" else 1,
                -r["priority"],
                r["_index"],
            ),
        )
        if winner["effect"] == "deny":
            reason = (
                "explicit deny overrides any allow: matched deny rule %r with "
                "priority %d" % (winner["id"], winner["priority"])
            )
        else:
            reason = "matched allow rule %r with priority %d" % (
                winner["id"],
                winner["priority"],
            )
        return {"effect": winner["effect"], "rule": winner["id"], "reason": reason}
