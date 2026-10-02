import fnmatch
from collections.abc import Mapping

_ALLOWED_FIELDS = frozenset(
    {"id", "effect", "priority", "subject", "action", "resource", "tags"}
)
_STRING_FIELDS = ("subject", "action", "resource")


class PolicyGate:
    """Offline policy evaluator.

    Rules are fully validated at construction time; decide() only performs
    deterministic matching over the normalized rule list.
    """

    def __init__(self, rules):
        if not isinstance(rules, (list, tuple)):
            raise ValueError("rules must be a sequence of rule mappings")
        self.rules = []
        seen_ids = set()
        for i, r in enumerate(rules):
            if not isinstance(r, dict):
                raise ValueError("rule %d: rule must be a mapping" % i)

            effect = r.get("effect")
            if effect not in ("allow", "deny"):
                raise ValueError(
                    "rule %d: field 'effect' must be 'allow' or 'deny'" % i
                )

            rid = r.get("id", str(i))
            if not isinstance(rid, str) or not rid:
                raise ValueError(
                    "rule %d: field 'id' must be a non-empty string" % i
                )
            if rid in seen_ids:
                raise ValueError("rule %d: duplicate id %r" % (i, rid))
            seen_ids.add(rid)

            priority = r.get("priority", 0)
            if not isinstance(priority, int) or isinstance(priority, bool):
                raise ValueError(
                    "rule %d: field 'priority' must be a non-boolean integer" % i
                )

            for field in _STRING_FIELDS:
                if not isinstance(r.get(field, "*"), str):
                    raise ValueError(
                        "rule %d: field %r must be a string" % (i, field)
                    )

            tags = r.get("tags", {})
            if not isinstance(tags, dict) or not all(
                isinstance(k, str) for k in tags
            ):
                raise ValueError(
                    "rule %d: field 'tags' must be a mapping with string keys" % i
                )

            unsupported = set(r) - _ALLOWED_FIELDS
            if unsupported:
                raise ValueError(
                    "rule %d: unsupported field %r" % (i, sorted(unsupported)[0])
                )

            self.rules.append(
                {
                    "id": rid,
                    "effect": effect,
                    "priority": priority,
                    "subject": r.get("subject", "*"),
                    "action": r.get("action", "*"),
                    "resource": r.get("resource", "*"),
                    "tags": tags,
                    "_index": i,
                }
            )

    @staticmethod
    def _matches(rule, subject, action, resource, tags):
        return (
            fnmatch.fnmatchcase(subject, rule["subject"])
            and fnmatch.fnmatchcase(action, rule["action"])
            and fnmatch.fnmatchcase(resource, rule["resource"])
            and all(tags.get(k) == v for k, v in rule["tags"].items())
        )

    def decide(self, subject, action, resource, tags=None):
        for name, value in (
            ("subject", subject),
            ("action", action),
            ("resource", resource),
        ):
            if not isinstance(value, str):
                raise TypeError("%s must be a string" % name)
        if tags is None:
            tags = {}
        elif not isinstance(tags, Mapping):
            raise TypeError("tags must be a mapping or None")

        matched = [
            r
            for r in self.rules
            if self._matches(r, subject, action, resource, tags)
        ]
        denies = [r for r in matched if r["effect"] == "deny"]
        allows = [r for r in matched if r["effect"] == "allow"]

        # Explicit deny always wins; within one effect, higher priority wins,
        # then the earliest declaration order breaks ties deterministically.
        winners = denies if denies else allows
        if not winners:
            return {"effect": "deny", "rule": None, "reason": "default deny"}

        winner = min(winners, key=lambda r: (-r["priority"], r["_index"]))
        reason = "matched %s rule %r (priority %d)" % (
            winner["effect"],
            winner["id"],
            winner["priority"],
        )
        if winner["effect"] == "deny" and allows:
            reason += "; explicit deny overrides allow"
        return {"effect": winner["effect"], "rule": winner["id"], "reason": reason}
