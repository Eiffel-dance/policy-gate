import fnmatch
import json
from collections.abc import Mapping

_ALLOWED_FIELDS = frozenset(
    {"id", "effect", "priority", "subject", "action", "resource", "tags"}
)
_STRING_FIELDS = ("subject", "action", "resource")


class PolicyConfigError(Exception):
    """Raised when a JSON policy document cannot be loaded.

    Carries a public string ``code`` identifying the failure category:
    ``invalid_json``, ``duplicate_key``, ``root_not_array`` or
    ``rule_not_object``. Semantic rule violations still surface as the
    constructor's plain ValueError.
    """

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _reject_duplicate_keys(pairs):
    """object_pairs_hook that refuses silent last-wins key overwrites."""
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise PolicyConfigError(
                "duplicate_key", "duplicate key %r in JSON object" % key
            )
        obj[key] = value
    return obj


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

    @classmethod
    def from_json(cls, document):
        """Load a gate from a JSON text string.

        The root value must be an array of rule objects; each rule is
        validated by the regular constructor, so all field constraints,
        defaults and matching semantics are identical to PolicyGate(rules).
        Duplicate keys at any nesting level are rejected instead of
        silently overwriting earlier values. Loading performs no decision,
        no file or network access, and never mutates the input text.

        Raises TypeError for a non-string document, PolicyConfigError for
        malformed JSON / duplicate keys / wrong root or element shape, and
        ValueError for semantic rule violations (first offending index).
        """
        if not isinstance(document, str):
            raise TypeError("document must be a JSON text string")
        try:
            data = json.loads(document, object_pairs_hook=_reject_duplicate_keys)
        except PolicyConfigError:
            raise
        except json.JSONDecodeError as exc:
            raise PolicyConfigError(
                "invalid_json", "invalid JSON document: %s" % exc
            ) from exc
        if not isinstance(data, list):
            raise PolicyConfigError(
                "root_not_array", "root value must be an array of rule objects"
            )
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                raise PolicyConfigError(
                    "rule_not_object", "rule %d: rule must be an object" % i
                )
        return cls(data)

    @staticmethod
    def _matches(rule, subject, action, resource, tags):
        return (
            fnmatch.fnmatchcase(subject, rule["subject"])
            and fnmatch.fnmatchcase(action, rule["action"])
            and fnmatch.fnmatchcase(resource, rule["resource"])
            and all(tags.get(k) == v for k, v in rule["tags"].items())
        )

    @staticmethod
    def _check_inputs(subject, action, resource, tags):
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
        return tags

    def _evaluate(self, subject, action, resource, tags):
        """Shared decision core; returns (decision, matched rules in order)."""
        tags = self._check_inputs(subject, action, resource, tags)

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
            return (
                {"effect": "deny", "rule": None, "reason": "default deny"},
                matched,
            )

        winner = min(winners, key=lambda r: (-r["priority"], r["_index"]))
        reason = "matched %s rule %r (priority %d)" % (
            winner["effect"],
            winner["id"],
            winner["priority"],
        )
        if winner["effect"] == "deny" and allows:
            reason += "; explicit deny overrides allow"
        return (
            {"effect": winner["effect"], "rule": winner["id"], "reason": reason},
            matched,
        )

    def decide(self, subject, action, resource, tags=None):
        result, _matched = self._evaluate(subject, action, resource, tags)
        return result

    def explain(self, subject, action, resource, tags=None):
        """Read-only offline view of one decision and its full evidence.

        Shares decide()'s validation and selection semantics; adds
        matched_rules, every actually matched rule in declaration order.
        Does not mutate the rule list or touch any external state.
        """
        result, matched = self._evaluate(subject, action, resource, tags)
        explanation = dict(result)
        explanation["matched_rules"] = [
            {"id": r["id"], "effect": r["effect"], "priority": r["priority"]}
            for r in matched
        ]
        return explanation
