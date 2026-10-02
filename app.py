import fnmatch
import json
from collections.abc import Mapping

_ALLOWED_FIELDS = frozenset(
    {"id", "effect", "priority", "subject", "action", "resource", "tags"}
)
_STRING_FIELDS = ("subject", "action", "resource")
_REQUEST_FIELDS = ("subject", "action", "resource", "tags")


class PolicyConfigError(Exception):
    """A JSON policy document could not be loaded.

    The machine-readable ``code`` attribute distinguishes failure classes:
    ``invalid_json``, ``duplicate_key``, ``root_not_array`` or
    ``rule_not_object``. Semantic problems inside an otherwise well-formed
    rule object keep raising plain ``ValueError`` (see ``PolicyGate``).
    """

    def __init__(self, code, message):
        self.code = code
        super().__init__("[%s] %s" % (code, message))


class PolicyBatchError(Exception):
    """A batch handed to :meth:`PolicyGate.decide_many` failed validation.

    The machine-readable ``code`` attribute is one of ``invalid_batch``,
    ``item_not_mapping``, ``unknown_field``, ``missing_field`` or
    ``invalid_field_type``. ``index`` names the offending request (``None``
    when the outer container itself is invalid); ``field`` names the
    offending request field (``None`` for non-field errors). No partial
    results are produced when this is raised.
    """

    def __init__(self, code, index, field=None, message=None):
        self.code = code
        self.index = index
        self.field = field
        if message is None:
            if code == "invalid_batch":
                message = "batch must be a list or tuple of request mappings"
            elif code == "item_not_mapping":
                message = "request %d: item must be a mapping" % index
            elif code == "unknown_field":
                message = "request %d: unknown field %r" % (index, field)
            elif code == "missing_field":
                message = "request %d: missing required field %r" % (index, field)
            else:
                message = "request %d: field %r has an invalid type" % (
                    index,
                    field,
                )
        super().__init__("[%s] %s" % (code, message))


class _DuplicateKeyError(ValueError):
    """Raised internally by the JSON object hook when a key repeats."""


def _reject_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKeyError(key)
        obj[key] = value
    return obj


def _reject_constant(value):
    # json.loads accepts NaN/Infinity by default; strict JSON does not.
    raise ValueError("invalid JSON constant %r" % value)


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
        """Build a gate from a JSON text document.

        ``document`` must be a ``str`` whose root JSON value is an array of
        rule objects. Loading performs no decisions, no I/O and never
        mutates the input text; on failure no partially built instance
        escapes this method.

        Structural JSON problems raise :class:`PolicyConfigError` with a
        ``code`` of ``invalid_json``, ``duplicate_key``, ``root_not_array``
        or ``rule_not_object``; semantic rule errors raise ``ValueError``
        exactly like the direct constructor (naming the first bad index).
        """
        if not isinstance(document, str):
            raise TypeError("document must be a JSON text string")

        try:
            rules = json.loads(
                document,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except _DuplicateKeyError as exc:
            raise PolicyConfigError(
                "duplicate_key", "duplicate key %r in JSON object" % str(exc)
            ) from None
        except (json.JSONDecodeError, ValueError) as exc:
            raise PolicyConfigError(
                "invalid_json", "document is not valid JSON: %s" % exc
            ) from None

        if not isinstance(rules, list):
            raise PolicyConfigError(
                "root_not_array",
                "root JSON value must be an array, got %s"
                % type(rules).__name__,
            )
        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                raise PolicyConfigError(
                    "rule_not_object",
                    "rule %d: array element must be a JSON object, got %s"
                    % (i, type(rule).__name__),
                )

        return cls(rules)

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

    @staticmethod
    def _validate_batch(requests):
        """Validate a decide_many payload; return the accepted list.

        Validation runs over the whole payload before any decision, so a
        failure never yields partial results. Within one item, checks run
        unknown-field first, then missing-field, then field-type, with
        fields visited in the fixed subject/action/resource/tags order.
        Neither the rules nor any caller mapping is mutated.
        """
        if not isinstance(requests, (list, tuple)):
            raise PolicyBatchError(
                "invalid_batch",
                None,
                None,
                "batch must be a list or tuple of request mappings, got %s"
                % type(requests).__name__,
            )

        for index, item in enumerate(requests):
            if not isinstance(item, Mapping):
                raise PolicyBatchError("item_not_mapping", index)

            keys = set(item)

            def first_unknown():
                unknown = sorted(keys - set(_REQUEST_FIELDS))
                return unknown[0] if unknown else None

            unknown_field = first_unknown()
            if unknown_field is not None:
                raise PolicyBatchError("unknown_field", index, unknown_field)

            for field in _REQUEST_FIELDS:
                if field not in keys:
                    if field == "tags":
                        continue  # tags is optional
                    raise PolicyBatchError("missing_field", index, field)

            for field in _STRING_FIELDS:
                if not isinstance(item[field], str):
                    raise PolicyBatchError("invalid_field_type", index, field)
            if "tags" in keys and item["tags"] is not None and not isinstance(
                item["tags"], Mapping
            ):
                raise PolicyBatchError("invalid_field_type", index, "tags")

        return requests

    def decide_many(self, requests):
        """Evaluate many requests in one offline, reviewable batch.

        ``requests`` must be a list or tuple of mappings, each limited to
        the keys ``subject``, ``action``, ``resource`` and ``tags``. The
        three string fields are required and must be strings; ``tags`` is
        optional and may be omitted, ``None`` or any mapping accepted by
        :meth:`decide`.

        Returns ``{"decisions": [...], "summary": {"total", "allow",
        "deny"}}``; decisions appear in input order and are byte-for-byte
        the same effect/rule/reason mappings that repeated ``decide`` calls
        would produce, and an empty batch yields an empty decision list
        and an all-zero summary. Validation failures raise
        :class:`PolicyBatchError` before any decision is made.
        """
        requests = self._validate_batch(requests)

        decisions = [
            self.decide(
                item["subject"],
                item["action"],
                item["resource"],
                item.get("tags"),
            )
            for item in requests
        ]
        allow = sum(1 for d in decisions if d["effect"] == "allow")
        return {
            "decisions": decisions,
            "summary": {
                "total": len(decisions),
                "allow": allow,
                "deny": len(decisions) - allow,
            },
        }

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
