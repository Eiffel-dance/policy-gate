import fnmatch
import hashlib
import json
import math
from collections.abc import Mapping

_ALLOWED_FIELDS = frozenset(
    {"id", "effect", "priority", "subject", "action", "resource", "tags"}
)
_STRING_FIELDS = ("subject", "action", "resource")
_REQUEST_FIELDS = frozenset({"subject", "action", "resource", "tags"})


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
    ``invalid_field_type``. ``index`` is the offending element index, or
    ``None`` when the outer batch value itself is not a list or tuple.
    ``field`` names the offending request field for the field-level codes
    and is ``None`` otherwise.
    """

    def __init__(self, code, index, field=None, message=None):
        self.code = code
        self.index = index
        self.field = field
        if message is None:
            message = self._default_message(code, index, field)
        super().__init__("[%s] %s" % (code, message))

    @staticmethod
    def _default_message(code, index, field):
        if code == "invalid_batch":
            return "batch must be a list or tuple of request mappings"
        if code == "item_not_mapping":
            return "request at index %s must be a mapping" % index
        if code == "unknown_field":
            return "request at index %d contains unknown field %r" % (index, field)
        if code == "missing_field":
            return "request at index %d is missing required field %r" % (index, field)
        if code == "invalid_field_type":
            return "request at index %d field %r has an invalid type" % (index, field)
        return "batch validation failed"


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


# --- canonical snapshot serialization (to_json / fingerprint) ------------
#
# A snapshot must be lossless strict JSON and byte-stable across calls, so
# every value is validated and copied into a fresh structure first: tuples,
# sets, other non-JSON containers, non-finite numbers and mappings with
# non-string keys raise ValueError tagged with the fixed marker
# ``non_json_value``; mapping keys are sorted by Unicode code point at every
# nesting level. The caller's mappings are never mutated or aliased.

def _canonical_snapshot_value(value, location):
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, str) or isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(
                "non_json_value: %s is %r, not a finite JSON number"
                % (location, value)
            )
        return value
    if isinstance(value, Mapping):
        normalized = {}
        for key in value:
            if not isinstance(key, str):
                raise ValueError(
                    "non_json_value: %s contains a non-string mapping key %r"
                    % (location, key)
                )
            normalized[key] = _canonical_snapshot_value(
                value[key], "%s[%r]" % (location, key)
            )
        # Rebuild in Unicode (code-point) dictionary order.
        return {key: normalized[key] for key in sorted(normalized)}
    if isinstance(value, list):
        return [
            _canonical_snapshot_value(item, "%s[%d]" % (location, index))
            for index, item in enumerate(value)
        ]
    raise ValueError(
        "non_json_value: %s has type %s, which cannot be represented in "
        "strict JSON" % (location, type(value).__name__)
    )


# --- static pattern analysis (used by PolicyGate.audit) ------------------
#
# A pattern is compiled to a tuple of tokens mirroring fnmatch.translate
# semantics exactly: ("star",) for `*`, or ("char", negated, ranges) for a
# single-character matcher, where ranges is a sorted tuple of inclusive
# (lo, hi) codepoint pairs describing the set as written (the set excluded
# when negated). `?` and literal characters are single-character matchers
# too. An empty positive range set never matches any character.

_FULL_RANGE = ((0, 0x10FFFF),)
_STAR = ("star",)
_ANY_CHAR = ("char", False, _FULL_RANGE)


def _normalize_ranges(ranges):
    """Sort inclusive (lo, hi) ranges and merge overlapping/adjacent ones."""
    merged = []
    for lo, hi in sorted(ranges):
        if merged and lo <= merged[-1][1] + 1:
            if hi > merged[-1][1]:
                merged[-1] = (merged[-1][0], hi)
        else:
            merged.append((lo, hi))
    return tuple(merged)


def _chars_to_ranges(chars):
    return _normalize_ranges((ord(c), ord(c)) for c in chars)


def _parse_class(pat, start):
    """Parse the ``[``-class at ``pat[start]`` like fnmatch.translate does.

    Returns ``(negated, ranges, next_index)``, or ``None`` when the ``[``
    is unterminated and fnmatch treats it as a literal character.
    """
    n = len(pat)
    j = start + 1
    if j < n and pat[j] == "!":
        j += 1
    if j < n and pat[j] == "]":
        j += 1
    while j < n and pat[j] != "]":
        j += 1
    if j >= n:
        return None
    body = pat[start + 1:j]
    nxt = j + 1
    if "-" not in body:
        if not body:
            return (False, (), nxt)  # empty range: never matches
        if body == "!":
            return (False, _FULL_RANGE, nxt)  # negated empty: any char
        negated = body[0] == "!"
        return (negated, _chars_to_ranges(body[1:] if negated else body), nxt)
    # Range-aware chunk processing, mirroring fnmatch.translate: dashes
    # found after the first body char split the body into chunks joined by
    # ranges; chunks whose range would be empty are merged away.
    chunks = []
    k = start + 3 if pat[start + 1] == "!" else start + 2
    i = start + 1
    while True:
        k = pat.find("-", k, j)
        if k < 0:
            break
        chunks.append(pat[i:k])
        i = k + 1
        k = k + 3
    chunk = pat[i:j]
    if chunk:
        chunks.append(chunk)
    else:
        chunks[-1] += "-"
    for m in range(len(chunks) - 1, 0, -1):
        if chunks[m - 1][-1] > chunks[m][0]:
            chunks[m - 1] = chunks[m - 1][:-1] + chunks[m][1:]
            del chunks[m]
    if chunks == [""]:
        return (False, (), nxt)  # empty range: never matches
    negated = chunks[0][0] == "!"
    if negated:
        chunks[0] = chunks[0][1:]
        if chunks == [""]:
            return (False, _FULL_RANGE, nxt)  # negated empty: any char
    ranges = []
    for m, chunk in enumerate(chunks):
        lo = 1 if m > 0 else 0
        hi = len(chunk) - 1 if m < len(chunks) - 1 else len(chunk)
        ranges.extend((ord(c), ord(c)) for c in chunk[lo:hi])
    for m in range(len(chunks) - 1):
        ranges.append((ord(chunks[m][-1]), ord(chunks[m + 1][0])))
    return (negated, _normalize_ranges(ranges), nxt)


def _tokenize_pattern(pat):
    """Compile a glob pattern to the token tuple used for overlap checks."""
    tokens = []
    i, n = 0, len(pat)
    while i < n:
        c = pat[i]
        if c == "*":
            tokens.append(_STAR)
            while i < n and pat[i] == "*":
                i += 1
        elif c == "?":
            tokens.append(_ANY_CHAR)
            i += 1
        elif c == "[":
            parsed = _parse_class(pat, i)
            if parsed is None:
                tokens.append(("char", False, _chars_to_ranges("[")))
                i += 1
            else:
                negated, ranges, i = parsed
                tokens.append(("char", negated, ranges))
        else:
            tokens.append(("char", False, _chars_to_ranges(c)))
            i += 1
    return tuple(tokens)


def _positive_ranges(token):
    """Positive codepoint ranges matched by a ("char", ...) token."""
    negated, ranges = token[1], token[2]
    if not negated:
        return ranges
    complement = []
    lo = 0
    for r_lo, r_hi in ranges:
        if r_lo > lo:
            complement.append((lo, r_lo - 1))
        lo = r_hi + 1
    if lo <= 0x10FFFF:
        complement.append((lo, 0x10FFFF))
    return tuple(complement)


def _ranges_intersect(r1, r2):
    i = j = 0
    while i < len(r1) and j < len(r2):
        if max(r1[i][0], r2[j][0]) <= min(r1[i][1], r2[j][1]):
            return True
        if r1[i][1] < r2[j][1]:
            i += 1
        else:
            j += 1
    return False


def _class_satisfiable(token):
    return bool(_positive_ranges(token))


def _classes_overlap(t1, t2):
    return _ranges_intersect(_positive_ranges(t1), _positive_ranges(t2))


def _patterns_overlap(t1, t2):
    """True iff some string matches both tokenized glob patterns.

    Dynamic programming over the token grid: dp[i][j] is True when the
    suffixes t1[i:] and t2[j:] can match a common string. `*` either
    matches empty or absorbs one character matched by the other side.
    """
    n1, n2 = len(t1), len(t2)
    star1 = [True] * (n1 + 1)
    for i in range(n1 - 1, -1, -1):
        star1[i] = star1[i + 1] and t1[i][0] == "star"
    star2 = [True] * (n2 + 1)
    for j in range(n2 - 1, -1, -1):
        star2[j] = star2[j + 1] and t2[j][0] == "star"

    row = bytearray(star2)  # row i == n1: t1 exhausted, t2[j:] must be stars
    for i in range(n1 - 1, -1, -1):
        cur = bytearray(n2 + 1)
        cur[n2] = star1[i]
        a = t1[i]
        a_star = a[0] == "star"
        for j in range(n2 - 1, -1, -1):
            b = t2[j]
            if a_star and b[0] == "star":
                cur[j] = cur[j + 1] or row[j]
            elif a_star:
                cur[j] = row[j] or (_class_satisfiable(b) and cur[j + 1])
            elif b[0] == "star":
                cur[j] = cur[j + 1] or (_class_satisfiable(a) and row[j])
            else:
                cur[j] = _classes_overlap(a, b) and row[j + 1]
        row = cur
    return bool(row[0])


def _tags_compatible(t1, t2):
    # Constraints on disjoint keys are jointly satisfiable (the caller may
    # supply extra tags); only a shared key with different values conflicts.
    return all(k not in t2 or t2[k] == v for k, v in t1.items())


def _audit_pair(r1, r2, c1, c2):
    """Build the finding for one rule pair, or None when there is none."""
    if not (
        _patterns_overlap(c1[0], c2[0])
        and _patterns_overlap(c1[1], c2[1])
        and _patterns_overlap(c1[2], c2[2])
        and _tags_compatible(r1["tags"], r2["tags"])
    ):
        return None

    identical = (
        r1["subject"] == r2["subject"]
        and r1["action"] == r2["action"]
        and r1["resource"] == r2["resource"]
        and r1["tags"] == r2["tags"]
    )
    if identical:
        # Identical selectors: one rule can never win, so it is shadowed.
        if r1["effect"] != r2["effect"]:
            winner = r1 if r1["effect"] == "deny" else r2
            severity = "error"
        else:
            # r1 is declared earlier, so it wins priority ties.
            winner = r1 if r1["priority"] >= r2["priority"] else r2
            severity = "warning"
        loser = r2 if winner is r1 else r1
        if severity == "error":
            reason = (
                "rule %r is fully shadowed by deny rule %r: identical "
                "selectors, and explicit deny overrides allow"
                % (loser["id"], winner["id"])
            )
        else:
            reason = (
                "rule %r is fully shadowed by rule %r: identical "
                "selectors, and priority then declaration order always "
                "prefer %r" % (loser["id"], winner["id"], winner["id"])
            )
        return {
            "code": "shadowed_rule",
            "severity": severity,
            "rule": r1["id"],
            "other_rule": r2["id"],
            "winner": winner["id"],
            "shadowed": loser["id"],
            "reason": reason,
        }

    if r1["effect"] != r2["effect"]:
        deny = r1 if r1["effect"] == "deny" else r2
        allow = r2 if deny is r1 else r1
        return {
            "code": "effect_overlap",
            "severity": "error",
            "rule": r1["id"],
            "other_rule": r2["id"],
            "winner": deny["id"],
            "shadowed": None,
            "reason": (
                "selectors overlap; explicit deny rule %r overrides allow "
                "rule %r for every request matching both, regardless of "
                "priority" % (deny["id"], allow["id"])
            ),
        }

    # Same-effect partial overlap is not a conflict.
    return None


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

    def _snapshot(self):
        """Canonical, fully normalized copy of the loaded rules.

        Rules stay in declaration order; each rule exposes exactly the
        normalized ``id``, ``effect``, ``priority``, ``subject``,
        ``action``, ``resource`` and ``tags`` that actually drive
        decisions (defaults made explicit, the internal ``_index``
        omitted). Mapping keys, including nested tag mappings, are
        recursively sorted by Unicode code point. Raises ``ValueError``
        whose message carries the fixed marker ``non_json_value`` when a
        value cannot be represented losslessly in strict JSON; no partial
        snapshot escapes in that case.
        """
        return _canonical_snapshot_value(
            [
                {
                    "id": rule["id"],
                    "effect": rule["effect"],
                    "priority": rule["priority"],
                    "subject": rule["subject"],
                    "action": rule["action"],
                    "resource": rule["resource"],
                    "tags": rule["tags"],
                }
                for rule in self.rules
            ],
            "rules",
        )

    def to_json(self):
        """Export the loaded rules as canonical strict JSON text.

        The root value is an array preserving declaration order; every
        rule writes the normalized, actually-effective ``id``,
        ``effect``, ``priority``, ``subject``, ``action``, ``resource``
        and ``tags``, with defaults explicit and no internal indexes.
        Mapping keys are recursively sorted by Unicode code point,
        separators are compact and non-ASCII characters are preserved
        unescaped. An empty rule set exports as ``[]`` and repeated calls
        on an unchanged instance return byte-identical text.

        The text round-trips through :meth:`from_json` with identical
        decide/explain/decide_many/audit behavior; neither the rules nor
        any caller-provided mapping is modified or aliased. A rule value
        that cannot be represented losslessly in strict JSON (tuples,
        sets, non-finite numbers, mappings with non-string keys, ...)
        raises ``ValueError`` tagged ``non_json_value`` before any text
        is produced. Performs no file, network or other external I/O.
        """
        snapshot = self._snapshot()
        return json.dumps(
            snapshot,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )

    def fingerprint(self):
        """SHA-256 of the canonical snapshot as UTF-8 bytes.

        Returns the lowercase hexadecimal digest, always 64 characters,
        computed over exactly the text :meth:`to_json` produces. A
        snapshot that cannot be encoded as strict JSON raises the same
        ``ValueError`` tagged ``non_json_value`` as ``to_json``.
        Performs no I/O.
        """
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

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
    def _validate_batch_item(item, index):
        # Within one item, error classes are checked unknown-field first,
        # then missing-field, then field-type; ties resolve in the fixed
        # subject/action/resource/tags order.
        unknown = [k for k in item if k not in _REQUEST_FIELDS]
        if unknown:
            raise PolicyBatchError("unknown_field", index, field=unknown[0])

        for field in _STRING_FIELDS:
            if field not in item:
                raise PolicyBatchError("missing_field", index, field=field)

        for field in _STRING_FIELDS:
            if not isinstance(item[field], str):
                raise PolicyBatchError("invalid_field_type", index, field=field)

        if "tags" in item:
            tags = item["tags"]
            if tags is not None and not isinstance(tags, Mapping):
                raise PolicyBatchError(
                    "invalid_field_type", index, field="tags"
                )

    def decide_many(self, requests):
        """Evaluate many requests in one offline, reviewable batch.

        ``requests`` must be a list or tuple of mappings, each limited to
        the keys ``subject``, ``action``, ``resource`` and ``tags``. The
        first three are required strings; ``tags`` may be omitted, be
        ``None`` or be any mapping accepted by :meth:`decide`.

        Returns ``{"decisions": [...], "summary": {"total", "allow",
        "deny"}}`` with decisions in input order, each identical to what a
        plain :meth:`decide` call would return. An empty batch yields an
        empty decision list and an all-zero summary.

        The whole batch is validated before any decision is computed, so a
        malformed batch raises :class:`PolicyBatchError` and never produces
        partial results. Rules and caller data are never modified.
        """
        if not isinstance(requests, (list, tuple)):
            raise PolicyBatchError("invalid_batch", None)

        for index, item in enumerate(requests):
            if not isinstance(item, Mapping):
                raise PolicyBatchError("item_not_mapping", index)
            self._validate_batch_item(item, index)

        decisions = [
            self.decide(
                item["subject"],
                item["action"],
                item["resource"],
                item.get("tags"),
            )
            for item in requests
        ]
        summary = {
            "total": len(decisions),
            "allow": sum(1 for d in decisions if d["effect"] == "allow"),
            "deny": sum(1 for d in decisions if d["effect"] == "deny"),
        }
        return {"decisions": decisions, "summary": summary}

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

    def audit(self):
        """Offline pre-release review of the loaded rules.

        Takes no request, performs no I/O and never modifies the rule
        list; it only analyzes the rules that loaded successfully, so
        decide()/explain()/decide_many() results are unaffected.

        Every pair of rules is checked in declaration order. Two
        selectors overlap when some subject/action/resource string
        matches both glob patterns under fnmatch.fnmatchcase semantics
        and their tag constraints are jointly satisfiable (only a shared
        tag key with different values conflicts; extra caller tags do not
        matter). Overlapping selectors with different effects yield one
        ``effect_overlap`` error finding whose winner is the deny rule —
        explicit deny overrides allow, and priority cannot change that.
        Selectors with identical pattern texts and tags yield one
        ``shadowed_rule`` finding instead: an error when deny shadows
        allow, a warning when same-effect rules collide (the loser by
        priority, then declaration order, is shadowed). Same-effect
        partial overlaps are not conflicts and produce no finding.

        Returns ``{"findings": [...], "summary": {"total", "error",
        "warning"}}``. Each finding has the fixed keys ``code``,
        ``severity``, ``rule``, ``other_rule``, ``winner``, ``shadowed``
        and ``reason``; ``rule``/``other_rule`` are the earlier/later
        declared rule ids and ``shadowed`` is None when no rule is fully
        shadowed. Findings are stably ordered by declaration position
        with at most one finding per pair. With no overlapping selectors
        the report is empty and every summary count is 0.
        """
        compiled = [
            (
                _tokenize_pattern(r["subject"]),
                _tokenize_pattern(r["action"]),
                _tokenize_pattern(r["resource"]),
            )
            for r in self.rules
        ]
        findings = []
        for earlier in range(len(self.rules)):
            for later in range(earlier + 1, len(self.rules)):
                finding = _audit_pair(
                    self.rules[earlier],
                    self.rules[later],
                    compiled[earlier],
                    compiled[later],
                )
                if finding is not None:
                    findings.append(finding)
        summary = {
            "total": len(findings),
            "error": sum(1 for f in findings if f["severity"] == "error"),
            "warning": sum(1 for f in findings if f["severity"] == "warning"),
        }
        return {"findings": findings, "summary": summary}
