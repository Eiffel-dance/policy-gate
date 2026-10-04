import copy
import fnmatch
import hashlib
import json
import math
from collections.abc import Mapping

_ALLOWED_FIELDS = frozenset(
    {
        "id",
        "effect",
        "priority",
        "subject",
        "action",
        "resource",
        "tags",
        "tag_patterns",
        "tag_exclude_patterns",
    }
)
_STRING_FIELDS = ("subject", "action", "resource")
_REQUEST_FIELDS = frozenset({"subject", "action", "resource", "tags"})
_CASE_FIELDS = frozenset(
    {"subject", "action", "resource", "tags", "expected"}
)
_EXPECTATION_FIELDS = frozenset({"effect", "rule"})
_REQUIRED_CASE_FIELDS = ("subject", "action", "resource", "expected")


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


class PolicyVerificationError(Exception):
    """A batch handed to :meth:`PolicyGate.verify` failed validation.

    The machine-readable ``code`` attribute is one of ``invalid_cases``,
    ``item_not_mapping``, ``unknown_field``, ``missing_field``,
    ``invalid_field_type`` or ``invalid_expectation``. ``index`` is the
    offending element index, or ``None`` when the outer batch value itself
    is not a list or tuple. ``field`` names the offending field for the
    field-level codes (nested expectation fields are written
    ``expected.effect`` / ``expected.rule``) and is ``None`` otherwise.
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
        if code == "invalid_cases":
            return "cases must be a list or tuple of case mappings"
        if code == "item_not_mapping":
            return "case at index %s must be a mapping" % index
        if code == "unknown_field":
            return "case at index %d contains unknown field %r" % (index, field)
        if code == "missing_field":
            return "case at index %d is missing required field %r" % (index, field)
        if code == "invalid_field_type":
            return "case at index %d field %r has an invalid type" % (index, field)
        if code == "invalid_expectation":
            return "case at index %d field %r has an invalid value" % (index, field)
        return "case validation failed"


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


def _json_snapshot_error(kind):
    return ValueError("[non_json_value] rule snapshot contains %s" % kind)


class _FixedObject:
    """A JSON object whose keys must appear in a fixed order."""

    __slots__ = ("pairs",)

    def __init__(self, pairs):
        self.pairs = pairs


def _canonical_json(value):
    """Serialize normalized rule data to canonical strict-JSON text.

    Serialization is canonical: ``_FixedObject`` keeps its declared key
    order (used for rule-level fields), while plain mappings emit their
    string keys in Unicode code-point order at every nesting level.

    Values are restricted to strict JSON types: tuples and sets are
    rejected even though Python treats them as containers, non-finite
    numbers are rejected (strict JSON has no NaN/Infinity), and lone
    surrogates are rejected because the resulting text could not be
    encoded as UTF-8 for fingerprinting. Raises ValueError tagged
    ``non_json_value`` and never returns partially built text.
    """
    if value is None or isinstance(value, bool):
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, str):
        if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
            raise _json_snapshot_error("a string with a lone surrogate")
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _json_snapshot_error("a non-finite number")
        return json.dumps(value, separators=(",", ":"), allow_nan=False)
    if isinstance(value, _FixedObject):
        return "{" + ",".join(
            _canonical_json(key) + ":" + _canonical_json(val)
            for key, val in value.pairs
        ) + "}"
    if isinstance(value, Mapping):
        keys = list(value.keys())
        for key in keys:
            if not isinstance(key, str):
                raise _json_snapshot_error("a mapping with a non-string key")
        parts = []
        for key in sorted(keys):
            parts.append(_canonical_json(key) + ":" + _canonical_json(value[key]))
        return "{" + ",".join(parts) + "}"
    if isinstance(value, (list, tuple, set, frozenset)):
        if isinstance(value, (tuple, set, frozenset)):
            raise _json_snapshot_error(
                "a %s, which has no JSON representation"
                % type(value).__name__
            )
        return "[" + ",".join(_canonical_json(v) for v in value) + "]"
    raise _json_snapshot_error(
        "a value of type %s, which has no JSON representation"
        % type(value).__name__
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


def _token_min_char(token):
    """Smallest single character (by Unicode code point) a char token matches."""
    return chr(_positive_ranges(token)[0][0])


def _intersection_min_char(t1, t2):
    """Smallest character matched by both char tokens, or None if disjoint."""
    r1 = _positive_ranges(t1)
    r2 = _positive_ranges(t2)
    i = j = 0
    found = None
    while i < len(r1) and j < len(r2):
        lo = max(r1[i][0], r2[j][0])
        hi = min(r1[i][1], r2[j][1])
        if lo <= hi and (found is None or lo < found):
            found = lo
        if r1[i][1] < r2[j][1]:
            i += 1
        else:
            j += 1
    return chr(found) if found is not None else None


def _min_common_string(t1, t2):
    """Shortest string matching both tokenized patterns; ties broken by
    Unicode code-point lexicographic order.

    Mirrors :func:`_patterns_overlap` over the same token grid, but each
    reachable state stores the minimum witness suffix as a ``(length,
    text)`` pair (compared by length first, then text) instead of a mere
    boolean: a `*` may match the empty string, skip itself, or absorb one
    character demanded by a char token on the other side. A star/star
    alignment never needs to emit a character. Returns None only when the
    two patterns have no common string, which cannot happen for a pair
    whose overlap has already been established.
    """
    n1, n2 = len(t1), len(t2)
    best = [[None] * (n2 + 1) for _ in range(n1 + 1)]
    best[n1][n2] = (0, "")
    for j in range(n2 - 1, -1, -1):
        if t2[j][0] == "star":
            best[n1][j] = best[n1][j + 1]
    for i in range(n1 - 1, -1, -1):
        if t1[i][0] == "star":
            best[i][n2] = best[i + 1][n2]

    for i in range(n1 - 1, -1, -1):
        a = t1[i]
        a_star = a[0] == "star"
        for j in range(n2 - 1, -1, -1):
            b = t2[j]
            candidates = []
            if a_star:
                candidates.append(best[i + 1][j])  # a's '*' matches empty
                if b[0] == "star":
                    candidates.append(best[i][j + 1])
                elif _class_satisfiable(b):
                    tail = best[i][j + 1]  # a's '*' absorbs b's char
                    if tail is not None:
                        candidates.append(
                            (tail[0] + 1, _token_min_char(b) + tail[1])
                        )
            elif b[0] == "star":
                candidates.append(best[i][j + 1])  # b's '*' matches empty
                if _class_satisfiable(a):
                    tail = best[i + 1][j]  # b's '*' absorbs a's char
                    if tail is not None:
                        candidates.append(
                            (tail[0] + 1, _token_min_char(a) + tail[1])
                        )
            else:
                ch = _intersection_min_char(a, b)
                tail = best[i + 1][j + 1]
                if ch is not None and tail is not None:
                    candidates.append((tail[0] + 1, ch + tail[1]))
            candidates = [c for c in candidates if c is not None]
            best[i][j] = min(candidates) if candidates else None

    result = best[0][0]
    return None if result is None else result[1]


def _pattern_satisfiable(tokens):
    """True iff the tokenized pattern matches at least one string."""
    return all(
        token[0] == "star" or _class_satisfiable(token) for token in tokens
    )


def _min_pattern_string(tokens):
    """Shortest string matching one tokenized pattern; ties (impossible
    here, each position is forced) would break by Unicode code point.

    Every ``char`` token must consume exactly one character, so the
    shortest match takes the smallest code point each token accepts and
    every ``*`` matches empty. Returns None when the pattern matches no
    string at all (an empty character class).
    """
    chars = []
    for token in tokens:
        if token[0] == "char":
            positive = _positive_ranges(token)
            if not positive:
                return None
            chars.append(chr(positive[0][0]))
    return "".join(chars)


def _value_matches_pattern(value, pattern):
    # A pattern constraint only matches string tag values; anything else
    # (including a missing key, surfaced as a non-string here) fails.
    return isinstance(value, str) and fnmatch.fnmatchcase(value, pattern)


# --- joint witness solving with positive and excluded patterns ----------
#
# A tag key can carry up to two positive glob constraints (one per rule,
# tokenized like the subject/action/resource patterns) and up to two
# excluded ones: a witness value must match every positive pattern and no
# excluded one. Each glob is run as an NFA over its token grid (a char
# token consumes exactly one character, a star consumes zero or more);
# positive patterns are driven as joint subset automata, while excluded
# patterns run alongside and may only be non-matching once the full string
# is built. BFS by string length, choosing the smallest code point that
# keeps every automaton alive, yields the shortest witness, ties broken by
# Unicode code-point lexicographic order.

_UNIVERSAL_TOKENS = (_STAR,)
_MAX_CODEPOINT = 0x10FFFF


def _automaton_closure(states, tokens):
    """Epsilon closure: walk star tokens matching the empty string."""
    end = len(tokens)
    states = set(states)
    stack = list(states)
    while stack:
        i = stack.pop()
        if i < end and tokens[i][0] == "star" and i + 1 not in states:
            states.add(i + 1)
            stack.append(i + 1)
    return frozenset(states)


def _codepoint_matches_token(token, codepoint):
    for lo, hi in _positive_ranges(token):
        if lo <= codepoint <= hi:
            return True
    return False


def _automaton_step(states, tokens, codepoint):
    """Subset-NFA transition for one consumed character."""
    end = len(tokens)
    moved = set()
    for i in states:
        if i >= end:
            continue
        token = tokens[i]
        if token[0] == "star":
            moved.add(i)  # the star keeps consuming
            moved.add(i + 1)  # the star absorbs this character
        elif _codepoint_matches_token(token, codepoint):
            moved.add(i + 1)
    return _automaton_closure(moved, tokens)


def _automaton_permanently_matched(states, tokens):
    """True iff a prefix already matched and every suffix still matches.

    Reaching the end is not enough: glob patterns match whole strings, so
    a prefix match of ``a`` is undone by a second character. Only an
    accepting subset with an open run of trailing stars (the tokenizer
    collapses repeated stars, in practice just a trailing star) absorbs
    every possible continuation and is matched for good.
    """
    end = len(tokens)
    for i in states:
        if (
            i < end
            and tokens[i][0] == "star"
            and all(tokens[j][0] == "star" for j in range(i, end))
        ):
            return True
    return False


def _constraints_min_string(positive_tokens, avoid_tokens):
    """Shortest string matching every positive pattern and no avoided one.

    Returns None when no such string exists. With no positive constraint
    the target is the universal language (``*``), so the empty string is
    considered first. Character candidates are restricted to one
    representative per equivalence class induced by the char-token ranges
    live in the current frontier: two code points in one elementary range
    interval take identical transitions in every automaton, so only the
    smallest code point of each class can be optimal.
    """
    automata = list(positive_tokens) if positive_tokens else [_UNIVERSAL_TOKENS]
    n_positive = len(automata)
    ends = [len(tokens) for tokens in automata] + [
        len(tokens) for tokens in avoid_tokens
    ]

    def step_state(state, codepoint):
        next_state = []
        for k, subset in enumerate(state):
            tokens = (
                automata[k]
                if k < n_positive
                else avoid_tokens[k - n_positive]
            )
            moved = _automaton_step(subset, tokens, codepoint)
            if k < n_positive and not moved:
                return None
            if k >= n_positive and _automaton_permanently_matched(
                moved, tokens
            ):
                return None
            next_state.append(moved)
        return tuple(next_state)

    start = tuple(
        _automaton_closure(frozenset({0}), tokens)
        for tokens in automata + list(avoid_tokens)
    )
    if any(
        _automaton_permanently_matched(start[n_positive + k], tokens)
        for k, tokens in enumerate(avoid_tokens)
    ):
        return None

    best = {start: ""}
    frontier = [start]
    while frontier:
        goals = [
            state
            for state in frontier
            if all(ends[k] in state[k] for k in range(n_positive))
            and all(
                ends[n_positive + k] not in state[n_positive + k]
                for k in range(len(avoid_tokens))
            )
        ]
        if goals:
            return min(best[state] for state in goals)

        boundaries = {0, _MAX_CODEPOINT + 1}
        for state in frontier:
            for k, subset in enumerate(state):
                tokens = (
                    automata[k]
                    if k < n_positive
                    else avoid_tokens[k - n_positive]
                )
                for i in subset:
                    if i < len(tokens) and tokens[i][0] == "char":
                        for lo, hi in _positive_ranges(tokens[i]):
                            boundaries.add(lo)
                            boundaries.add(min(hi + 1, _MAX_CODEPOINT + 1))
        cuts = sorted(boundaries)

        incoming = {}
        for codepoint in cuts[:-1]:
            for state in frontier:
                moved = step_state(state, codepoint)
                if moved is None or moved in best:
                    continue
                text = best[state] + chr(codepoint)
                if moved not in incoming or text < incoming[moved][0]:
                    incoming[moved] = (text, state)
        frontier = []
        for state, (text, _prev) in incoming.items():
            best[state] = text
            frontier.append(state)
    return None


def _tag_witness_assignment(r1, r2, c1, c2):
    """Joint tag assignment satisfying both rules' positive and excluded
    tag constraints, or None when none exists.

    Only keys declared by one of the two rules appear, emitted in Unicode
    code-point order. An exact value pins the witness (deep-copied, since
    direct construction permits non-string or mutable tag values) and must
    match the other side's positive pattern and avoid both sides' excluded
    patterns. A key without an exact value keeps its legacy witness when
    neither rule excludes it (shortest single/intersection string), and
    otherwise goes through the subset-NFA solver.
    """
    tags1, tags2 = r1["tags"], r2["tags"]
    pos1, pos2 = c1[3], c2[3]
    exc1, exc2 = c1[4], c2[4]
    keys = (
        set(tags1)
        | set(tags2)
        | set(pos1)
        | set(pos2)
        | set(exc1)
        | set(exc2)
    )
    assignment = {}
    for key in sorted(keys):
        exact = None
        have_exact = False
        if key in tags1:
            have_exact = True
            exact = tags1[key]
        if key in tags2:
            if have_exact and tags2[key] != exact:
                return None
            have_exact = True
            exact = tags2[key]

        positive_tokens = []
        positive_patterns = []
        for rule, compiled in ((r1, pos1), (r2, pos2)):
            if key in compiled and key not in rule["tags"]:
                positive_tokens.append(compiled[key])
                positive_patterns.append(rule["tag_patterns"][key])

        exclude_tokens = []
        exclude_patterns = []
        for rule, compiled in ((r1, exc1), (r2, exc2)):
            if key in compiled and key not in rule["tags"]:
                exclude_tokens.append(compiled[key])
                exclude_patterns.append(rule["tag_exclude_patterns"][key])

        if have_exact:
            for pattern in positive_patterns:
                if not _value_matches_pattern(exact, pattern):
                    return None
            for pattern in exclude_patterns:
                if _value_matches_pattern(exact, pattern):
                    return None
            assignment[key] = copy.deepcopy(exact)
            continue

        for tokens in positive_tokens:
            if not _pattern_satisfiable(tokens):
                return None

        if not exclude_tokens:
            if len(positive_tokens) == 1:
                value = _min_pattern_string(positive_tokens[0])
            else:
                value = _min_common_string(
                    positive_tokens[0], positive_tokens[1]
                )
            if value is None:
                return None
        else:
            value = _constraints_min_string(positive_tokens, exclude_tokens)
            if value is None:
                return None
        assignment[key] = value
    return assignment



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


def _audit_pair(r1, r2, c1, c2):
    """Build the finding for one rule pair, or None when there is none."""
    if not (
        _patterns_overlap(c1[0], c2[0])
        and _patterns_overlap(c1[1], c2[1])
        and _patterns_overlap(c1[2], c2[2])
    ):
        return None

    # The tag assignment doubles as the overlap test: there is a finding
    # only when tag values can meet both rules' positive constraints and
    # avoid both rules' excluded patterns at once.
    witness_tags = _tag_witness_assignment(r1, r2, c1, c2)
    if witness_tags is None:
        return None

    identical = (
        r1["subject"] == r2["subject"]
        and r1["action"] == r2["action"]
        and r1["resource"] == r2["resource"]
        and r1["tags"] == r2["tags"]
        and r1["tag_patterns"] == r2["tag_patterns"]
        and r1["tag_exclude_patterns"] == r2["tag_exclude_patterns"]
    )
    witness = {
        "subject": _min_common_string(c1[0], c2[0]),
        "action": _min_common_string(c1[1], c2[1]),
        "resource": _min_common_string(c1[2], c2[2]),
        "tags": witness_tags,
    }
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
            "witness": witness,
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
            "witness": witness,
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

            tag_patterns = r.get("tag_patterns", {})
            if (
                not isinstance(tag_patterns, dict)
                or not all(isinstance(k, str) for k in tag_patterns)
                or not all(isinstance(v, str) for v in tag_patterns.values())
            ):
                raise ValueError(
                    "invalid_tag_patterns: rule %d: field 'tag_patterns' "
                    "must be a mapping with string keys and string pattern "
                    "values" % i
                )

            shared_tag_keys = sorted(set(tags) & set(tag_patterns))
            if shared_tag_keys:
                raise ValueError(
                    "tag_constraint_conflict: rule %d: key %r appears in "
                    "both 'tags' and 'tag_patterns'" % (i, shared_tag_keys[0])
                )

            tag_exclude_patterns = r.get("tag_exclude_patterns", {})
            if (
                not isinstance(tag_exclude_patterns, dict)
                or not all(isinstance(k, str) for k in tag_exclude_patterns)
                or not all(
                    isinstance(v, str) for v in tag_exclude_patterns.values()
                )
            ):
                raise ValueError(
                    "invalid_tag_exclude_patterns: rule %d: field "
                    "'tag_exclude_patterns' must be a mapping with string "
                    "keys and string pattern values" % i
                )

            exclude_conflicts = sorted(
                set(tag_exclude_patterns) & (set(tags) | set(tag_patterns))
            )
            if exclude_conflicts:
                other = (
                    "'tags'"
                    if exclude_conflicts[0] in tags
                    else "'tag_patterns'"
                )
                raise ValueError(
                    "tag_constraint_conflict: rule %d: key %r appears in "
                    "both 'tag_exclude_patterns' and %s"
                    % (i, exclude_conflicts[0], other)
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
                    "tag_patterns": tag_patterns,
                    "tag_exclude_patterns": tag_exclude_patterns,
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

    # --- canonical snapshot export ------------------------------------

    _SNAPSHOT_FIELDS = (
        "id",
        "effect",
        "priority",
        "subject",
        "action",
        "resource",
        "tags",
    )

    def _snapshot(self):
        """Normalized rules ready for canonical JSON serialization.

        Only the effective fields are copied, in fixed order, so the
        internal ``_index`` never leaks; the copy is shallow, and only read
        by the serializer, so neither the rules nor caller-provided
        mappings are mutated. ``tag_patterns`` is appended right after
        ``tags`` only when non-empty, and ``tag_exclude_patterns`` occupies
        the next fixed slot, likewise only when non-empty, so rules that
        never use either mapping keep their legacy byte-level snapshot.
        """
        snapshot = []
        for rule in self.rules:
            pairs = [(field, rule[field]) for field in self._SNAPSHOT_FIELDS]
            if rule["tag_patterns"]:
                pairs.append(("tag_patterns", rule["tag_patterns"]))
            if rule["tag_exclude_patterns"]:
                pairs.append(
                    ("tag_exclude_patterns", rule["tag_exclude_patterns"])
                )
            snapshot.append(_FixedObject(pairs))
        return snapshot

    def to_json(self):
        """Export the loaded rules as canonical strict-JSON text.

        The root value is an array preserving declaration order. Every
        rule writes its normalized, actually-effective ``id``, ``effect``,
        ``priority``, ``subject``, ``action``, ``resource`` and ``tags``
        in that fixed order, so all defaults appear explicitly and no
        internal index leaks; a rule with a non-empty ``tag_patterns``
        mapping writes it in the same fixed order immediately after
        ``tags``, and a non-empty ``tag_exclude_patterns`` mapping in the
        next fixed slot, while rules without pattern constraints export
        exactly the same bytes as before. Tag objects (at every nesting
        level) have their keys sorted by Unicode code point; separators are
        compact and non-ASCII characters are emitted unescaped. An empty
        rule set exports as ``[]`` and repeated calls return identical
        text while the rules are unchanged.

        The result reloads losslessly through :meth:`from_json` with
        identical decide/explain/decide_many/audit behavior. A value that
        cannot be represented losslessly in strict JSON (a tuple, set,
        non-finite number, nested mapping with non-string keys, or a
        string that cannot be UTF-8 encoded) raises ``ValueError`` whose
        message carries the fixed tag ``non_json_value``; no partial text
        is returned. Performs no I/O.
        """
        return _canonical_json(self._snapshot())

    def fingerprint(self):
        """SHA-256 hex digest of the canonical snapshot's UTF-8 bytes.

        Uses exactly the same snapshot as :meth:`to_json`, so digest and
        text always agree; the result is a 64-character lowercase hex
        string. A snapshot that cannot be serialized or UTF-8 encoded
        raises the same ``ValueError`` tagged ``non_json_value``.
        Performs no I/O.
        """
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    @staticmethod
    def _tags_match(rule, tags):
        # Exact constraints compare values for equality; pattern
        # constraints apply fnmatch.fnmatchcase to the request's tag
        # value, so a missing key or a non-string value simply means the
        # rule does not match. Exclude patterns are the inverse: they pass
        # for a missing key or a non-string value, and only a string value
        # that actually matches the excluded pattern makes the rule fail.
        if not all(tags.get(k) == v for k, v in rule["tags"].items()):
            return False
        if not all(
            _value_matches_pattern(tags.get(k), pattern)
            for k, pattern in rule["tag_patterns"].items()
        ):
            return False
        return all(
            not _value_matches_pattern(tags.get(k), pattern)
            for k, pattern in rule["tag_exclude_patterns"].items()
        )

    @staticmethod
    def _matches(rule, subject, action, resource, tags):
        return (
            fnmatch.fnmatchcase(subject, rule["subject"])
            and fnmatch.fnmatchcase(action, rule["action"])
            and fnmatch.fnmatchcase(resource, rule["resource"])
            and PolicyGate._tags_match(rule, tags)
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

    @staticmethod
    def _select(matched):
        """Pick the winning rule out of the matched ones.

        Explicit deny always wins; within one effect, higher priority wins,
        then the earliest declaration order breaks ties deterministically.
        Returns (decision, winner rule or None).
        """
        denies = [r for r in matched if r["effect"] == "deny"]
        allows = [r for r in matched if r["effect"] == "allow"]

        winners = denies if denies else allows
        if not winners:
            return (
                {"effect": "deny", "rule": None, "reason": "default deny"},
                None,
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
            winner,
        )

    def _evaluate(self, subject, action, resource, tags):
        """Shared decision core; returns (decision, matched rules in order)."""
        tags = self._check_inputs(subject, action, resource, tags)

        matched = [
            r
            for r in self.rules
            if self._matches(r, subject, action, resource, tags)
        ]
        decision, _winner = self._select(matched)
        return decision, matched

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

    @staticmethod
    def _validate_requests(requests):
        # Shared by decide_many(), compare() and coverage(): the whole
        # batch is checked before any decision is computed, so a malformed
        # batch never produces partial results.
        if not isinstance(requests, (list, tuple)):
            raise PolicyBatchError("invalid_batch", None)

        for index, item in enumerate(requests):
            if not isinstance(item, Mapping):
                raise PolicyBatchError("item_not_mapping", index)
            PolicyGate._validate_batch_item(item, index)

    @staticmethod
    def _validate_case_item(item, index):
        # Error classes are checked in the fixed precedence unknown-field,
        # missing-field, field-type, invalid-expectation value; nested
        # expectation fields take part in the same phases under dotted
        # names. A non-mapping expected cannot be inspected field by field,
        # so it skips the nested checks and surfaces in the type phase.
        unknown = [k for k in item if k not in _CASE_FIELDS]
        if unknown:
            raise PolicyVerificationError(
                "unknown_field", index, field=unknown[0]
            )

        expected = item.get("expected")
        expected_mapping = isinstance(expected, Mapping)
        if expected_mapping:
            nested_unknown = [
                k for k in expected if k not in _EXPECTATION_FIELDS
            ]
            if nested_unknown:
                raise PolicyVerificationError(
                    "unknown_field",
                    index,
                    field="expected." + nested_unknown[0],
                )

        for field in _REQUIRED_CASE_FIELDS:
            if field not in item:
                raise PolicyVerificationError(
                    "missing_field", index, field=field
                )

        if expected_mapping:
            for field in ("effect", "rule"):
                if field not in expected:
                    raise PolicyVerificationError(
                        "missing_field",
                        index,
                        field="expected." + field,
                    )

        for field in _STRING_FIELDS:
            if not isinstance(item[field], str):
                raise PolicyVerificationError(
                    "invalid_field_type", index, field=field
                )

        tags = item.get("tags")
        if tags is not None and not isinstance(tags, Mapping):
            raise PolicyVerificationError(
                "invalid_field_type", index, field="tags"
            )

        if not expected_mapping:
            raise PolicyVerificationError(
                "invalid_field_type", index, field="expected"
            )

        if expected["effect"] not in ("allow", "deny"):
            raise PolicyVerificationError(
                "invalid_expectation", index, field="expected.effect"
            )

        rule = expected["rule"]
        if rule is not None and not isinstance(rule, str):
            raise PolicyVerificationError(
                "invalid_expectation", index, field="expected.rule"
            )

    @staticmethod
    def _validate_cases(cases):
        # Whole-batch-first validation for verify(): every case is checked
        # before any decision is computed, so a malformed batch never
        # produces partial results.
        if not isinstance(cases, (list, tuple)):
            raise PolicyVerificationError("invalid_cases", None)

        for index, item in enumerate(cases):
            if not isinstance(item, Mapping):
                raise PolicyVerificationError("item_not_mapping", index)
            PolicyGate._validate_case_item(item, index)

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
        self._validate_requests(requests)

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

    def verify(self, cases):
        """Check fixed cases against the rules before a release.

        ``cases`` must be a list or tuple of mappings, each limited to the
        keys ``subject``, ``action``, ``resource``, ``tags`` and
        ``expected``. The first three are required strings with the same
        meaning as in :meth:`decide`; ``tags`` may be omitted, be ``None``
        or be any mapping accepted by :meth:`decide`. ``expected`` is
        required and must be a mapping holding exactly ``effect``
        (``"allow"`` or ``"deny"``) and ``rule`` (a string or ``None``;
        the default deny is written as ``{"effect": "deny", "rule": None}``).

        The whole batch is validated before any decision is computed, so a
        malformed batch raises :class:`PolicyVerificationError` and never
        produces partial results. Its ``code``/``index``/``field`` follow
        the error-class order: ``invalid_cases`` for a non-list/tuple
        batch, ``item_not_mapping`` for a non-mapping element,
        ``unknown_field`` / ``missing_field`` / ``invalid_field_type`` for
        case fields (nested expectation fields are reported as
        ``expected.effect`` / ``expected.rule``), and
        ``invalid_expectation`` for an illegal ``expected`` value.

        After validation, cases are evaluated in input order using the
        existing :meth:`decide` semantics (glob matching, exact and
        pattern tag constraints, explicit deny, priority, declaration
        order and
        default deny). A case passes only when both ``effect`` and
        ``rule`` equal the actual decision; ``reason`` never participates.

        Returns ``{"ok", "failures", "summary"}`` — namely the fixed keys
        ``ok``, ``failures`` and ``summary`` — where ``summary`` holds
        ``total``, ``passed`` and ``failed``. Each failure is listed in
        input order as ``{"index", "expected", "actual"}`` with ``actual``
        the complete :meth:`decide` result; ``ok`` is true exactly when
        ``failed`` is zero. An empty batch yields an empty failure list,
        an all-zero summary and ``ok`` true. Returned mappings are
        independent copies, so mutating a report never affects later
        calls. Verification is read-only and offline: rules and inputs
        are never modified, no I/O happens, and gates built directly and
        via :meth:`from_json` verify identically.
        """
        self._validate_cases(cases)

        failures = []
        passed = 0
        for index, item in enumerate(cases):
            actual = self.decide(
                item["subject"],
                item["action"],
                item["resource"],
                item.get("tags"),
            )
            expected = item["expected"]
            if (
                actual["effect"] == expected["effect"]
                and actual["rule"] == expected["rule"]
            ):
                passed += 1
            else:
                failures.append(
                    {
                        "index": index,
                        "expected": copy.deepcopy(expected),
                        "actual": copy.deepcopy(actual),
                    }
                )

        total = len(cases)
        return {
            "ok": passed == total,
            "failures": failures,
            "summary": {"total": total, "passed": passed,
                        "failed": total - passed},
        }

    def coverage(self, requests):
        """Measure how the loaded rules participate in deciding a batch.

        ``requests`` uses the same list/tuple of request mappings as
        :meth:`decide_many` and is validated exactly the same way: the
        whole batch is checked first, and a malformed batch raises
        :class:`PolicyBatchError` with ``code``/``index``/``field``
        instead of producing a partial report.

        Returns ``{"rules": [...], "summary": {...}}``. ``rules`` lists
        every loaded rule in declaration order as ``{"id", "effect",
        "matched", "winner"}``: ``matched`` counts the requests whose
        subject/action/resource matched the rule's glob patterns under
        ``fnmatch.fnmatchcase`` semantics together with its exact and
        pattern tag constraints, and ``winner`` counts the requests the
        rule
        actually decided after explicit-deny precedence, priority and
        declaration-order tie-breaking. A request matching several rules
        raises every matched rule's ``matched`` but only the final
        rule's ``winner``; a request falling through to the default deny
        raises no rule's ``winner``.

        ``summary`` has the fixed keys ``total``, ``allow``,
        ``explicit_deny``, ``default_deny`` and ``matched_request``:
        ``allow`` counts requests whose final effect is allow,
        ``explicit_deny`` counts requests won by a deny rule,
        ``default_deny`` counts requests that matched no rule at all,
        and ``matched_request`` counts requests matching at least one
        rule. An empty batch yields all-zero counts; with an empty rule
        set every request lands in ``default_deny``.

        The report is read-only and offline: rules and caller mappings
        are never modified, no I/O happens, and repeated calls over the
        same batch return equal results.
        """
        self._validate_requests(requests)

        matched_counts = [0] * len(self.rules)
        winner_counts = [0] * len(self.rules)
        index_by_id = {r["id"]: r["_index"] for r in self.rules}
        allow = explicit_deny = default_deny = matched_request = 0

        for item in requests:
            decision, matched = self._evaluate(
                item["subject"],
                item["action"],
                item["resource"],
                item.get("tags"),
            )
            for rule in matched:
                matched_counts[rule["_index"]] += 1
            if matched:
                matched_request += 1
            if decision["rule"] is None:
                default_deny += 1
            else:
                winner_counts[index_by_id[decision["rule"]]] += 1
                if decision["effect"] == "allow":
                    allow += 1
                else:
                    explicit_deny += 1

        rules = [
            {
                "id": rule["id"],
                "effect": rule["effect"],
                "matched": matched_counts[rule["_index"]],
                "winner": winner_counts[rule["_index"]],
            }
            for rule in self.rules
        ]
        summary = {
            "total": len(requests),
            "allow": allow,
            "explicit_deny": explicit_deny,
            "default_deny": default_deny,
            "matched_request": matched_request,
        }
        return {"rules": rules, "summary": summary}

    def compare(self, candidate, requests):
        """Compare this gate (the baseline) against ``candidate`` on one batch.

        The two gates each apply their own glob matching, explicit-deny,
        priority, declaration-order and default-deny rules to the same
        requests; the point of the comparison is to locate exactly what a
        candidate policy change alters.

        ``candidate`` must be a :class:`PolicyGate`, otherwise ``TypeError``
        is raised. ``requests`` uses the same list/tuple of request
        mappings as :meth:`decide_many` and is validated exactly the same
        way (:class:`PolicyBatchError` with ``code``/``index``/``field``;
        the first error aborts the whole comparison with no partial
        results). Validation of ``candidate`` and the whole batch finishes
        before either gate evaluates anything. An empty batch returns an
        all-zero summary and no changes.

        Returns ``{"changes": [...], "summary": {"total", "unchanged",
        "changed", "allow_to_deny", "deny_to_allow", "winner_changed"}}``.
        ``total`` is the request count; each change is listed in input
        order as ``{"index", "before", "after", "kind"}``, where
        ``before``/``after`` are the full :meth:`decide` results of the
        baseline and the candidate. ``kind`` is ``allow_to_deny`` or
        ``deny_to_allow`` when the effect flips, and ``winner_changed``
        when the effect is the same but the winning rule or reason
        differs; identical results only count as ``unchanged``. The three
        change kinds are disjoint, so ``changed`` is always their sum.

        The comparison is read-only and offline: neither gate, request
        mapping nor tag mapping is modified, no I/O happens, and repeated
        calls return equal results.
        """
        if not isinstance(candidate, PolicyGate):
            raise TypeError("candidate must be a PolicyGate instance")
        self._validate_requests(requests)

        changes = []
        allow_to_deny = deny_to_allow = winner_changed = 0
        for index, item in enumerate(requests):
            before = self.decide(
                item["subject"],
                item["action"],
                item["resource"],
                item.get("tags"),
            )
            after = candidate.decide(
                item["subject"],
                item["action"],
                item["resource"],
                item.get("tags"),
            )
            if before == after:
                continue
            if before["effect"] != after["effect"]:
                if after["effect"] == "deny":
                    kind = "allow_to_deny"
                    allow_to_deny += 1
                else:
                    kind = "deny_to_allow"
                    deny_to_allow += 1
            else:
                kind = "winner_changed"
                winner_changed += 1
            changes.append(
                {"index": index, "before": before, "after": after, "kind": kind}
            )

        changed = allow_to_deny + deny_to_allow + winner_changed
        summary = {
            "total": len(requests),
            "unchanged": len(requests) - changed,
            "changed": changed,
            "allow_to_deny": allow_to_deny,
            "deny_to_allow": deny_to_allow,
            "winner_changed": winner_changed,
        }
        return {"changes": changes, "summary": summary}

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

    def trace(self, subject, action, resource, tags=None):
        """Per-rule decision trace of one request, for offline review.

        Shares decide()'s input validation and selection semantics: the
        root ``effect``, ``rule`` and ``reason`` are exactly what
        :meth:`decide` returns. Adds ``evaluations``, one entry per loaded
        rule in declaration order, each with the fixed key order ``id``,
        ``effect``, ``priority``, ``subject_match``, ``action_match``,
        ``resource_match``, ``tags_match``, ``matched``, ``selected``.
        The first three flags compare subject/action/resource against the
        rule's glob patterns with ``fnmatch.fnmatchcase``; ``tags_match``
        is the conjunction of the rule's exact tag constraints, its
        ``tag_patterns`` pattern constraints and its
        ``tag_exclude_patterns`` exclusions (``tags=None`` counts as an
        empty mapping; a missing key or non-string value fails a positive
        pattern constraint but passes an exclusion — only a string value
        matching an excluded pattern fails it). ``matched`` is the
        conjunction of the four flags; ``selected`` is true only on the
        final winning rule, and false everywhere when the request falls
        through to the default deny (``rule`` is then ``None``).

        Read-only and offline: the rule list and caller mappings are never
        modified and no I/O happens.
        """
        tags = self._check_inputs(subject, action, resource, tags)

        evaluations = []
        matched = []
        for r in self.rules:
            subject_match = fnmatch.fnmatchcase(subject, r["subject"])
            action_match = fnmatch.fnmatchcase(action, r["action"])
            resource_match = fnmatch.fnmatchcase(resource, r["resource"])
            tags_match = PolicyGate._tags_match(r, tags)
            rule_matched = (
                subject_match and action_match and resource_match and tags_match
            )
            if rule_matched:
                matched.append(r)
            evaluations.append(
                {
                    "id": r["id"],
                    "effect": r["effect"],
                    "priority": r["priority"],
                    "subject_match": subject_match,
                    "action_match": action_match,
                    "resource_match": resource_match,
                    "tags_match": tags_match,
                    "matched": rule_matched,
                    "selected": False,
                }
            )

        decision, winner = self._select(matched)
        if winner is not None:
            evaluations[winner["_index"]]["selected"] = True

        result = dict(decision)
        result["evaluations"] = evaluations
        return result

    def trace_many(self, requests):
        """Batch counterpart of :meth:`trace`.

        ``requests`` uses the same list/tuple of request mappings as
        :meth:`decide_many` and is validated exactly the same way: the
        whole batch is checked first, and the first malformed element
        raises :class:`PolicyBatchError` with its ``code``/``index``/
        ``field`` instead of producing partial results.

        Returns ``{"traces": [...], "summary": {"total", "allow",
        "deny"}}`` with one :meth:`trace` result per request in input
        order; the summary counts match :meth:`decide_many` and an empty
        batch yields all-zero counts. Read-only and offline: rules and
        caller mappings are never modified and no I/O happens.
        """
        self._validate_requests(requests)

        traces = [
            self.trace(
                item["subject"],
                item["action"],
                item["resource"],
                item.get("tags"),
            )
            for item in requests
        ]
        summary = {
            "total": len(traces),
            "allow": sum(1 for t in traces if t["effect"] == "allow"),
            "deny": sum(1 for t in traces if t["effect"] == "deny"),
        }
        return {"traces": traces, "summary": summary}

    def audit(self):
        """Offline pre-release review of the loaded rules.

        Takes no request, performs no I/O and never modifies the rule
        list; it only analyzes the rules that loaded successfully, so
        decide()/explain()/decide_many() results are unaffected.

        Every pair of rules is checked in declaration order. Two
        selectors overlap when some subject/action/resource string
        matches both glob patterns under fnmatch.fnmatchcase semantics
        and their tag constraints are jointly satisfiable: a shared tag
        key with different exact values conflicts; an exact value must
        match a shared key's ``tag_patterns`` pattern and avoid both
        rules' ``tag_exclude_patterns`` patterns on it; two positive
        patterns on a key need one common string that also avoids every
        excluded pattern; extra caller tags do not matter. A finding is
        reported only when tag values exist that meet both rules'
        positive constraints and avoid both rules' excluded patterns.
        Overlapping selectors with different effects yield one
        ``effect_overlap`` error finding whose winner is the deny rule —
        explicit deny overrides allow, and priority cannot change that.
        Selectors with identical pattern texts, tags, positive and
        excluded tag patterns yield one ``shadowed_rule`` finding
        instead: an error when deny shadows allow, a warning when
        same-effect rules collide (the loser by priority, then
        declaration order, is shadowed). Same-effect partial overlaps
        are not conflicts and produce no finding.

        A pair whose selectors cannot be jointly satisfied because an
        excluded pattern covers the shared positive language (for
        example both rules constrain ``env`` and one rule excludes
        ``*``) produces no finding at all, even for otherwise identical
        selectors: no witness can replay it.

        Returns ``{"findings": [...], "summary": {"total", "error",
        "warning"}}``. Each finding has the fixed keys ``code``,
        ``severity``, ``rule``, ``other_rule``, ``winner``, ``shadowed``,
        ``reason`` and ``witness``; ``rule``/``other_rule`` are the
        earlier/later declared rule ids and ``shadowed`` is None when no
        rule is fully shadowed. Findings are stably ordered by declaration
        position with at most one finding per pair. With no overlapping
        selectors the report is empty and every summary count is 0.

        ``witness`` is a concrete request that actually triggers the
        finding, with exactly the keys ``subject``, ``action``,
        ``resource`` and ``tags``: replaying it through decide() matches
        both rules of the pair under fnmatch.fnmatchcase semantics and the
        pair's exact and pattern tag constraints, so it reproduces the
        reported
        effect overlap or full shadowing. For each string field the
        witness is the shortest string matching both rules' patterns,
        ties broken by Unicode code-point lexicographic order (the empty
        string is allowed), and the three fields are chosen
        independently. ``tags`` merges both rules' constraints only:
        shared keys already carry equal (exact) or jointly satisfiable
        (pattern) values for a reported pair, all non-conflicting keys
        are retained, keys are emitted in Unicode code-point order, and
        no other request tag is invented. For a key without an exact
        value the witness is the shortest string that satisfies every
        positive pattern of the pair and matches none of the pair's
        ``tag_exclude_patterns`` on that key (ties broken by Unicode
        code-point lexicographic order); a key with an exact constraint
        keeps that exact value, which the feasibility check has already
        shown to avoid every excluded pattern. Rules
        built directly and via from_json produce identical witnesses,
        repeated calls return equal results, and mutating a returned
        report never affects later calls.
        """
        compiled = [
            (
                _tokenize_pattern(r["subject"]),
                _tokenize_pattern(r["action"]),
                _tokenize_pattern(r["resource"]),
                {
                    key: _tokenize_pattern(pattern)
                    for key, pattern in r["tag_patterns"].items()
                },
                {
                    key: _tokenize_pattern(pattern)
                    for key, pattern in r["tag_exclude_patterns"].items()
                },
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
