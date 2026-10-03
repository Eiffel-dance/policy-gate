import unittest

from app import (
    PolicyBatchError,
    PolicyConfigError,
    PolicyGate,
    PolicyVerificationError,
)


class BackwardCompatTest(unittest.TestCase):
    def test_default_deny_shape(self):
        gate = PolicyGate([])
        result = gate.decide("alice", "read", "data/x")
        self.assertEqual(result["effect"], "deny")
        self.assertIsNone(result["rule"])
        self.assertEqual(result["reason"], "default deny")

    def test_legacy_fnmatch_and_tags(self):
        gate = PolicyGate(
            [
                {"effect": "allow", "action": "read", "resource": "docs/*"},
                {"id": "tagged", "effect": "allow", "tags": {"env": "prod"}},
            ]
        )
        self.assertEqual(
            gate.decide("bob", "read", "docs/a", {"env": "dev"})["rule"], "0"
        )
        # tags are a key/value subset match; extra caller tags are fine
        self.assertEqual(
            gate.decide("bob", "write", "x", {"env": "prod", "x": 1})["rule"],
            "tagged",
        )
        # fnmatch is case sensitive
        self.assertEqual(
            gate.decide("bob", "READ", "docs/a")["effect"], "deny"
        )

    def test_missing_tag_value_does_not_match(self):
        gate = PolicyGate([{"id": "a", "effect": "allow", "tags": {"k": "v"}}])
        self.assertEqual(gate.decide("s", "a", "r")["effect"], "deny")

    def test_demo_gate(self):
        gate = PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read"},
                {"id": "prod-lock", "effect": "deny", "resource": "prod/*"},
            ]
        )
        self.assertEqual(gate.decide("alice", "read", "prod/db")["effect"], "deny")
        self.assertEqual(gate.decide("alice", "read", "dev/db")["effect"], "allow")


class PriorityAndConflictTest(unittest.TestCase):
    def test_explicit_deny_beats_higher_priority_allow(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow", "priority": 100},
                {"id": "d1", "effect": "deny", "priority": -5},
            ]
        )
        result = gate.decide("s", "a", "r")
        self.assertEqual(result["effect"], "deny")
        self.assertEqual(result["rule"], "d1")
        self.assertIn("deny", result["reason"])
        self.assertIn("d1", result["reason"])
        self.assertIn("priority", result["reason"])
        self.assertIn("overrides allow", result["reason"])

    def test_higher_priority_allow_wins(self):
        gate = PolicyGate(
            [
                {"id": "low", "effect": "allow", "priority": 1},
                {"id": "high", "effect": "allow", "priority": 10},
            ]
        )
        result = gate.decide("s", "a", "r")
        self.assertEqual(result["effect"], "allow")
        self.assertEqual(result["rule"], "high")

    def test_equal_priority_keeps_declaration_order(self):
        gate = PolicyGate(
            [
                {"id": "first", "effect": "allow"},
                {"id": "second", "effect": "allow"},
            ]
        )
        self.assertEqual(gate.decide("s", "a", "r")["rule"], "first")

    def test_deny_tie_keeps_declaration_order(self):
        gate = PolicyGate(
            [
                {"id": "d-first", "effect": "deny", "priority": 5},
                {"id": "d-second", "effect": "deny", "priority": 5},
                {"id": "a", "effect": "allow", "priority": 9},
            ]
        )
        self.assertEqual(gate.decide("s", "a", "r")["rule"], "d-first")

    def test_decision_is_deterministic(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow", "priority": 1},
                {"id": "a2", "effect": "allow", "priority": 2},
                {"id": "d1", "effect": "deny", "priority": 1},
                {"id": "d2", "effect": "deny", "priority": 2},
            ]
        )
        results = [gate.decide("s", "a", "r") for _ in range(20)]
        self.assertTrue(all(r == results[0] for r in results))
        self.assertEqual(results[0]["rule"], "d2")

    def test_reason_mentions_effect_id_priority(self):
        gate = PolicyGate([{"id": "x", "effect": "allow", "priority": 7}])
        reason = gate.decide("s", "a", "r")["reason"]
        self.assertIn("allow", reason)
        self.assertIn("x", reason)
        self.assertIn("7", reason)

    def test_default_priority_is_zero(self):
        gate = PolicyGate([{"id": "x", "effect": "allow"}])
        self.assertIn("priority 0", gate.decide("s", "a", "r")["reason"])


class LoadValidationTest(unittest.TestCase):
    def _expect_value_error(self, rules):
        with self.assertRaises(ValueError):
            PolicyGate(rules)

    def test_non_mapping_rule(self):
        self._expect_value_error([["not", "a", "dict"]])

    def test_bad_effect(self):
        self._expect_value_error([{"id": "x", "effect": "maybe"}])

    def test_missing_effect(self):
        self._expect_value_error([{"id": "x"}])

    def test_empty_and_non_string_id(self):
        self._expect_value_error([{"id": "", "effect": "allow"}])
        self._expect_value_error([{"id": 3, "effect": "allow"}])

    def test_duplicate_ids(self):
        self._expect_value_error(
            [
                {"id": "x", "effect": "allow"},
                {"id": "x", "effect": "deny"},
            ]
        )

    def test_duplicate_default_and_explicit_id(self):
        self._expect_value_error(
            [
                {"id": "1", "effect": "allow"},
                {"effect": "deny"},
            ]
        )

    def test_bad_priority(self):
        self._expect_value_error([{"id": "x", "effect": "allow", "priority": 1.5}])
        self._expect_value_error([{"id": "x", "effect": "allow", "priority": True}])
        self._expect_value_error([{"id": "x", "effect": "allow", "priority": "1"}])

    def test_bad_string_fields(self):
        self._expect_value_error([{"id": "x", "effect": "allow", "subject": 1}])
        self._expect_value_error([{"id": "x", "effect": "allow", "action": None}])
        self._expect_value_error([{"id": "x", "effect": "allow", "resource": 9}])

    def test_bad_tags(self):
        self._expect_value_error([{"id": "x", "effect": "allow", "tags": []}])
        self._expect_value_error(
            [{"id": "x", "effect": "allow", "tags": {1: "v"}}]
        )

    def test_unsupported_field(self):
        self._expect_value_error(
            [{"id": "x", "effect": "allow", "sourc3": "nope"}]
        )

    def test_error_names_first_offending_index(self):
        rules = [
            {"id": "ok", "effect": "allow"},
            {"id": "bad", "effect": "allow", "priority": "nope"},
            {"id": "also-bad", "effect": "wat"},
        ]
        with self.assertRaises(ValueError) as ctx:
            PolicyGate(rules)
        self.assertIn("rule 1", str(ctx.exception))
        self.assertIn("priority", str(ctx.exception))

    def test_legacy_config_loads_without_changes(self):
        gate = PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read"},
                {"effect": "deny", "resource": "secret/*", "tags": {"k": "v"}},
            ]
        )
        self.assertEqual(gate.rules[1]["id"], "1")
        self.assertEqual(gate.rules[1]["priority"], 0)


class DecideInputValidationTest(unittest.TestCase):
    def setUp(self):
        self.gate = PolicyGate([{"id": "x", "effect": "allow"}])

    def test_non_string_inputs(self):
        with self.assertRaises(TypeError):
            self.gate.decide(1, "a", "r")
        with self.assertRaises(TypeError):
            self.gate.decide("s", ["a"], "r")
        with self.assertRaises(TypeError):
            self.gate.decide("s", "a", None)

    def test_bad_tags_type(self):
        with self.assertRaises(TypeError):
            self.gate.decide("s", "a", "r", tags="k=v")
        with self.assertRaises(TypeError):
            self.gate.decide("s", "a", "r", tags=[("k", "v")])

    def test_tags_none_is_allowed(self):
        result = self.gate.decide("s", "a", "r", tags=None)
        self.assertEqual(result["effect"], "allow")

    def test_result_is_always_defined(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "subject": "bob"},
                {"id": "d", "effect": "deny"},
            ]
        )
        for subject in ("bob", "carol"):
            effect = gate.decide(subject, "x", "y")["effect"]
            self.assertIn(effect, ("allow", "deny"))


class ExplainTest(unittest.TestCase):
    def _gate(self):
        return PolicyGate(
            [
                {"id": "r-low", "effect": "allow", "priority": -1, "action": "read"},
                {"id": "r-high", "effect": "allow", "priority": 10, "action": "read"},
                {"id": "w-star", "effect": "allow", "action": "*", "tags": {"env": "dev"}},
                {"id": "d-prod", "effect": "deny", "resource": "prod/*"},
                {"id": "d-other", "effect": "deny", "action": "write"},
                {"id": "miss", "effect": "allow", "subject": "nobody"},
            ]
        )

    def test_core_fields_equal_decide(self):
        gate = self._gate()
        for args in (
            ("alice", "read", "dev/x", None),
            ("alice", "read", "prod/db", {"env": "dev"}),
            ("bob", "write", "x", {"env": "dev"}),
            ("bob", "delete", "x", {"env": "prod"}),
        ):
            decision = gate.decide(*args)
            explanation = gate.explain(*args)
            for key in ("effect", "rule", "reason"):
                self.assertEqual(explanation[key], decision[key])

    def test_matched_rules_in_declaration_order(self):
        gate = self._gate()
        explanation = gate.explain("alice", "read", "dev/x", {"env": "dev"})
        self.assertEqual(explanation["rule"], "r-high")
        self.assertEqual(
            explanation["matched_rules"],
            [
                {"id": "r-low", "effect": "allow", "priority": -1},
                {"id": "r-high", "effect": "allow", "priority": 10},
                {"id": "w-star", "effect": "allow", "priority": 0},
            ],
        )

    def test_deny_and_allow_both_listed(self):
        gate = self._gate()
        explanation = gate.explain("alice", "read", "prod/db", {"env": "dev"})
        self.assertEqual(explanation["effect"], "deny")
        self.assertEqual(explanation["rule"], "d-prod")
        self.assertIn("overrides allow", explanation["reason"])
        self.assertEqual(
            explanation["matched_rules"],
            [
                {"id": "r-low", "effect": "allow", "priority": -1},
                {"id": "r-high", "effect": "allow", "priority": 10},
                {"id": "w-star", "effect": "allow", "priority": 0},
                {"id": "d-prod", "effect": "deny", "priority": 0},
            ],
        )

    def test_unmatched_rules_never_listed(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "subject": "alice"},
                {"id": "b", "effect": "deny", "subject": "bob"},
            ]
        )
        explanation = gate.explain("carol", "x", "y")
        self.assertEqual(explanation["matched_rules"], [])

    def test_default_deny_shape(self):
        gate = PolicyGate([])
        explanation = gate.explain("s", "a", "r")
        self.assertEqual(explanation["effect"], "deny")
        self.assertIsNone(explanation["rule"])
        self.assertEqual(explanation["reason"], "default deny")
        self.assertEqual(explanation["matched_rules"], [])

    def test_equal_priority_uses_declaration_order(self):
        gate = PolicyGate(
            [
                {"id": "first", "effect": "allow", "priority": 2},
                {"id": "second", "effect": "allow", "priority": 2},
            ]
        )
        explanation = gate.explain("s", "a", "r")
        self.assertEqual(explanation["rule"], "first")
        self.assertEqual(
            explanation["matched_rules"],
            [
                {"id": "first", "effect": "allow", "priority": 2},
                {"id": "second", "effect": "allow", "priority": 2},
            ],
        )

    def test_type_errors_match_decide(self):
        gate = PolicyGate([{"id": "x", "effect": "allow"}])
        for bad in ((1, "a", "r"), ("s", ["a"], "r"), ("s", "a", None)):
            with self.assertRaises(TypeError) as d_ctx:
                gate.decide(*bad)
            with self.assertRaises(TypeError) as e_ctx:
                gate.explain(*bad)
            self.assertEqual(str(e_ctx.exception), str(d_ctx.exception))
        with self.assertRaises(TypeError) as d_ctx:
            gate.decide("s", "a", "r", tags="k=v")
        with self.assertRaises(TypeError) as e_ctx:
            gate.explain("s", "a", "r", tags="k=v")
        self.assertEqual(str(e_ctx.exception), str(d_ctx.exception))

    def test_tags_none_treated_as_empty(self):
        gate = PolicyGate([{"id": "x", "effect": "allow"}])
        explanation = gate.explain("s", "a", "r", tags=None)
        self.assertEqual(explanation["effect"], "allow")
        self.assertEqual(
            explanation["matched_rules"],
            [{"id": "x", "effect": "allow", "priority": 0}],
        )

    def test_repeatable_and_read_only(self):
        gate = self._gate()
        before = [dict(r) for r in gate.rules]
        first = gate.explain("alice", "read", "prod/db", {"env": "dev"})
        for _ in range(20):
            again = gate.explain("alice", "read", "prod/db", {"env": "dev"})
            self.assertEqual(again, first)
        self.assertEqual(gate.rules, before)
        # returned entries must not alias internal rule mappings
        first["matched_rules"].append({"id": "tampered", "effect": "deny", "priority": 0})
        self.assertEqual(
            gate.explain("alice", "read", "prod/db", {"env": "dev"})["matched_rules"],
            first["matched_rules"][:-1],
        )


class FromJsonTest(unittest.TestCase):
    DOCUMENT = (
        '['
        '{"id": "read", "effect": "allow", "action": "read", "resource": "docs/*"},'
        '{"effect": "deny", "resource": "secret/*", "tags": {"env": "prod"}},'
        '{"id": "num", "effect": "allow", "priority": 5}'
        ']'
    )

    def test_loads_and_decides_like_constructor(self):
        gate = PolicyGate.from_json(self.DOCUMENT)
        legacy = PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read", "resource": "docs/*"},
                {"effect": "deny", "resource": "secret/*", "tags": {"env": "prod"}},
                {"id": "num", "effect": "allow", "priority": 5},
            ]
        )
        for args in (
            ("alice", "read", "docs/a", None),
            ("alice", "read", "secret/x", None),
            ("bob", "write", "x", {"env": "prod"}),
            ("bob", "write", "x", {"env": "dev"}),
        ):
            self.assertEqual(gate.decide(*args), legacy.decide(*args))
            self.assertEqual(gate.explain(*args), legacy.explain(*args))

    def test_defaults_are_applied(self):
        gate = PolicyGate.from_json('[{"effect": "allow"}]')
        self.assertEqual(gate.rules[0]["id"], "0")
        self.assertEqual(gate.rules[0]["priority"], 0)
        self.assertEqual(gate.rules[0]["subject"], "*")
        self.assertEqual(gate.rules[0]["action"], "*")
        self.assertEqual(gate.rules[0]["resource"], "*")
        self.assertEqual(gate.rules[0]["tags"], {})

    def test_empty_array_is_default_deny(self):
        gate = PolicyGate.from_json("[]")
        self.assertEqual(gate.rules, [])
        result = gate.decide("s", "a", "r")
        self.assertEqual(result["effect"], "deny")
        self.assertIsNone(result["rule"])
        self.assertEqual(result["reason"], "default deny")

    def test_whitespace_only_wrapping_is_fine(self):
        gate = PolicyGate.from_json('  \n\t [ ] \t\n  ')
        self.assertEqual(gate.decide("s", "a", "r")["effect"], "deny")

    def test_case_sensitive_fnmatch_preserved(self):
        gate = PolicyGate.from_json(
            '[{"id": "a", "effect": "allow", "action": "read"}]'
        )
        self.assertEqual(gate.decide("s", "read", "r")["effect"], "allow")
        self.assertEqual(gate.decide("s", "READ", "r")["effect"], "deny")

    def test_explicit_deny_and_priority_semantics_preserved(self):
        gate = PolicyGate.from_json(
            '['
            '{"id": "a", "effect": "allow", "priority": 100},'
            '{"id": "d", "effect": "deny", "priority": -5}'
            ']'
        )
        result = gate.decide("s", "a", "r")
        self.assertEqual(result["effect"], "deny")
        self.assertEqual(result["rule"], "d")

    # --- input type -------------------------------------------------

    def test_non_string_document_raises_type_error(self):
        for bad in (None, 1, 1.5, b"[]", [], {}, True):
            with self.assertRaises(TypeError):
                PolicyGate.from_json(bad)

    def test_bytes_are_not_silently_decoded(self):
        with self.assertRaises(TypeError):
            PolicyGate.from_json(b'[{"effect": "allow"}]')

    # --- structural errors ------------------------------------------

    def _expect_code(self, document, code):
        with self.assertRaises(PolicyConfigError) as ctx:
            PolicyGate.from_json(document)
        self.assertEqual(ctx.exception.code, code)
        self.assertIn(code, str(ctx.exception))

    def test_invalid_json_syntax(self):
        for bad in ("", "   ", "{", "[{", "[,]", "not json", "[1,]"):
            self._expect_code(bad, "invalid_json")

    def test_non_finite_numbers_are_invalid_json(self):
        self._expect_code("[NaN]", "invalid_json")
        self._expect_code("[Infinity]", "invalid_json")
        self._expect_code("[-Infinity]", "invalid_json")

    def test_duplicate_key_at_rule_level(self):
        self._expect_code(
            '[{"id": "x", "id": "y", "effect": "allow"}]', "duplicate_key"
        )

    def test_duplicate_key_nested_in_tags(self):
        self._expect_code(
            '[{"effect": "allow", "tags": {"k": "a", "k": "b"}}]',
            "duplicate_key",
        )

    def test_root_not_array(self):
        for bad in ('{"effect": "allow"}', "5", '"str"', "true", "null"):
            self._expect_code(bad, "root_not_array")

    def test_rule_not_object_reports_index(self):
        with self.assertRaises(PolicyConfigError) as ctx:
            PolicyGate.from_json('[{"effect": "allow"}, 5]')
        self.assertEqual(ctx.exception.code, "rule_not_object")
        self.assertIn("rule 1", str(ctx.exception))
        for bad in ("[[]]", '["allow"]', "[true]", "[null]"):
            self._expect_code(bad, "rule_not_object")

    def test_first_bad_element_index_is_reported(self):
        with self.assertRaises(PolicyConfigError) as ctx:
            PolicyGate.from_json('["nope", {"effect": "allow"}]')
        self.assertEqual(ctx.exception.code, "rule_not_object")
        self.assertIn("rule 0", str(ctx.exception))

    # --- semantic errors reuse ValueError ---------------------------

    def _expect_value_error(self, document):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(document)
        self.assertNotIsInstance(ctx.exception, PolicyConfigError)
        return ctx

    def test_missing_effect_is_value_error(self):
        self._expect_value_error('[{"id": "x"}]')

    def test_unknown_field_is_value_error(self):
        ctx = self._expect_value_error(
            '[{"id": "x", "effect": "allow", "bogus": 1}]'
        )
        self.assertIn("rule 0", str(ctx.exception))

    def test_duplicate_id_is_value_error(self):
        self._expect_value_error(
            '[{"id": "x", "effect": "allow"},'
            '{"id": "x", "effect": "deny"}]'
        )

    def test_type_mismatches_are_value_errors(self):
        self._expect_value_error('[{"id": "x", "effect": "allow", "priority": 1.5}]')
        self._expect_value_error('[{"id": "x", "effect": "allow", "priority": "1"}]')
        self._expect_value_error('[{"id": 3, "effect": "allow"}]')
        self._expect_value_error('[{"effect": "allow", "subject": 1}]')
        self._expect_value_error('[{"effect": "allow", "tags": []}]')

    def test_semantic_error_names_first_offending_index(self):
        ctx = self._expect_value_error(
            '['
            '{"id": "ok", "effect": "allow"},'
            '{"id": "bad", "effect": "allow", "priority": "nope"},'
            '{"id": "also", "effect": "wat"}'
            ']'
        )
        self.assertIn("rule 1", str(ctx.exception))
        self.assertIn("priority", str(ctx.exception))

    # --- no side effects / no half-built instance -------------------

    def test_failed_load_leaves_no_instance(self):
        with self.assertRaises(PolicyConfigError):
            PolicyGate.from_json('[{"effect": "allow"}, oops]')
        with self.assertRaises(PolicyConfigError):
            PolicyGate.from_json('{"effect": "allow"}')
        with self.assertRaises(ValueError):
            PolicyGate.from_json('[{"id": "x"}]')

    def test_input_text_is_not_mutated(self):
        document = '[{"effect": "allow"}]'
        snapshot = document
        PolicyGate.from_json(document)
        self.assertEqual(document, snapshot)
        self.assertIs(document, snapshot)

    def test_loaded_decisions_match_after_text_is_reused(self):
        document = '[{"id": "x", "effect": "allow"}]'
        gate = PolicyGate.from_json(document)
        again = PolicyGate.from_json(document)
        self.assertEqual(
            gate.decide("s", "a", "r"), again.decide("s", "a", "r")
        )


class AuditTest(unittest.TestCase):
    def test_empty_rules_empty_report(self):
        self.assertEqual(
            PolicyGate([]).audit(),
            {"findings": [], "summary": {"total": 0, "error": 0, "warning": 0}},
        )

    def test_no_overlap_empty_report(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "subject": "alice"},
                {"id": "d", "effect": "deny", "subject": "bob"},
            ]
        )
        self.assertEqual(
            gate.audit(),
            {"findings": [], "summary": {"total": 0, "error": 0, "warning": 0}},
        )

    def test_similar_but_disjoint_patterns_not_flagged(self):
        disjoint_pairs = [
            ("data/[0-9]*", "data/[a-z]*"),
            ("a*", "b*"),
            ("[!a]", "a"),
            ("prod/?", "prod/xy"),
            ("[z-a]", "*"),  # empty range never matches anything
        ]
        for first, second in disjoint_pairs:
            gate = PolicyGate(
                [
                    {"id": "a", "effect": "allow", "resource": first},
                    {"id": "d", "effect": "deny", "resource": second},
                ]
            )
            self.assertEqual(
                gate.audit()["findings"],
                [],
                "patterns %r and %r must not be reported as overlapping"
                % (first, second),
            )

    def test_effect_overlap_error(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow", "resource": "data/*"},
                {"id": "d1", "effect": "deny", "resource": "data/secret*"},
            ]
        )
        report = gate.audit()
        self.assertEqual(report["summary"], {"total": 1, "error": 1, "warning": 0})
        (finding,) = report["findings"]
        self.assertEqual(
            finding,
            {
                "code": "effect_overlap",
                "severity": "error",
                "rule": "a1",
                "other_rule": "d1",
                "winner": "d1",
                "shadowed": None,
                "reason": finding["reason"],
                "witness": finding["witness"],
            },
        )
        self.assertIn("deny", finding["reason"])
        self.assertIn("allow", finding["reason"])

    def test_effect_overlap_winner_ignores_priority(self):
        gate = PolicyGate(
            [
                {"id": "d1", "effect": "deny", "priority": -5, "action": "read"},
                {"id": "a1", "effect": "allow", "priority": 100, "action": "r*"},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "effect_overlap")
        # rule/other_rule follow declaration order, not effect or priority
        self.assertEqual(finding["rule"], "d1")
        self.assertEqual(finding["other_rule"], "a1")
        self.assertEqual(finding["winner"], "d1")
        self.assertIsNone(finding["shadowed"])

    def test_shadowed_allow_by_deny_is_error(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow", "priority": 10, "action": "read"},
                {"id": "d1", "effect": "deny", "priority": -1, "action": "read"},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "shadowed_rule")
        self.assertEqual(finding["severity"], "error")
        self.assertEqual(finding["winner"], "d1")
        self.assertEqual(finding["shadowed"], "a1")

    def test_shadowed_same_effect_is_warning(self):
        gate = PolicyGate(
            [
                {"id": "first", "effect": "allow", "action": "read"},
                {"id": "second", "effect": "allow", "action": "read"},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "shadowed_rule")
        self.assertEqual(finding["severity"], "warning")
        self.assertEqual(finding["winner"], "first")
        self.assertEqual(finding["shadowed"], "second")

    def test_shadowed_same_effect_uses_priority(self):
        gate = PolicyGate(
            [
                {"id": "low", "effect": "deny", "priority": 1},
                {"id": "high", "effect": "deny", "priority": 9},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["severity"], "warning")
        self.assertEqual(finding["winner"], "high")
        self.assertEqual(finding["shadowed"], "low")

    def test_same_effect_partial_overlap_no_finding(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "resource": "data/*"},
                {"id": "b", "effect": "allow", "resource": "data/x*"},
                {"id": "c", "effect": "deny", "resource": "a*"},
                {"id": "d", "effect": "deny", "resource": "ab*"},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_tag_conflict_prevents_overlap(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"env": "prod"}},
                {"id": "d", "effect": "deny", "tags": {"env": "dev"}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_disjoint_tag_keys_still_overlap(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"env": "prod"}},
                {"id": "d", "effect": "deny", "tags": {"team": "sec"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "effect_overlap")

    def test_glob_semantics_in_overlap(self):
        # 'a?c' and 'abc' both match "abc"; '?' and '[!x]' share characters
        for first, second in (("a?c", "abc"), ("?", "[!x]"), ("a*", "*b")):
            gate = PolicyGate(
                [
                    {"id": "a", "effect": "allow", "action": first},
                    {"id": "d", "effect": "deny", "action": second},
                ]
            )
            (finding,) = gate.audit()["findings"]
            self.assertEqual(finding["code"], "effect_overlap")

    def test_summary_counts_and_stable_order(self):
        gate = PolicyGate(
            [
                {"id": "r0", "effect": "allow", "action": "read"},
                {"id": "r1", "effect": "deny", "action": "r*"},
                {"id": "r2", "effect": "allow", "action": "read"},
                {"id": "r3", "effect": "deny", "resource": "x"},
                {"id": "r4", "effect": "deny", "resource": "x"},
            ]
        )
        report = gate.audit()
        pairs = [(f["rule"], f["other_rule"]) for f in report["findings"]]
        self.assertEqual(pairs, sorted(pairs))
        self.assertEqual(len(pairs), len(set(pairs)))
        self.assertEqual(
            report["summary"],
            {
                "total": len(report["findings"]),
                "error": sum(
                    1 for f in report["findings"] if f["severity"] == "error"
                ),
                "warning": sum(
                    1 for f in report["findings"] if f["severity"] == "warning"
                ),
            },
        )
        self.assertGreater(report["summary"]["error"], 0)
        self.assertGreater(report["summary"]["warning"], 0)

    def test_audit_is_read_only_and_decisions_unchanged(self):
        rules = [
            {"id": "a1", "effect": "allow", "priority": 5, "resource": "data/*"},
            {"id": "d1", "effect": "deny", "resource": "data/secret*"},
            {"id": "a2", "effect": "allow", "resource": "data/*"},
        ]
        gate = PolicyGate(rules)
        before = [dict(r) for r in gate.rules]
        decisions_before = gate.decide_many(
            [
                {"subject": "s", "action": "read", "resource": "data/x"},
                {"subject": "s", "action": "read", "resource": "data/secret1"},
            ]
        )
        first = gate.audit()
        for _ in range(5):
            self.assertEqual(gate.audit(), first)
        self.assertEqual(gate.rules, before)
        self.assertEqual(
            gate.decide_many(
                [
                    {"subject": "s", "action": "read", "resource": "data/x"},
                    {"subject": "s", "action": "read", "resource": "data/secret1"},
                ]
            ),
            decisions_before,
        )
        self.assertEqual(
            gate.decide("s", "read", "data/x"),
            {"effect": "allow", "rule": "a1",
             "reason": "matched allow rule 'a1' (priority 5)"},
        )

    def test_audit_matches_from_json_gate(self):
        document = (
            '[{"id": "read", "effect": "allow", "action": "read"},'
            '{"effect": "deny", "resource": "secret/*", "tags": {"env": "prod"}}]'
        )
        gate = PolicyGate.from_json(document)
        legacy = PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read"},
                {"effect": "deny", "resource": "secret/*", "tags": {"env": "prod"}},
            ]
        )
        self.assertEqual(gate.audit(), legacy.audit())
        # read-anything allow vs secret/* prod deny overlap on e.g. a
        # prod read of secret/x; the deny rule (default id "1") wins
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "effect_overlap")
        self.assertEqual(finding["rule"], "read")
        self.assertEqual(finding["other_rule"], "1")
        self.assertEqual(finding["winner"], "1")


class WitnessTest(unittest.TestCase):
    def _gate_for_pair(self, first, second):
        return PolicyGate(
            [
                dict(first, id="r1"),
                dict(second, id="r2"),
            ]
        )

    def assertWitnessTriggers(self, gate, finding):
        witness = finding["witness"]
        self.assertEqual(
            set(witness), {"subject", "action", "resource", "tags"}
        )
        rules = {r["id"]: r for r in gate.rules}
        for rid in (finding["rule"], finding["other_rule"]):
            self.assertTrue(
                PolicyGate._matches(
                    rules[rid],
                    witness["subject"],
                    witness["action"],
                    witness["resource"],
                    witness["tags"],
                ),
                "witness %r does not match rule %r of finding %r"
                % (witness, rid, finding["code"]),
            )
        explanation = gate.explain(
            witness["subject"],
            witness["action"],
            witness["resource"],
            witness["tags"],
        )
        matched_ids = [m["id"] for m in explanation["matched_rules"]]
        self.assertIn(finding["rule"], matched_ids)
        self.assertIn(finding["other_rule"], matched_ids)
        # pairwise replay: with only the pair present, the named winner
        # must win exactly as the finding describes
        pair_decision, pair_winner = PolicyGate._select(
            [rules[finding["rule"]], rules[finding["other_rule"]]]
        )
        self.assertEqual(pair_winner["id"], finding["winner"])
        if finding["code"] == "effect_overlap":
            self.assertEqual(pair_decision["effect"], "deny")
            # the deny side can never be overridden globally either
            self.assertEqual(explanation["effect"], "deny")
        elif finding["severity"] == "error":
            self.assertEqual(pair_decision["effect"], "deny")
        return explanation

    def test_every_finding_carries_a_working_witness(self):
        gate = PolicyGate(
            [
                {"id": "r0", "effect": "allow", "action": "read"},
                {"id": "r1", "effect": "deny", "action": "r*"},
                {"id": "r2", "effect": "allow", "action": "read"},
                {"id": "r3", "effect": "deny", "resource": "x"},
                {"id": "r4", "effect": "deny", "resource": "x"},
            ]
        )
        report = gate.audit()
        self.assertTrue(report["findings"])
        for finding in report["findings"]:
            self.assertIn(
                "witness", finding, "finding %r has no witness" % finding
            )
            explanation = self.assertWitnessTriggers(gate, finding)
            if finding["code"] == "effect_overlap":
                # explicit deny cannot be undone by any third rule either
                self.assertEqual(explanation["effect"], "deny")

    def test_effect_overlap_witness_reproduces_explicit_deny(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow", "resource": "data/*",
                 "tags": {"env": "prod"}},
                {"id": "d1", "effect": "deny", "resource": "data/secret*"},
            ]
        )
        (finding,) = gate.audit()["findings"]
        witness = finding["witness"]
        self.assertEqual(witness["subject"], "")
        self.assertEqual(witness["action"], "")
        self.assertEqual(witness["resource"], "data/secret")
        self.assertEqual(witness["tags"], {"env": "prod"})
        explanation = self.assertWitnessTriggers(gate, finding)
        self.assertEqual(explanation["effect"], "deny")
        self.assertEqual(explanation["rule"], "d1")

    def test_shadowed_rule_witness_matches_both(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow", "priority": 10, "action": "read"},
                {"id": "d1", "effect": "deny", "priority": -1, "action": "read"},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "shadowed_rule")
        witness = finding["witness"]
        self.assertEqual(
            witness, {"subject": "", "action": "read", "resource": "", "tags": {}}
        )
        self.assertWitnessTriggers(gate, finding)

    def test_shortest_then_codepoint_lexicographic(self):
        cases = [
            ("*", "*", ""),
            ("a*", "*b", "ab"),
            ("?", "[!x]", "\x00"),
            ("[a-c]", "[b-d]", "b"),
            ("[abc]", "[cba]", "a"),
            ("data/*", "data/secret*", "data/secret"),
            ("a?c", "abc", "abc"),
            ("read", "r*", "read"),
            ("*b", "b*", "b"),
            ("中*", "*文", "中文"),
            ("[中-文]", "*", "中"),
            ("h?", "h[!x]", "h\x00"),
        ]
        for first, second, expected in cases:
            gate = self._gate_for_pair(
                {"effect": "allow", "resource": first},
                {"effect": "deny", "resource": second},
            )
            (finding,) = gate.audit()["findings"]
            self.assertEqual(
                finding["witness"]["resource"],
                expected,
                "patterns %r/%r" % (first, second),
            )

    def test_literal_brackets_and_single_char_classes(self):
        gate = self._gate_for_pair(
            {"effect": "allow", "resource": "["},
            {"effect": "deny", "resource": "*"},
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["resource"], "[")
        self.assertWitnessTriggers(gate, finding)

        gate = self._gate_for_pair(
            {"effect": "allow", "resource": "[]]"},
            {"effect": "deny", "resource": "?"},
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["resource"], "]")
        self.assertWitnessTriggers(gate, finding)

    def test_fields_are_chosen_independently(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "subject": "alice*",
                 "action": "read", "resource": "docs/*"},
                {"id": "d", "effect": "deny", "subject": "*z",
                 "action": "r*", "resource": "d*"},
            ]
        )
        (finding,) = gate.audit()["findings"]
        witness = finding["witness"]
        self.assertEqual(witness["subject"], "alicez")
        self.assertEqual(witness["action"], "read")
        self.assertEqual(witness["resource"], "docs/")  # docs/* vs d*
        self.assertWitnessTriggers(gate, finding)

    def test_tags_merged_not_invented(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tags": {"z": 1, "中": 2, "env": "prod"}},
                {"id": "d", "effect": "deny",
                 "tags": {"team": "sec", "env": "prod"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        tags = finding["witness"]["tags"]
        self.assertEqual(
            tags, {"env": "prod", "team": "sec", "z": 1, "中": 2}
        )
        # emitted in Unicode code-point order
        self.assertEqual(
            list(tags), sorted(tags, key=lambda k: ord(k[0]))
        )
        self.assertWitnessTriggers(gate, finding)

    def test_tags_empty_when_unconstrained(self):
        gate = self._gate_for_pair(
            {"effect": "allow"}, {"effect": "deny"}
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["tags"], {})
        self.assertWitnessTriggers(gate, finding)

    def test_conflicting_tags_means_no_finding_no_witness(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"env": "prod"}},
                {"id": "d", "effect": "deny", "tags": {"env": "dev"}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_same_effect_partial_overlap_still_no_finding(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "resource": "data/*"},
                {"id": "b", "effect": "allow", "resource": "data/x*"},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_from_json_and_constructor_give_identical_witnesses(self):
        document = (
            '[{"id": "read", "effect": "allow", "action": "read",'
            ' "resource": "docs/*", "tags": {"中": 1}},'
            '{"id": "lock", "effect": "deny", "resource": "d*",'
            ' "tags": {"a": 2}}]'
        )
        loaded = PolicyGate.from_json(document)
        built = PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read",
                 "resource": "docs/*", "tags": {"中": 1}},
                {"id": "lock", "effect": "deny", "resource": "d*",
                 "tags": {"a": 2}},
            ]
        )
        self.assertEqual(loaded.audit(), built.audit())
        witness = loaded.audit()["findings"][0]["witness"]
        self.assertEqual(
            witness,
            {"subject": "", "action": "read", "resource": "docs/",
             "tags": {"a": 2, "中": 1}},
        )
        self.assertWitnessTriggers(loaded, loaded.audit()["findings"][0])
        self.assertWitnessTriggers(built, built.audit()["findings"][0])

    def test_repeated_audits_equal_and_report_mutation_isolated(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow", "resource": "data/*",
                 "tags": {"env": "prod"}},
                {"id": "d1", "effect": "deny", "resource": "data/secret*"},
            ]
        )
        first = gate.audit()
        for _ in range(10):
            self.assertEqual(gate.audit(), first)
        first["findings"][0]["witness"]["subject"] = "tampered"
        first["findings"][0]["witness"]["tags"]["new"] = 3
        first["findings"][0]["winner"] = "tampered"
        fresh = gate.audit()
        self.assertEqual(fresh["findings"][0]["winner"], "d1")
        witness = fresh["findings"][0]["witness"]
        self.assertEqual(witness["subject"], "")
        self.assertEqual(witness["tags"], {"env": "prod"})
        # rule tag mappings must never have been touched
        self.assertEqual(
            gate.rules[0]["tags"], {"env": "prod"}
        )

    def test_witness_decisions_do_not_change_between_audits(self):
        rules = [
            {"id": "a1", "effect": "allow", "priority": 5, "resource": "data/*"},
            {"id": "d1", "effect": "deny", "resource": "data/secret*"},
        ]
        gate = PolicyGate(rules)
        before = gate.audit()
        requests = [
            f["witness"]
            for f in before["findings"]
        ]
        gate.audit()
        gate.audit()
        decisions = [
            gate.decide(r["subject"], r["action"], r["resource"], r["tags"])
            for r in requests
        ]
        self.assertTrue(all(d["effect"] == "deny" for d in decisions))
        self.assertEqual(decisions[0]["rule"], "d1")

    def test_witnesses_validate_against_real_fnmatch_on_random_pairs(self):
        import fnmatch
        import random

        random.seed(1234)
        alphabet = list("ab[]*?!x-中é")
        for _ in range(300):
            first = "".join(
                random.choice(alphabet) for _ in range(random.randint(0, 5))
            )
            second = "".join(
                random.choice(alphabet) for _ in range(random.randint(0, 5))
            )
            gate = self._gate_for_pair(
                {"effect": "allow", "resource": first},
                {"effect": "deny", "resource": second},
            )
            findings = gate.audit()["findings"]
            witness = _min_common_from_patterns(first, second)
            if witness is None:
                self.assertEqual(findings, [], (first, second))
            else:
                self.assertEqual(len(findings), 1, (first, second))
                w = findings[0]["witness"]["resource"]
                self.assertTrue(fnmatch.fnmatchcase(w, first), (first, second, w))
                self.assertTrue(fnmatch.fnmatchcase(w, second), (first, second, w))


    def test_mutable_tag_values_are_detached_from_report(self):
        shared = {"nested": [1, 2]}
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"env": shared}},
                {"id": "d", "effect": "deny", "tags": {"k": "v"}},
            ]
        )
        witness = gate.audit()["findings"][0]["witness"]
        witness["tags"]["env"]["nested"].append(3)
        witness["tags"]["k"] = "tampered"
        fresh = gate.audit()["findings"][0]["witness"]
        self.assertEqual(fresh["tags"], {"env": {"nested": [1, 2]}, "k": "v"})
        self.assertEqual(shared, {"nested": [1, 2]})

    def test_full_gate_random_witness_fuzz(self):
        import fnmatch
        import random

        random.seed(99)
        alphabet = list("ab[]*?!x-中")
        tag_values = ("v1", "v2")
        for _ in range(150):
            rules = []
            for idx in range(random.randint(2, 6)):
                rule = {
                    "id": "r%d" % idx,
                    "effect": random.choice(("allow", "deny")),
                    "priority": random.randint(0, 3),
                }
                for field in ("subject", "action", "resource"):
                    if random.random() < 0.8:
                        rule[field] = "".join(
                            random.choice(alphabet)
                            for _ in range(random.randint(0, 5))
                        )
                tags = {}
                for key in ("env", "team", "中"):
                    if random.random() < 0.5:
                        tags[key] = random.choice(tag_values)
                rule["tags"] = tags
                rules.append(rule)
            gate = PolicyGate(rules)
            by_id = {r["id"]: r for r in gate.rules}
            report = gate.audit()
            seen_pairs = set()
            for finding in report["findings"]:
                pair = (finding["rule"], finding["other_rule"])
                self.assertEqual(len(pair), len(set(pair)))
                self.assertNotIn(pair, seen_pairs)
                seen_pairs.add(pair)
                self.assertEqual(
                    set(finding),
                    {
                        "code", "severity", "rule", "other_rule", "winner",
                        "shadowed", "reason", "witness",
                    },
                )
                w = finding["witness"]
                self.assertEqual(
                    set(w), {"subject", "action", "resource", "tags"}
                )
                for rid in pair:
                    r = by_id[rid]
                    self.assertTrue(fnmatch.fnmatchcase(w["subject"], r["subject"]))
                    self.assertTrue(fnmatch.fnmatchcase(w["action"], r["action"]))
                    self.assertTrue(
                        fnmatch.fnmatchcase(w["resource"], r["resource"])
                    )
                    for key, value in r["tags"].items():
                        self.assertEqual(w["tags"][key], value)
                # no invented tags: witness tags are exactly the union
                union_keys = set(by_id[pair[0]]["tags"]) | set(
                    by_id[pair[1]]["tags"]
                )
                self.assertEqual(set(w["tags"]), union_keys)
                # deny on the pair is always the winner of an overlap
                if finding["code"] == "effect_overlap":
                    self.assertEqual(
                        by_id[finding["winner"]]["effect"], "deny"
                    )
            # repeatability under the same rules
            self.assertEqual(gate.audit(), report)


def _min_common_from_patterns(first, second):
    from app import _tokenize_pattern, _min_common_string

    return _min_common_string(
        _tokenize_pattern(first), _tokenize_pattern(second)
    )


class SnapshotTest(unittest.TestCase):
    def test_empty_rules_export(self):
        self.assertEqual(PolicyGate([]).to_json(), "[]")

    def test_defaults_are_explicit_and_order_is_fixed(self):
        document = PolicyGate([{"effect": "allow"}]).to_json()
        self.assertEqual(
            document,
            '[{"id":"0","effect":"allow","priority":0,'
            '"subject":"*","action":"*","resource":"*","tags":{}}]',
        )
        rule = __import__("json").loads(document)[0]
        self.assertEqual(
            list(rule),
            ["id", "effect", "priority", "subject", "action", "resource", "tags"],
        )

    def test_declaration_order_internal_index_absent(self):
        gate = PolicyGate(
            [
                {"id": "second", "effect": "allow", "priority": 5},
                {"effect": "deny"},
                {"id": "first", "effect": "allow"},
            ]
        )
        document = gate.to_json()
        self.assertNotIn("_index", document)
        ids = [r["id"] for r in __import__("json").loads(document)]
        self.assertEqual(ids, ["second", "1", "first"])

    def test_tags_keys_sorted_recursively_non_ascii_kept(self):
        gate = PolicyGate(
            [
                {
                    "id": "r",
                    "effect": "allow",
                    "tags": {"z": 1, "a": {"中": "文", "b": [2, 1]}},
                }
            ]
        )
        document = gate.to_json()
        # compact separators and literal non-ASCII characters
        self.assertNotIn(", ", document)
        self.assertNotIn(": ", document)
        self.assertIn("中", document)
        self.assertNotIn("\\u", document)
        tags = __import__("json").loads(document)[0]["tags"]
        self.assertEqual(list(tags), ["a", "z"])
        self.assertEqual(list(tags["a"]), ["b", "中"])

    def test_repeated_calls_identical(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "priority": -2},
                {"id": "b", "effect": "deny", "tags": {"k": "v"}},
            ]
        )
        first = gate.to_json()
        self.assertTrue(all(gate.to_json() == first for _ in range(20)))

    def test_roundtrip_preserves_all_behaviors(self):
        import json

        rules = [
            {"id": "read", "effect": "allow", "action": "read",
             "resource": "docs/*"},
            {"effect": "deny", "resource": "secret/*",
             "tags": {"env": "prod", "nested": {"b": 1, "a": [1, 2]}}},
            {"id": "num", "effect": "allow", "priority": 5},
        ]
        gate = PolicyGate(rules)
        reloaded = PolicyGate.from_json(gate.to_json())
        requests = [
            {"subject": "alice", "action": "read", "resource": "docs/a"},
            {"subject": "alice", "action": "read", "resource": "secret/x",
             "tags": {"env": "prod"}},
            {"subject": "bob", "action": "write", "resource": "x",
             "tags": {"env": "dev"}},
        ]
        for request in requests:
            args = (request["subject"], request["action"], request["resource"],
                    request.get("tags"))
            self.assertEqual(reloaded.decide(*args), gate.decide(*args))
            self.assertEqual(reloaded.explain(*args), gate.explain(*args))
        self.assertEqual(reloaded.decide_many(requests), gate.decide_many(requests))
        self.assertEqual(reloaded.audit(), gate.audit())
        self.assertEqual(reloaded.to_json(), gate.to_json())
        # the exported document itself is strict JSON with no duplicates
        self.assertEqual(json.loads(gate.to_json())[1]["id"], "1")

    def test_export_does_not_mutate_rules_or_caller_data(self):
        import copy

        rules = [
            {"id": "a", "effect": "allow", "tags": {"z": 1, "a": {"y": 2}}},
            {"effect": "deny"},
        ]
        rules_snapshot = copy.deepcopy(rules)
        gate = PolicyGate(rules)
        caller_tags = {"env": "prod"}
        tags_snapshot = copy.deepcopy(caller_tags)
        for _ in range(3):
            gate.to_json()
            gate.fingerprint()
        gate.decide("s", "a", "r", caller_tags)
        self.assertEqual(rules, rules_snapshot)
        self.assertEqual(caller_tags, tags_snapshot)

    def _expect_non_json_value(self, rules):
        gate = PolicyGate(rules)
        for method in ("to_json", "fingerprint"):
            with self.assertRaises(ValueError) as ctx:
                getattr(gate, method)()
            self.assertNotIsInstance(ctx.exception, PolicyConfigError)
            self.assertIn("non_json_value", str(ctx.exception))

    def test_tuple_and_set_values_rejected(self):
        self._expect_non_json_value(
            [{"id": "t", "effect": "allow", "tags": {"k": (1, 2)}}]
        )
        self._expect_non_json_value(
            [{"id": "t", "effect": "allow", "tags": {"k": {1, 2}}}]
        )

    def test_non_finite_numbers_rejected(self):
        self._expect_non_json_value(
            [{"id": "t", "effect": "allow", "tags": {"k": float("nan")}}]
        )
        self._expect_non_json_value(
            [{"id": "t", "effect": "allow", "tags": {"k": float("inf")}}]
        )

    def test_nested_non_string_keys_rejected(self):
        self._expect_non_json_value(
            [{"id": "t", "effect": "allow", "tags": {"k": {1: "v"}}}]
        )
        self._expect_non_json_value(
            [{"id": "t", "effect": "allow", "tags": {"k": {"j": {2: "v"}}}}]
        )
        # mixed key types must not leak a TypeError from sorting
        self._expect_non_json_value(
            [{"id": "t", "effect": "allow", "tags": {"k": {"b": 1, 2: "x"}}}]
        )

    def test_lone_surrogate_rejected(self):
        self._expect_non_json_value([{"id": "t\ud800", "effect": "allow"}])

    def test_failure_returns_no_partial_text(self):
        gate = PolicyGate(
            [{"id": "ok", "effect": "allow"},
             {"id": "bad", "effect": "allow", "tags": {"k": (1,)}}]
        )
        with self.assertRaises(ValueError):
            gate.to_json()
        # the valid prefix must not be observable anywhere; the gate and
        # its rules remain usable for decisions
        self.assertEqual(gate.decide("s", "a", "r")["rule"], "ok")

    def test_fingerprint_shape_and_agreement(self):
        import hashlib

        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "subject": "alice",
                 "tags": {"z": 1, "a": 2}},
                {"effect": "deny"},
            ]
        )
        digest = gate.fingerprint()
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, digest.lower())
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(
            digest, hashlib.sha256(gate.to_json().encode("utf-8")).hexdigest()
        )
        self.assertTrue(all(gate.fingerprint() == digest for _ in range(10)))
        self.assertEqual(
            PolicyGate.from_json(gate.to_json()).fingerprint(), digest
        )
        self.assertEqual(PolicyGate([]).fingerprint(),
                         hashlib.sha256(b"[]").hexdigest())

    def test_snapshot_uses_no_io(self):
        import inspect

        source = inspect.getsource(PolicyGate.to_json) + inspect.getsource(
            PolicyGate.fingerprint
        )
        for forbidden in ("open(", "socket", "urllib", "requests", "subprocess"):
            self.assertNotIn(forbidden, source)


class CompareTest(unittest.TestCase):
    def setUp(self):
        # baseline: reads allowed, everything else default deny
        self.base = PolicyGate(
            [{"id": "read", "effect": "allow", "action": "read"}]
        )
        # candidate: same allow plus an explicit deny on prod/*
        self.candidate = PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read"},
                {"id": "prod-lock", "effect": "deny", "resource": "prod/*"},
            ]
        )
        self.requests = [
            {"subject": "alice", "action": "read", "resource": "dev/x"},
            {"subject": "alice", "action": "read", "resource": "prod/db"},
            {"subject": "bob", "action": "write", "resource": "x"},
        ]

    def test_report_structure_and_counts(self):
        report = self.base.compare(self.candidate, self.requests)
        self.assertEqual(
            report["summary"],
            {
                "total": 3,
                "unchanged": 2,
                "changed": 1,
                "allow_to_deny": 1,
                "deny_to_allow": 0,
                "winner_changed": 0,
            },
        )
        self.assertEqual(len(report["changes"]), 1)
        change = report["changes"][0]
        self.assertEqual(set(change), {"index", "before", "after", "kind"})
        self.assertEqual(change["index"], 1)
        self.assertEqual(change["kind"], "allow_to_deny")
        self.assertEqual(
            change["before"], self.base.decide("alice", "read", "prod/db")
        )
        self.assertEqual(
            change["after"], self.candidate.decide("alice", "read", "prod/db")
        )
        self.assertEqual(
            set(report), {"changes", "summary"}
        )
        self.assertEqual(
            set(report["summary"]),
            {
                "total",
                "unchanged",
                "changed",
                "allow_to_deny",
                "deny_to_allow",
                "winner_changed",
            },
        )

    def test_changes_follow_input_order(self):
        candidate = PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read"},
                {"id": "lock", "effect": "deny", "resource": "p*"},
            ]
        )
        requests = [
            {"subject": "s", "action": "read", "resource": "p/1"},
            {"subject": "s", "action": "read", "resource": "ok/2"},
            {"subject": "s", "action": "read", "resource": "p/3"},
        ]
        report = self.base.compare(candidate, requests)
        self.assertEqual([c["index"] for c in report["changes"]], [0, 2])
        for change in report["changes"]:
            self.assertEqual(change["kind"], "allow_to_deny")

    def test_deny_to_allow(self):
        report = self.candidate.compare(self.base, self.requests)
        self.assertEqual(
            report["summary"],
            {
                "total": 3,
                "unchanged": 2,
                "changed": 1,
                "allow_to_deny": 0,
                "deny_to_allow": 1,
                "winner_changed": 0,
            },
        )
        self.assertEqual(report["changes"][0]["index"], 1)
        self.assertEqual(report["changes"][0]["kind"], "deny_to_allow")

    def test_winner_changed_same_effect_different_rule(self):
        base = PolicyGate([{"id": "low", "effect": "allow", "priority": 1}])
        candidate = PolicyGate(
            [{"id": "high", "effect": "allow", "priority": 9}]
        )
        request = [{"subject": "s", "action": "a", "resource": "r"}]
        report = base.compare(candidate, request)
        self.assertEqual(
            report["summary"],
            {
                "total": 1,
                "unchanged": 0,
                "changed": 1,
                "allow_to_deny": 0,
                "deny_to_allow": 0,
                "winner_changed": 1,
            },
        )
        change = report["changes"][0]
        self.assertEqual(change["kind"], "winner_changed")
        self.assertEqual(change["before"]["rule"], "low")
        self.assertEqual(change["after"]["rule"], "high")
        self.assertEqual(change["before"]["effect"], change["after"]["effect"])

    def test_winner_changed_same_rule_different_reason(self):
        # same deny winner, but the baseline reason notes the overridden
        # allow while the candidate no longer has one
        base = PolicyGate(
            [
                {"id": "a", "effect": "allow"},
                {"id": "d", "effect": "deny"},
            ]
        )
        candidate = PolicyGate([{"id": "d", "effect": "deny"}])
        report = base.compare(
            candidate, [{"subject": "s", "action": "a", "resource": "r"}]
        )
        (change,) = report["changes"]
        self.assertEqual(change["kind"], "winner_changed")
        self.assertEqual(change["before"]["rule"], "d")
        self.assertEqual(change["after"]["rule"], "d")
        self.assertIn("overrides allow", change["before"]["reason"])
        self.assertNotIn("overrides allow", change["after"]["reason"])

    def test_identical_gates_report_everything_unchanged(self):
        requests = [
            {"subject": "alice", "action": "read", "resource": "prod/db"},
            {"subject": "bob", "action": "write", "resource": "x"},
        ]
        report = self.candidate.compare(self.candidate, requests)
        self.assertEqual(
            report["summary"],
            {
                "total": 2,
                "unchanged": 2,
                "changed": 0,
                "allow_to_deny": 0,
                "deny_to_allow": 0,
                "winner_changed": 0,
            },
        )
        self.assertEqual(report["changes"], [])

    def test_empty_batch_is_all_zero(self):
        report = self.base.compare(self.candidate, [])
        self.assertEqual(
            report,
            {
                "changes": [],
                "summary": {
                    "total": 0,
                    "unchanged": 0,
                    "changed": 0,
                    "allow_to_deny": 0,
                    "deny_to_allow": 0,
                    "winner_changed": 0,
                },
            },
        )

    def test_tuple_batch_accepted(self):
        report = self.base.compare(self.candidate, tuple(self.requests))
        self.assertEqual(report["summary"]["total"], 3)

    def test_tags_omitted_none_and_mapping(self):
        candidate = PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read"},
                {"id": "prod", "effect": "deny", "tags": {"env": "prod"}},
            ]
        )
        requests = [
            {"subject": "s", "action": "read", "resource": "r", "tags": None},
            {"subject": "s", "action": "read", "resource": "r",
             "tags": {"env": "prod"}},
            {"subject": "s", "action": "read", "resource": "r"},
        ]
        report = self.base.compare(candidate, requests)
        self.assertEqual([c["index"] for c in report["changes"]], [1])
        self.assertEqual(report["changes"][0]["kind"], "allow_to_deny")

    def test_candidate_must_be_policy_gate(self):
        for bad in (None, 1, 1.5, "gate", [], {}, True, object()):
            with self.assertRaises(TypeError):
                self.base.compare(bad, self.requests)

    def test_batch_validation_matches_decide_many(self):
        cases = [
            ("nope", "invalid_batch", None, None),
            (["x"], "item_not_mapping", 0, None),
            ([{"action": "a", "resource": "r"}],
             "missing_field", 0, "subject"),
            ([{"subject": 1, "action": "a", "resource": "r"}],
             "invalid_field_type", 0, "subject"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "bogus": 1}], "unknown_field", 0, "bogus"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "tags": "k=v"}], "invalid_field_type", 0, "tags"),
        ]
        for requests, code, index, field in cases:
            with self.subTest(requests=requests):
                with self.assertRaises(PolicyBatchError) as ctx:
                    self.base.compare(self.candidate, requests)
                self.assertEqual(ctx.exception.code, code)
                self.assertEqual(ctx.exception.index, index)
                self.assertEqual(ctx.exception.field, field)
                # decide_many rejects the same batch identically
                with self.assertRaises(PolicyBatchError):
                    self.base.decide_many(requests)

    def test_first_error_aborts_with_no_partial_results(self):
        good = {"subject": "s", "action": "a", "resource": "r"}
        with self.assertRaises(PolicyBatchError) as ctx:
            self.base.compare(
                self.candidate,
                [good, {"subject": "s", "bogus": 1}],
            )
        self.assertEqual(ctx.exception.index, 1)
        self.assertEqual(ctx.exception.code, "unknown_field")

    def test_candidate_type_checked_before_batch(self):
        # even an invalid batch must not mask a non-PolicyGate candidate
        with self.assertRaises(TypeError):
            self.base.compare("not-a-gate", "not-a-batch")

    def test_compare_is_read_only_and_repeatable(self):
        import copy

        requests_snapshot = copy.deepcopy(self.requests)
        base_rules = [dict(r) for r in self.base.rules]
        candidate_rules = [dict(r) for r in self.candidate.rules]
        first = self.base.compare(self.candidate, self.requests)
        for _ in range(20):
            self.assertEqual(
                self.base.compare(self.candidate, copy.deepcopy(self.requests)),
                first,
            )
        self.assertEqual(self.requests, requests_snapshot)
        self.assertEqual([dict(r) for r in self.base.rules], base_rules)
        self.assertEqual(
            [dict(r) for r in self.candidate.rules], candidate_rules
        )
        # mutating a returned result must not affect later comparisons
        first["changes"][0]["before"]["rule"] = "tampered"
        fresh = self.base.compare(self.candidate, self.requests)
        self.assertEqual(fresh["changes"][0]["before"]["rule"], "read")

    def test_from_json_gates_compare_like_constructor_gates(self):
        base = PolicyGate.from_json(
            '[{"id": "read", "effect": "allow", "action": "read"}]'
        )
        candidate = PolicyGate.from_json(
            '['
            '{"id": "read", "effect": "allow", "action": "read"},'
            '{"id": "prod-lock", "effect": "deny", "resource": "prod/*"}'
            ']'
        )
        report = base.compare(candidate, self.requests)
        self.assertEqual(report["summary"]["allow_to_deny"], 1)
        self.assertEqual(report["changes"][0]["index"], 1)
        self.assertEqual(report["changes"][0]["after"]["rule"], "prod-lock")


class CoverageTest(unittest.TestCase):
    def _gate(self):
        return PolicyGate(
            [
                {"id": "r-low", "effect": "allow", "priority": -1,
                 "action": "read"},
                {"id": "r-high", "effect": "allow", "priority": 10,
                 "action": "read"},
                {"id": "d-prod", "effect": "deny", "resource": "prod/*"},
                {"id": "tagged", "effect": "allow", "tags": {"env": "prod"}},
                {"id": "miss", "effect": "allow", "subject": "nobody"},
            ]
        )

    def test_report_structure_and_counts(self):
        gate = self._gate()
        requests = [
            # matches r-low, r-high, tagged; r-high wins -> allow
            {"subject": "alice", "action": "read", "resource": "dev/x",
             "tags": {"env": "prod"}},
            # matches r-low, r-high, d-prod; explicit deny wins
            {"subject": "bob", "action": "read", "resource": "prod/db"},
            # matches nothing -> default deny
            {"subject": "carol", "action": "write", "resource": "x"},
        ]
        report = gate.coverage(requests)
        self.assertEqual(set(report), {"rules", "summary"})
        self.assertEqual(
            report["rules"],
            [
                {"id": "r-low", "effect": "allow", "matched": 2, "winner": 0},
                {"id": "r-high", "effect": "allow", "matched": 2, "winner": 1},
                {"id": "d-prod", "effect": "deny", "matched": 1, "winner": 1},
                {"id": "tagged", "effect": "allow", "matched": 1, "winner": 0},
                {"id": "miss", "effect": "allow", "matched": 0, "winner": 0},
            ],
        )
        self.assertEqual(
            report["summary"],
            {
                "total": 3,
                "allow": 1,
                "explicit_deny": 1,
                "default_deny": 1,
                "matched_request": 2,
            },
        )

    def test_rule_fields_and_order_stable(self):
        gate = self._gate()
        report = gate.coverage(
            [{"subject": "s", "action": "read", "resource": "r"}]
        )
        self.assertEqual(
            [r["id"] for r in report["rules"]],
            ["r-low", "r-high", "d-prod", "tagged", "miss"],
        )
        for entry in report["rules"]:
            self.assertEqual(list(entry), ["id", "effect", "matched", "winner"])

    def test_empty_batch_is_all_zero(self):
        gate = self._gate()
        report = gate.coverage([])
        self.assertEqual(
            report["summary"],
            {
                "total": 0,
                "allow": 0,
                "explicit_deny": 0,
                "default_deny": 0,
                "matched_request": 0,
            },
        )
        self.assertEqual(len(report["rules"]), 5)
        for entry in report["rules"]:
            self.assertEqual(entry["matched"], 0)
            self.assertEqual(entry["winner"], 0)

    def test_empty_rule_set_counts_default_deny(self):
        gate = PolicyGate([])
        requests = [
            {"subject": "s", "action": "a", "resource": "r"},
            {"subject": "t", "action": "b", "resource": "x"},
        ]
        report = gate.coverage(requests)
        self.assertEqual(report["rules"], [])
        self.assertEqual(
            report["summary"],
            {
                "total": 2,
                "allow": 0,
                "explicit_deny": 0,
                "default_deny": 2,
                "matched_request": 0,
            },
        )

    def test_tuple_batch_accepted(self):
        gate = self._gate()
        report = gate.coverage(
            ({"subject": "s", "action": "read", "resource": "r"},)
        )
        self.assertEqual(report["summary"]["total"], 1)
        self.assertEqual(report["summary"]["allow"], 1)

    def test_tags_omitted_none_and_mapping(self):
        gate = PolicyGate(
            [{"id": "tagged", "effect": "allow", "tags": {"env": "prod"}}]
        )
        requests = [
            {"subject": "s", "action": "a", "resource": "r", "tags": None},
            {"subject": "s", "action": "a", "resource": "r"},
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod"}},
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod", "extra": 1}},
        ]
        report = gate.coverage(requests)
        self.assertEqual(report["rules"][0]["matched"], 2)
        self.assertEqual(report["rules"][0]["winner"], 2)
        self.assertEqual(report["summary"]["allow"], 2)
        self.assertEqual(report["summary"]["default_deny"], 2)

    def test_explicit_deny_beats_higher_priority_allow(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow", "priority": 100},
                {"id": "d1", "effect": "deny", "priority": -5},
            ]
        )
        report = gate.coverage(
            [{"subject": "s", "action": "a", "resource": "r"}]
        )
        self.assertEqual(
            report["rules"],
            [
                {"id": "a1", "effect": "allow", "matched": 1, "winner": 0},
                {"id": "d1", "effect": "deny", "matched": 1, "winner": 1},
            ],
        )
        self.assertEqual(report["summary"]["explicit_deny"], 1)
        self.assertEqual(report["summary"]["allow"], 0)

    def test_priority_then_declaration_order_tiebreak(self):
        gate = PolicyGate(
            [
                {"id": "low", "effect": "allow", "priority": 1},
                {"id": "high", "effect": "allow", "priority": 10},
                {"id": "also-high", "effect": "allow", "priority": 10},
            ]
        )
        report = gate.coverage(
            [{"subject": "s", "action": "a", "resource": "r"}] * 3
        )
        self.assertEqual(
            [r["winner"] for r in report["rules"]], [0, 3, 0]
        )
        self.assertEqual(
            [r["matched"] for r in report["rules"]], [3, 3, 3]
        )

    def test_fnmatchcase_semantics_used(self):
        gate = PolicyGate(
            [{"id": "a", "effect": "allow", "action": "read"}]
        )
        report = gate.coverage(
            [
                {"subject": "s", "action": "read", "resource": "r"},
                {"subject": "s", "action": "READ", "resource": "r"},
            ]
        )
        self.assertEqual(report["rules"][0]["matched"], 1)
        self.assertEqual(report["summary"]["default_deny"], 1)

    def test_batch_validation_matches_decide_many(self):
        gate = self._gate()
        cases = [
            ("nope", "invalid_batch", None, None),
            (["x"], "item_not_mapping", 0, None),
            ([{"action": "a", "resource": "r"}],
             "missing_field", 0, "subject"),
            ([{"subject": 1, "action": "a", "resource": "r"}],
             "invalid_field_type", 0, "subject"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "bogus": 1}], "unknown_field", 0, "bogus"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "tags": "k=v"}], "invalid_field_type", 0, "tags"),
        ]
        for requests, code, index, field in cases:
            with self.subTest(requests=requests):
                with self.assertRaises(PolicyBatchError) as ctx:
                    gate.coverage(requests)
                self.assertEqual(ctx.exception.code, code)
                self.assertEqual(ctx.exception.index, index)
                self.assertEqual(ctx.exception.field, field)
                with self.assertRaises(PolicyBatchError):
                    gate.decide_many(requests)

    def test_first_error_aborts_with_no_partial_report(self):
        gate = self._gate()
        good = {"subject": "s", "action": "read", "resource": "r"}
        with self.assertRaises(PolicyBatchError) as ctx:
            gate.coverage([good, {"subject": "s", "bogus": 1}])
        self.assertEqual(ctx.exception.index, 1)
        self.assertEqual(ctx.exception.code, "unknown_field")

    def test_coverage_is_read_only_and_repeatable(self):
        import copy

        gate = self._gate()
        requests = [
            {"subject": "alice", "action": "read", "resource": "dev/x",
             "tags": {"env": "prod"}},
            {"subject": "bob", "action": "read", "resource": "prod/db"},
            {"subject": "carol", "action": "write", "resource": "x"},
        ]
        requests_snapshot = copy.deepcopy(requests)
        rules_before = [dict(r) for r in gate.rules]
        first = gate.coverage(requests)
        for _ in range(20):
            self.assertEqual(gate.coverage(copy.deepcopy(requests)), first)
        self.assertEqual(requests, requests_snapshot)
        self.assertEqual([dict(r) for r in gate.rules], rules_before)
        # mutating a returned report must not affect later calls
        first["rules"][0]["matched"] = 999
        first["summary"]["total"] = 999
        fresh = gate.coverage(requests)
        self.assertEqual(fresh["rules"][0]["matched"], 2)
        self.assertEqual(fresh["summary"]["total"], 3)

    def test_counts_agree_with_decide_many(self):
        gate = self._gate()
        requests = [
            {"subject": "alice", "action": "read", "resource": "dev/x",
             "tags": {"env": "prod"}},
            {"subject": "bob", "action": "read", "resource": "prod/db"},
            {"subject": "carol", "action": "write", "resource": "x"},
            {"subject": "nobody", "action": "delete", "resource": "y"},
        ]
        coverage = gate.coverage(requests)
        decisions = gate.decide_many(requests)["decisions"]
        self.assertEqual(
            coverage["summary"]["allow"],
            sum(1 for d in decisions if d["effect"] == "allow"),
        )
        self.assertEqual(
            coverage["summary"]["explicit_deny"]
            + coverage["summary"]["default_deny"],
            sum(1 for d in decisions if d["effect"] == "deny"),
        )
        self.assertEqual(
            coverage["summary"]["default_deny"],
            sum(1 for d in decisions if d["rule"] is None),
        )
        # every winner count matches the decisions' winning rule ids
        for entry in coverage["rules"]:
            self.assertEqual(
                entry["winner"],
                sum(1 for d in decisions if d["rule"] == entry["id"]),
            )

    def test_from_json_gate_coverage_matches_constructor(self):
        rules = [
            {"id": "read", "effect": "allow", "action": "read"},
            {"id": "prod-lock", "effect": "deny", "resource": "prod/*"},
        ]
        gate = PolicyGate(rules)
        reloaded = PolicyGate.from_json(gate.to_json())
        requests = [
            {"subject": "alice", "action": "read", "resource": "prod/db"},
            {"subject": "alice", "action": "read", "resource": "dev/db"},
        ]
        self.assertEqual(gate.coverage(requests), reloaded.coverage(requests))


class VerifyTest(unittest.TestCase):
    def _gate(self):
        return PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read"},
                {"id": "prod-lock", "effect": "deny", "resource": "prod/*"},
            ]
        )

    def _cases(self):
        return [
            {"subject": "alice", "action": "read", "resource": "dev/x",
             "expected": {"effect": "allow", "rule": "read"}},
            {"subject": "alice", "action": "read", "resource": "prod/db",
             "expected": {"effect": "deny", "rule": "prod-lock"}},
            {"subject": "bob", "action": "write", "resource": "x",
             "expected": {"effect": "deny", "rule": None}},
        ]

    def test_all_pass_report(self):
        gate = self._gate()
        report = gate.verify(self._cases())
        self.assertTrue(report["ok"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(
            report["summary"], {"total": 3, "passed": 3, "failed": 0}
        )
        self.assertEqual(set(report), {"ok", "failures", "summary"})
        self.assertEqual(
            set(report["summary"]), {"total", "passed", "failed"}
        )

    def test_empty_batch_is_ok_with_zero_summary(self):
        report = self._gate().verify([])
        self.assertEqual(
            report,
            {
                "ok": True,
                "failures": [],
                "summary": {"total": 0, "passed": 0, "failed": 0},
            },
        )
        self.assertEqual(self._gate().verify(())["ok"], True)

    def test_tuple_batch_accepted(self):
        report = self._gate().verify(tuple(self._cases()))
        self.assertTrue(report["ok"])
        self.assertEqual(report["summary"]["total"], 3)

    def test_default_deny_written_as_deny_null(self):
        gate = PolicyGate([])
        report = gate.verify(
            [
                {"subject": "s", "action": "a", "resource": "r",
                 "expected": {"effect": "deny", "rule": None}},
            ]
        )
        self.assertTrue(report["ok"])

    def test_failures_follow_input_order_and_hold_full_decision(self):
        gate = self._gate()
        cases = [
            {"subject": "alice", "action": "read", "resource": "dev/x",
             "expected": {"effect": "allow", "rule": "read"}},
            {"subject": "alice", "action": "read", "resource": "prod/db",
             "expected": {"effect": "allow", "rule": "read"}},
            {"subject": "bob", "action": "write", "resource": "x",
             "expected": {"effect": "deny", "rule": None}},
            {"subject": "carol", "action": "read", "resource": "dev/y",
             "expected": {"effect": "deny", "rule": "prod-lock"}},
        ]
        report = gate.verify(cases)
        self.assertFalse(report["ok"])
        self.assertEqual(
            report["summary"], {"total": 4, "passed": 2, "failed": 2}
        )
        self.assertEqual([f["index"] for f in report["failures"]], [1, 3])
        first, second = report["failures"]
        self.assertEqual(set(first), {"index", "expected", "actual"})
        self.assertEqual(
            first["expected"], {"effect": "allow", "rule": "read"}
        )
        self.assertEqual(
            first["actual"],
            gate.decide("alice", "read", "prod/db"),
        )
        self.assertEqual(first["actual"]["effect"], "deny")
        self.assertEqual(first["actual"]["rule"], "prod-lock")
        self.assertIn("reason", first["actual"])
        # index 3: effect allow is right, but the winning rule differs
        self.assertEqual(second["actual"]["effect"], "allow")
        self.assertEqual(second["actual"]["rule"], "read")

    def test_effect_and_rule_must_both_match_reason_ignored(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow"},
                {"id": "d", "effect": "deny", "subject": "z"},
            ]
        )
        # effect mismatch
        report = gate.verify(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": "deny", "rule": None}}]
        )
        self.assertEqual(report["summary"]["failed"], 1)
        self.assertEqual(report["failures"][0]["actual"]["effect"], "allow")
        # same effect but different rule still fails
        report = gate.verify(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": "allow", "rule": "other"}}]
        )
        self.assertEqual(report["summary"]["failed"], 1)
        self.assertEqual(report["failures"][0]["actual"]["rule"], "a")
        # the full decision, including reason, is reported as actual
        self.assertEqual(
            set(report["failures"][0]["actual"]),
            {"effect", "rule", "reason"},
        )
        # matching effect+rule passes regardless of the reason text
        report = gate.verify(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": "allow", "rule": "a"}}]
        )
        self.assertTrue(report["ok"])

    def test_tags_omitted_none_and_mapping(self):
        gate = PolicyGate(
            [{"id": "tagged", "effect": "allow", "tags": {"env": "prod"}}]
        )
        cases = [
            {"subject": "s", "action": "a", "resource": "r", "tags": None,
             "expected": {"effect": "deny", "rule": None}},
            {"subject": "s", "action": "a", "resource": "r",
             "expected": {"effect": "deny", "rule": None}},
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod"},
             "expected": {"effect": "allow", "rule": "tagged"}},
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod", "extra": 1},
             "expected": {"effect": "allow", "rule": "tagged"}},
        ]
        self.assertTrue(gate.verify(cases)["ok"])

    def test_validation_error_codes(self):
        gate = self._gate()
        good_expectation = {"effect": "allow", "rule": "read"}
        cases = [
            ("nope", "invalid_cases", None, None),
            (None, "invalid_cases", None, None),
            ({}, "invalid_cases", None, None),
            (42, "invalid_cases", None, None),
            (["x"], "item_not_mapping", 0, None),
            ([None], "item_not_mapping", 0, None),
            ([{"action": "a", "resource": "r",
               "expected": good_expectation}],
             "missing_field", 0, "subject"),
            ([{"subject": "s", "resource": "r",
               "expected": good_expectation}],
             "missing_field", 0, "action"),
            ([{"subject": "s", "action": "a",
               "expected": good_expectation}],
             "missing_field", 0, "resource"),
            ([{"subject": 1, "action": "a", "resource": "r",
               "expected": good_expectation}],
             "invalid_field_type", 0, "subject"),
            ([{"subject": "s", "action": ["a"], "resource": "r",
               "expected": good_expectation}],
             "invalid_field_type", 0, "action"),
            ([{"subject": "s", "action": "a", "resource": 9,
               "expected": good_expectation}],
             "invalid_field_type", 0, "resource"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "bogus": 1, "expected": good_expectation}],
             "unknown_field", 0, "bogus"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "tags": "k=v", "expected": good_expectation}],
             "invalid_field_type", 0, "tags"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "tags": [1], "expected": good_expectation}],
             "invalid_field_type", 0, "tags"),
            ([{"subject": "s", "action": "a", "resource": "r"}],
             "missing_field", 0, "expected"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": "x"}],
             "invalid_field_type", 0, "expected"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": None}],
             "invalid_field_type", 0, "expected"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": {"effect": "allow", "rule": "read", "z": 1}}],
             "unknown_field", 0, "expected.z"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": {}}],
             "missing_field", 0, "expected.effect"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": {"rule": "read"}}],
             "missing_field", 0, "expected.effect"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": {"effect": "allow"}}],
             "missing_field", 0, "expected.rule"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": {"effect": "maybe", "rule": None}}],
             "invalid_expectation", 0, "expected.effect"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": {"effect": None, "rule": None}}],
             "invalid_expectation", 0, "expected.effect"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": {"effect": True, "rule": None}}],
             "invalid_expectation", 0, "expected.effect"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": {"effect": "deny", "rule": 3}}],
             "invalid_expectation", 0, "expected.rule"),
            ([{"subject": "s", "action": "a", "resource": "r",
               "expected": {"effect": "deny", "rule": True}}],
             "invalid_expectation", 0, "expected.rule"),
        ]
        for bad_cases, code, index, field in cases:
            with self.subTest(bad=bad_cases):
                with self.assertRaises(PolicyVerificationError) as ctx:
                    gate.verify(bad_cases)
                self.assertEqual(ctx.exception.code, code)
                self.assertEqual(ctx.exception.index, index)
                self.assertEqual(ctx.exception.field, field)
                self.assertIn(code, str(ctx.exception))

    def test_whole_batch_validated_before_any_decision(self):
        gate = self._gate()
        good = {
            "subject": "alice", "action": "read", "resource": "dev/x",
            "expected": {"effect": "allow", "rule": "read"},
        }
        with self.assertRaises(PolicyVerificationError) as ctx:
            gate.verify([good, "not-a-mapping"])
        self.assertEqual(ctx.exception.code, "item_not_mapping")
        self.assertEqual(ctx.exception.index, 1)
        with self.assertRaises(PolicyVerificationError) as ctx:
            gate.verify(
                [
                    good,
                    {"subject": "s", "action": "a", "resource": "r",
                     "expected": {"effect": "nope", "rule": None}},
                ]
            )
        self.assertEqual(ctx.exception.code, "invalid_expectation")
        self.assertEqual(ctx.exception.field, "expected.effect")

    def test_verify_is_read_only_and_repeatable(self):
        import copy

        gate = self._gate()
        cases = [
            {"subject": "alice", "action": "read", "resource": "dev/x",
             "tags": {"env": "prod"},
             "expected": {"effect": "allow", "rule": "read"}},
            {"subject": "alice", "action": "read", "resource": "prod/db",
             "expected": {"effect": "allow", "rule": "read"}},
            {"subject": "bob", "action": "write", "resource": "x",
             "expected": {"effect": "deny", "rule": None}},
            {"subject": "x", "action": "y", "resource": "z",
             "expected": {"effect": "allow", "rule": "read"}},
        ]
        cases_snapshot = copy.deepcopy(cases)
        rules_snapshot = [dict(r) for r in gate.rules]
        first = gate.verify(cases)
        self.assertEqual(
            [f["index"] for f in first["failures"]], [1, 3]
        )
        for _ in range(20):
            self.assertEqual(gate.verify(copy.deepcopy(cases)), first)
        self.assertEqual(cases, cases_snapshot)
        self.assertEqual([dict(r) for r in gate.rules], rules_snapshot)
        # mutating a returned report never affects later calls
        first["ok"] = True
        first["summary"]["failed"] = 0
        first["failures"][0]["actual"]["rule"] = "tampered"
        first["failures"][0]["expected"]["rule"] = "tampered"
        fresh = gate.verify(cases)
        self.assertFalse(fresh["ok"])
        self.assertEqual(fresh["summary"]["failed"], 2)
        self.assertEqual(
            [f["index"] for f in fresh["failures"]], [1, 3]
        )
        self.assertEqual(fresh["failures"][0]["actual"]["rule"], "prod-lock")
        self.assertEqual(
            fresh["failures"][0]["expected"],
            {"effect": "allow", "rule": "read"},
        )

    def test_from_json_gate_verifies_like_constructor_gate(self):
        gate = self._gate()
        loaded = PolicyGate.from_json(gate.to_json())
        cases = self._cases() + [
            {"subject": "x", "action": "y", "resource": "z",
             "expected": {"effect": "allow", "rule": "read"}},
        ]
        self.assertEqual(loaded.verify(cases), gate.verify(cases))

    def test_verify_does_not_change_other_apis(self):
        gate = self._gate()
        cases = self._cases()
        gate.verify(cases)
        gate.verify(cases)
        self.assertEqual(
            gate.decide("alice", "read", "prod/db")["rule"], "prod-lock"
        )
        self.assertEqual(
            gate.decide("alice", "read", "dev/x")["rule"], "read"
        )
        # existing batch validation is untouched
        with self.assertRaises(PolicyBatchError) as ctx:
            gate.decide_many("nope")
        self.assertEqual(ctx.exception.code, "invalid_batch")


if __name__ == "__main__":
    unittest.main()
