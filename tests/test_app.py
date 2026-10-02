import unittest

from app import PolicyConfigError, PolicyGate


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


if __name__ == "__main__":
    unittest.main()
