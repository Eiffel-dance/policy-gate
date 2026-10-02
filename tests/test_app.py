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
    def test_loads_and_decides_like_constructor(self):
        document = (
            '[{"id": "read", "effect": "allow", "action": "read"},'
            ' {"effect": "deny", "resource": "prod/*", "priority": 3,'
            '  "tags": {"env": "prod"}}]'
        )
        gate = PolicyGate.from_json(document)
        self.assertEqual(gate.rules[1]["id"], "1")
        self.assertEqual(
            gate.decide("alice", "read", "prod/db", {"env": "prod"})["rule"],
            "1",
        )
        self.assertEqual(
            gate.decide("alice", "read", "dev/db")["rule"], "read"
        )
        explanation = gate.explain("alice", "read", "prod/db", {"env": "prod"})
        self.assertEqual(explanation["effect"], "deny")
        self.assertEqual(
            [r["id"] for r in explanation["matched_rules"]], ["read", "1"]
        )

    def test_empty_array_is_default_deny(self):
        gate = PolicyGate.from_json("[]")
        result = gate.decide("s", "a", "r")
        self.assertEqual(result["effect"], "deny")
        self.assertEqual(result["reason"], "default deny")

    def test_non_string_document_raises_type_error(self):
        for bad in (b"[]", 42, None, [{"effect": "allow"}], ("x",)):
            with self.assertRaises(TypeError):
                PolicyGate.from_json(bad)

    def _expect_config_error(self, document, code):
        with self.assertRaises(PolicyConfigError) as ctx:
            PolicyGate.from_json(document)
        self.assertEqual(ctx.exception.code, code)

    def test_invalid_json(self):
        self._expect_config_error("[{", "invalid_json")
        self._expect_config_error("not json", "invalid_json")
        self._expect_config_error("", "invalid_json")

    def test_duplicate_key_at_rule_level(self):
        self._expect_config_error(
            '[{"effect": "allow", "effect": "deny"}]', "duplicate_key"
        )

    def test_duplicate_key_nested_in_tags(self):
        self._expect_config_error(
            '[{"effect": "allow", "tags": {"k": "a", "k": "b"}}]',
            "duplicate_key",
        )

    def test_root_not_array(self):
        for doc in ("{}", '"x"', "1", "null", "true"):
            self._expect_config_error(doc, "root_not_array")

    def test_rule_not_object(self):
        self._expect_config_error('[["effect"]]', "rule_not_object")
        self._expect_config_error('[{"effect": "allow"}, 3]', "rule_not_object")
        self._expect_config_error("[null]", "rule_not_object")

    def test_semantic_errors_stay_value_error_with_index(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(
                '[{"effect": "allow"}, {"id": "bad", "priority": "nope",'
                ' "effect": "allow"}]'
            )
        self.assertNotIsInstance(ctx.exception, PolicyConfigError)
        self.assertIn("rule 1", str(ctx.exception))
        with self.assertRaises(ValueError):
            PolicyGate.from_json('[{"effect": "maybe"}]')
        with self.assertRaises(ValueError):
            PolicyGate.from_json(
                '[{"id": "x", "effect": "allow"},'
                ' {"id": "x", "effect": "deny"}]'
            )
        with self.assertRaises(ValueError):
            PolicyGate.from_json('[{"effect": "allow", "sourc3": 1}]')

    def test_failed_load_leaves_no_instance(self):
        with self.assertRaises(PolicyConfigError):
            PolicyGate.from_json('{"effect": "allow"}')
        # a subsequent valid load is unaffected
        gate = PolicyGate.from_json('[{"effect": "allow"}]')
        self.assertEqual(gate.decide("s", "a", "r")["effect"], "allow")

    def test_constructor_still_accepts_list_and_tuple(self):
        rules = [{"id": "x", "effect": "allow"}]
        self.assertEqual(PolicyGate(rules).decide("s", "a", "r")["rule"], "x")
        self.assertEqual(
            PolicyGate(tuple(rules)).decide("s", "a", "r")["rule"], "x"
        )


if __name__ == "__main__":
    unittest.main()
