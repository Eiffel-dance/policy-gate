import unittest

from app import PolicyGate


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


if __name__ == "__main__":
    unittest.main()
