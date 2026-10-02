import unittest

from app import PolicyGate


class DecideTest(unittest.TestCase):
    def test_default_deny_when_nothing_matches(self):
        gate = PolicyGate([{"id": "read", "effect": "allow", "action": "read"}])
        result = gate.decide("alice", "write", "db/x")
        self.assertEqual(
            result, {"effect": "deny", "rule": None, "reason": "default deny"}
        )

    def test_empty_rules_default_deny(self):
        self.assertEqual(
            PolicyGate([]).decide("a", "b", "c"),
            {"effect": "deny", "rule": None, "reason": "default deny"},
        )

    def test_default_id_uses_original_index(self):
        gate = PolicyGate(
            [
                {"effect": "allow", "action": "read"},
                {"effect": "deny", "id": "lock", "resource": "locked/*"},
                {"effect": "allow", "action": "*"},
            ]
        )
        result = gate.decide("alice", "write", "x")
        self.assertEqual(result["effect"], "allow")
        self.assertEqual(result["rule"], "2")
        self.assertIn("'2'", result["reason"])

    def test_multiple_allows_higher_priority_wins(self):
        gate = PolicyGate(
            [
                {"id": "low", "effect": "allow", "priority": 1},
                {"id": "high", "effect": "allow", "priority": 10},
            ]
        )
        result = gate.decide("a", "b", "c")
        self.assertEqual(result["effect"], "allow")
        self.assertEqual(result["rule"], "high")
        self.assertIn("allow", result["reason"])
        self.assertIn("high", result["reason"])
        self.assertIn("10", result["reason"])

    def test_equal_priority_keeps_declaration_order(self):
        gate = PolicyGate(
            [
                {"id": "first", "effect": "allow"},
                {"id": "second", "effect": "allow"},
            ]
        )
        self.assertEqual(gate.decide("a", "b", "c")["rule"], "first")

    def test_negative_priority_allowed(self):
        gate = PolicyGate(
            [
                {"id": "neg", "effect": "allow", "priority": -5},
            ]
        )
        result = gate.decide("a", "b", "c")
        self.assertEqual(result["rule"], "neg")
        self.assertIn("-5", result["reason"])

    def test_deny_overrides_allow_regardless_of_priority(self):
        gate = PolicyGate(
            [
                {"id": "big-allow", "effect": "allow", "priority": 1000},
                {"id": "tiny-deny", "effect": "deny", "priority": -1000},
            ]
        )
        result = gate.decide("a", "b", "c")
        self.assertEqual(result["effect"], "deny")
        self.assertEqual(result["rule"], "tiny-deny")
        self.assertIn("deny", result["reason"])
        self.assertIn("tiny-deny", result["reason"])
        self.assertIn("overrides", result["reason"])

    def test_multiple_denies_resolve_by_priority_then_order(self):
        gate = PolicyGate(
            [
                {"id": "d-low", "effect": "deny", "priority": 1},
                {"id": "d-high", "effect": "deny", "priority": 9},
                {"id": "d-tie", "effect": "deny", "priority": 9},
            ]
        )
        self.assertEqual(gate.decide("a", "b", "c")["rule"], "d-high")

    def test_wildcards_case_sensitive_fnmatch(self):
        gate = PolicyGate(
            [{"id": "r", "effect": "allow", "resource": "prod/*"}]
        )
        self.assertEqual(gate.decide("a", "b", "prod/db")["effect"], "allow")
        self.assertEqual(gate.decide("a", "b", "PROD/db")["effect"], "deny")

    def test_tags_subset_match(self):
        gate = PolicyGate(
            [{"id": "t", "effect": "allow", "tags": {"env": "prod"}}]
        )
        self.assertEqual(
            gate.decide("a", "b", "c", {"env": "prod", "team": "x"})["effect"],
            "allow",
        )
        self.assertEqual(
            gate.decide("a", "b", "c", {"env": "dev"})["effect"], "deny"
        )

    def test_tags_none_means_empty(self):
        gate = PolicyGate(
            [{"id": "t", "effect": "allow", "tags": {}}]
        )
        self.assertEqual(gate.decide("a", "b", "c")["rule"], "t")

    def test_result_keys_stable(self):
        gate = PolicyGate([{"id": "r", "effect": "allow"}])
        self.assertEqual(
            set(gate.decide("a", "b", "c").keys()), {"effect", "rule", "reason"}
        )
        self.assertEqual(
            set(gate.decide("x", "y", "z").keys()), {"effect", "rule", "reason"}
        )

    def test_decision_independent_of_dict_iteration_order(self):
        # 无论规则/标签字典如何构造，同一配置裁决必须可复现。
        rules = [
            {"id": "r%d" % i, "effect": "allow" if i % 2 else "deny",
             "priority": i, "tags": {"k%d" % i: "v%d" % i}}
            for i in range(20)
        ]
        first = PolicyGate(rules).decide("a", "b", "c")
        for _ in range(5):
            self.assertEqual(PolicyGate(rules).decide("a", "b", "c"), first)


class LoadingValidationTest(unittest.TestCase):
    def assertRejects(self, rules, index, field=None):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate(rules)
        message = str(ctx.exception)
        self.assertIn("index %d" % index, message)
        if field is not None:
            self.assertIn(field, message)

    def test_rules_must_be_sequence(self):
        with self.assertRaises(ValueError):
            PolicyGate({"id": "r", "effect": "allow"})

    def test_rule_must_be_mapping(self):
        self.assertRejects(["not-a-rule"], 0)

    def test_invalid_effect(self):
        self.assertRejects(
            [{"id": "ok", "effect": "allow"}, {"effect": "maybe"}], 1, "effect"
        )

    def test_missing_effect(self):
        self.assertRejects([{"id": "r"}], 0, "effect")

    def test_empty_or_nonstring_id(self):
        self.assertRejects([{"effect": "allow", "id": ""}], 0, "id")
        self.assertRejects([{"effect": "allow", "id": 1}], 0, "id")

    def test_duplicate_id(self):
        self.assertRejects(
            [
                {"id": "x", "effect": "allow"},
                {"id": "x", "effect": "deny"},
            ],
            1,
            "id",
        )

    def test_invalid_priority(self):
        self.assertRejects(
            [{"effect": "allow", "priority": 1.5}], 0, "priority"
        )
        self.assertRejects(
            [{"effect": "allow", "priority": True}], 0, "priority"
        )
        self.assertRejects(
            [{"effect": "allow", "priority": "1"}], 0, "priority"
        )

    def test_invalid_match_fields(self):
        self.assertRejects(
            [{"effect": "allow", "subject": 1}], 0, "subject"
        )
        self.assertRejects(
            [{"effect": "allow", "action": ["read"]}], 0, "action"
        )
        self.assertRejects(
            [{"effect": "allow", "resource": None}], 0, "resource"
        )

    def test_invalid_tags(self):
        self.assertRejects([{"effect": "allow", "tags": []}], 0, "tags")
        self.assertRejects(
            [{"effect": "allow", "tags": {1: "v"}}], 0, "tags"
        )

    def test_unsupported_field(self):
        self.assertRejects(
            [{"effect": "allow", "unexpected": True}], 0, "unexpected"
        )

    def test_first_violating_rule_reported(self):
        self.assertRejects(
            [
                {"effect": "allow"},
                {"id": "ok", "effect": "allow"},
                {"effect": "allow", "priority": "nope"},
            ],
            2,
            "priority",
        )


class DecideTypeTest(unittest.TestCase):
    def setUp(self):
        self.gate = PolicyGate([{"id": "r", "effect": "allow"}])

    def test_nonstring_inputs_raise_type_error(self):
        with self.assertRaises(TypeError):
            self.gate.decide(1, "b", "c")
        with self.assertRaises(TypeError):
            self.gate.decide("a", None, "c")
        with self.assertRaises(TypeError):
            self.gate.decide("a", "b", object())

    def test_invalid_tags_raise_type_error(self):
        with self.assertRaises(TypeError):
            self.gate.decide("a", "b", "c", tags=[("k", "v")])
        with self.assertRaises(TypeError):
            self.gate.decide("a", "b", "c", tags="env=prod")


if __name__ == "__main__":
    unittest.main()
