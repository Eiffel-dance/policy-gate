import unittest

from app import PolicyBatchError, PolicyConfigError, PolicyGate


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


class CoverageTest(unittest.TestCase):
    def _gate(self):
        return PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read"},
                {"id": "prod-lock", "effect": "deny", "resource": "prod/*"},
                {"id": "tagged", "effect": "allow", "tags": {"env": "dev"}},
                {"id": "never", "effect": "allow", "subject": "nobody"},
            ]
        )

    def _requests(self):
        return [
            {"subject": "alice", "action": "read", "resource": "dev/x"},
            {"subject": "alice", "action": "read", "resource": "prod/db"},
            {"subject": "bob", "action": "write", "resource": "x",
             "tags": {"env": "dev"}},
            {"subject": "carol", "action": "write", "resource": "y"},
        ]

    def test_report_structure_and_rule_order(self):
        report = self._gate().coverage(self._requests())
        self.assertEqual(set(report), {"rules", "summary"})
        self.assertEqual(
            [r["id"] for r in report["rules"]],
            ["read", "prod-lock", "tagged", "never"],
        )
        for rule in report["rules"]:
            self.assertEqual(set(rule), {"id", "effect", "matched", "winner"})
        self.assertEqual(
            [(r["id"], r["effect"]) for r in report["rules"]],
            [
                ("read", "allow"),
                ("prod-lock", "deny"),
                ("tagged", "allow"),
                ("never", "allow"),
            ],
        )
        self.assertEqual(
            set(report["summary"]),
            {"total", "allow", "explicit_deny", "default_deny", "matched_request"},
        )

    def test_counts_matched_vs_winner_and_summary(self):
        report = self._gate().coverage(self._requests())
        by_id = {r["id"]: r for r in report["rules"]}
        # request 0: read matches -> allow winner read
        # request 1: read + prod-lock match -> explicit deny wins
        # request 2: tagged matches (env=dev) -> allow winner tagged
        # request 3: no match -> default deny
        self.assertEqual(by_id["read"]["matched"], 2)
        self.assertEqual(by_id["read"]["winner"], 1)
        self.assertEqual(by_id["prod-lock"]["matched"], 1)
        self.assertEqual(by_id["prod-lock"]["winner"], 1)
        self.assertEqual(by_id["tagged"]["matched"], 1)
        self.assertEqual(by_id["tagged"]["winner"], 1)
        self.assertEqual(by_id["never"]["matched"], 0)
        self.assertEqual(by_id["never"]["winner"], 0)
        self.assertEqual(
            report["summary"],
            {
                "total": 4,
                "allow": 2,
                "explicit_deny": 1,
                "default_deny": 1,
                "matched_request": 3,
            },
        )

    def test_winner_sum_equals_matched_request(self):
        gate = self._gate()
        requests = self._requests() * 3
        report = gate.coverage(requests)
        self.assertEqual(sum(r["winner"] for r in report["rules"]),
                         report["summary"]["matched_request"])
        self.assertEqual(sum(r["matched"] for r in report["rules"]), 12)
        summary = report["summary"]
        self.assertEqual(
            summary["total"],
            summary["allow"] + summary["explicit_deny"]
            + summary["default_deny"],
        )

    def test_explicit_deny_beats_matching_allows(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow", "priority": 100},
                {"id": "a2", "effect": "allow"},
                {"id": "d1", "effect": "deny", "priority": -5},
            ]
        )
        report = gate.coverage(
            [{"subject": "s", "action": "a", "resource": "r"}]
        )
        for rule in report["rules"]:
            self.assertEqual(rule["matched"], 1)
        by_id = {r["id"]: r for r in report["rules"]}
        self.assertEqual(by_id["d1"]["winner"], 1)
        self.assertEqual(by_id["a1"]["winner"], 0)
        self.assertEqual(by_id["a2"]["winner"], 0)
        self.assertEqual(
            report["summary"],
            {"total": 1, "allow": 0, "explicit_deny": 1,
             "default_deny": 0, "matched_request": 1},
        )

    def test_priority_then_declaration_order_picks_winner(self):
        gate = PolicyGate(
            [
                {"id": "low", "effect": "allow", "priority": 1},
                {"id": "high", "effect": "allow", "priority": 9},
                {"id": "mid", "effect": "allow", "priority": 9},
            ]
        )
        report = gate.coverage(
            [{"subject": "s", "action": "a", "resource": "r"}]
        )
        by_id = {r["id"]: r for r in report["rules"]}
        # all three match; high (priority 9, declared before mid) wins
        self.assertTrue(all(r["matched"] == 1 for r in report["rules"]))
        self.assertEqual(by_id["high"]["winner"], 1)
        self.assertEqual(by_id["low"]["winner"], 0)
        self.assertEqual(by_id["mid"]["winner"], 0)
        self.assertEqual(report["summary"]["allow"], 1)

    def test_empty_batch_lists_rules_with_zero_counts(self):
        report = self._gate().coverage([])
        self.assertEqual(
            [r["id"] for r in report["rules"]],
            ["read", "prod-lock", "tagged", "never"],
        )
        self.assertTrue(
            all(r["matched"] == 0 and r["winner"] == 0 for r in report["rules"])
        )
        self.assertEqual(
            report["summary"],
            {"total": 0, "allow": 0, "explicit_deny": 0,
             "default_deny": 0, "matched_request": 0},
        )
        # no rules at all still returns a well-formed report
        self.assertEqual(
            PolicyGate([]).coverage([]),
            {"rules": [],
             "summary": {"total": 0, "allow": 0, "explicit_deny": 0,
                         "default_deny": 0, "matched_request": 0}},
        )

    def test_empty_rule_set_counts_default_deny_per_request(self):
        report = PolicyGate([]).coverage(self._requests())
        self.assertEqual(report["rules"], [])
        self.assertEqual(
            report["summary"],
            {"total": 4, "allow": 0, "explicit_deny": 0,
             "default_deny": 4, "matched_request": 0},
        )

    def test_tuple_batch_accepted(self):
        report = self._gate().coverage(tuple(self._requests()))
        self.assertEqual(report["summary"]["total"], 4)

    def test_tags_and_fnmatch_case_sensitivity(self):
        gate = PolicyGate(
            [{"id": "r", "effect": "allow", "action": "read",
              "tags": {"env": "prod"}}]
        )
        report = gate.coverage(
            [
                {"subject": "s", "action": "read", "resource": "x",
                 "tags": {"env": "prod"}},
                {"subject": "s", "action": "READ", "resource": "x",
                 "tags": {"env": "prod"}},
                {"subject": "s", "action": "read", "resource": "x",
                 "tags": {"env": "dev"}},
                {"subject": "s", "action": "read", "resource": "x"},
            ]
        )
        rule = report["rules"][0]
        self.assertEqual(rule["matched"], 1)
        self.assertEqual(rule["winner"], 1)
        self.assertEqual(report["summary"]["allow"], 1)
        self.assertEqual(report["summary"]["default_deny"], 3)

    def test_agrees_with_decide_and_explain(self):
        gate = self._gate()
        requests = self._requests()
        report = gate.coverage(requests)
        matched_total = [0] * len(gate.rules)
        winner_by_id = {}
        effects = {"allow": 0, "deny": 0}
        matched_request = 0
        for item in requests:
            decision = gate.decide(
                item["subject"], item["action"], item["resource"],
                item.get("tags"),
            )
            explanation = gate.explain(
                item["subject"], item["action"], item["resource"],
                item.get("tags"),
            )
            if explanation["matched_rules"]:
                matched_request += 1
            for matched in explanation["matched_rules"]:
                idx = next(
                    i for i, r in enumerate(gate.rules)
                    if r["id"] == matched["id"]
                )
                matched_total[idx] += 1
            winner_by_id[decision["rule"]] = (
                winner_by_id.get(decision["rule"], 0) + 1
            )
            effects[decision["effect"]] += 1

        for i, rule in enumerate(report["rules"]):
            self.assertEqual(rule["matched"], matched_total[i])
            self.assertEqual(rule["winner"], winner_by_id.get(rule["id"], 0))
        self.assertEqual(report["summary"]["matched_request"], matched_request)
        self.assertEqual(report["summary"]["allow"], effects["allow"])
        self.assertEqual(
            report["summary"]["explicit_deny"]
            + report["summary"]["default_deny"],
            effects["deny"],
        )

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
                with self.assertRaises(PolicyBatchError) as cov_ctx:
                    gate.coverage(requests)
                with self.assertRaises(PolicyBatchError) as dm_ctx:
                    gate.decide_many(requests)
                for ctx in (cov_ctx, dm_ctx):
                    self.assertEqual(ctx.exception.code, code)
                    self.assertEqual(ctx.exception.index, index)
                    self.assertEqual(ctx.exception.field, field)

    def test_first_error_aborts_with_no_partial_report(self):
        gate = self._gate()
        good = {"subject": "s", "action": "a", "resource": "r"}
        with self.assertRaises(PolicyBatchError) as ctx:
            gate.coverage([good, {"subject": "s", "bogus": 1}])
        self.assertEqual(ctx.exception.index, 1)
        self.assertEqual(ctx.exception.code, "unknown_field")

    def test_read_only_repeatable_and_fresh_result(self):
        import copy

        gate = self._gate()
        requests = self._requests()
        requests_snapshot = copy.deepcopy(requests)
        rules_snapshot = [dict(r) for r in gate.rules]
        first = gate.coverage(requests)
        for _ in range(20):
            self.assertEqual(
                gate.coverage(copy.deepcopy(requests)), first
            )
        self.assertEqual(requests, requests_snapshot)
        self.assertEqual([dict(r) for r in gate.rules], rules_snapshot)
        # mutating a returned report must not affect later reports
        first["rules"][0]["matched"] = 999
        first["rules"].append(
            {"id": "tampered", "effect": "deny", "matched": 1, "winner": 1}
        )
        fresh = gate.coverage(requests)
        self.assertEqual(len(fresh["rules"]), 4)
        self.assertEqual(fresh["rules"][0]["matched"], 2)

    def test_coverage_does_not_change_decisions(self):
        gate = self._gate()
        requests = self._requests()
        before = gate.decide_many(requests)
        gate.coverage(requests)
        gate.coverage([])
        self.assertEqual(gate.decide_many(requests), before)


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


if __name__ == "__main__":
    unittest.main()
