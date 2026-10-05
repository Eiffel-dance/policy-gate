import unittest

from app import PolicyBatchError, PolicyConfigError, PolicyGate, PolicyVerificationError


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

    def test_root_not_array_or_object(self):
        for bad in ("5", '"str"', "true", "null"):
            self._expect_code(bad, "root_not_array_or_object")

    def test_root_object_with_unknown_field(self):
        self._expect_code('{"effect": "allow"}', "unknown_document_field")

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


class VersionedDocumentTest(unittest.TestCase):
    RULES = (
        '[{"id": "read", "effect": "allow", "action": "read", '
        '"resource": "docs/*"},'
        '{"effect": "deny", "resource": "secret/*", "tags": {"env": "prod"}}]'
    )

    def _fingerprint(self, rules_text):
        # the document digest commits to the canonical rules snapshot,
        # not to the raw text as written in the document
        return PolicyGate.from_json(rules_text).fingerprint()

    def _document(self, rules_text=None, fingerprint=None):
        if rules_text is None:
            rules_text = self.RULES
        if fingerprint is None:
            fingerprint = self._fingerprint(rules_text)
        return (
            '{"version": 1, "rules": %s, "fingerprint": "%s"}'
            % (rules_text, fingerprint)
        )

    def _expect_code(self, document, code):
        with self.assertRaises(PolicyConfigError) as ctx:
            PolicyGate.from_json(document)
        self.assertEqual(ctx.exception.code, code)
        self.assertIn(code, str(ctx.exception))

    # --- successful loads ---------------------------------------------

    def test_versioned_document_loads_and_decides_like_legacy(self):
        versioned = PolicyGate.from_json(self._document())
        legacy = PolicyGate.from_json(self.RULES)
        self.assertEqual(versioned.document_version, 1)
        self.assertIsNone(legacy.document_version)
        for args in (
            ("alice", "read", "docs/a", None),
            ("alice", "read", "secret/x", None),
            ("bob", "write", "x", {"env": "prod"}),
            ("bob", "write", "x", {"env": "dev"}),
        ):
            self.assertEqual(versioned.decide(*args), legacy.decide(*args))
            self.assertEqual(versioned.explain(*args), legacy.explain(*args))
            self.assertEqual(versioned.trace(*args), legacy.trace(*args))
        self.assertEqual(versioned.audit(), legacy.audit())
        self.assertEqual(versioned.fingerprint(), legacy.fingerprint())

    def test_fingerprint_field_is_optional(self):
        gate = PolicyGate.from_json('{"version": 1, "rules": %s}' % self.RULES)
        self.assertEqual(gate.document_version, 1)
        self.assertEqual(gate.decide("s", "read", "docs/a")["effect"], "allow")

    def test_empty_rules_versioned_document(self):
        gate = PolicyGate.from_json('{"version": 1, "rules": []}')
        self.assertEqual(gate.document_version, 1)
        self.assertEqual(gate.rules, [])
        self.assertEqual(gate.decide("s", "a", "r")["reason"], "default deny")

    def test_direct_construction_has_no_document_version(self):
        gate = PolicyGate([{"effect": "allow"}])
        self.assertIsNone(gate.document_version)

    # --- canonical export ----------------------------------------------

    def test_to_json_emits_fixed_order_envelope(self):
        gate = PolicyGate.from_json(self._document())
        expected_rules = PolicyGate.from_json(self.RULES).to_json()
        expected = (
            '{"version":1,"rules":%s,"fingerprint":"%s"}'
            % (expected_rules, self._fingerprint(expected_rules))
        )
        self.assertEqual(gate.to_json(), expected)

    def test_to_json_preserves_provided_fingerprint(self):
        document = self._document()
        gate = PolicyGate.from_json(document)
        # the provided digest is the canonical one, so the export carries
        # it back verbatim inside the envelope
        self.assertIn(
            '"fingerprint":"%s"' % self._fingerprint(
                PolicyGate.from_json(self.RULES).to_json()
            ),
            gate.to_json(),
        )

    def test_to_json_without_input_fingerprint_computes_it(self):
        gate = PolicyGate.from_json('{"version": 1, "rules": %s}' % self.RULES)
        self.assertEqual(
            gate.to_json(),
            '{"version":1,"rules":%s,"fingerprint":"%s"}'
            % (
                PolicyGate.from_json(self.RULES).to_json(),
                gate.fingerprint(),
            ),
        )

    def test_legacy_and_constructor_to_json_stay_bare_arrays(self):
        rules = [{"id": "a", "effect": "allow"}]
        self.assertIsNone(PolicyGate(rules).document_version)
        self.assertEqual(
            PolicyGate(rules).to_json(),
            PolicyGate.from_json('[{"id": "a", "effect": "allow"}]').to_json(),
        )
        self.assertTrue(PolicyGate(rules).to_json().startswith("["))

    def test_versioned_roundtrip_is_byte_identical(self):
        gate = PolicyGate.from_json(self._document())
        reloaded = PolicyGate.from_json(gate.to_json())
        self.assertEqual(reloaded.document_version, 1)
        self.assertEqual(reloaded.to_json(), gate.to_json())
        self.assertEqual(reloaded.fingerprint(), gate.fingerprint())

    def test_versioned_roundtrip_preserves_all_behaviors(self):
        gate = PolicyGate.from_json(self._document())
        reloaded = PolicyGate.from_json(gate.to_json())
        requests = [
            {"subject": "alice", "action": "read", "resource": "docs/a"},
            {"subject": "alice", "action": "read", "resource": "secret/x",
             "tags": {"env": "prod"}},
            {"subject": "bob", "action": "write", "resource": "x"},
        ]
        for request in requests:
            args = (request["subject"], request["action"],
                    request["resource"], request.get("tags"))
            self.assertEqual(reloaded.decide(*args), gate.decide(*args))
            self.assertEqual(reloaded.explain(*args), gate.explain(*args))
            self.assertEqual(reloaded.trace(*args), gate.trace(*args))
            self.assertEqual(reloaded.diagnose(*args), gate.diagnose(*args))
        self.assertEqual(reloaded.decide_many(requests),
                         gate.decide_many(requests))
        self.assertEqual(reloaded.trace_many(requests),
                         gate.trace_many(requests))
        self.assertEqual(reloaded.audit(), gate.audit())
        self.assertEqual(reloaded.coverage(requests), gate.coverage(requests))
        candidate = PolicyGate.from_json(self.RULES)
        self.assertEqual(reloaded.compare(candidate, requests),
                         gate.compare(candidate, requests))
        self.assertEqual(reloaded.rule_change_report(candidate),
                         gate.rule_change_report(candidate))

    # --- envelope errors, in precedence order ---------------------------

    def test_unknown_document_field(self):
        self._expect_code(
            '{"version": 1, "rules": [], "bogus": 1}',
            "unknown_document_field",
        )
        self._expect_code('{"Rules": []}', "unknown_document_field")

    def test_unknown_field_wins_over_missing_version(self):
        self._expect_code('{"bogus": 1}', "unknown_document_field")

    def test_missing_version(self):
        self._expect_code('{"rules": []}', "missing_version")

    def test_missing_version_wins_over_rules_problems(self):
        self._expect_code('{"rules": 5}', "missing_version")

    def test_invalid_version(self):
        for bad in ('{"version": "1", "rules": []}',
                    '{"version": 1.0, "rules": []}',
                    '{"version": true, "rules": []}',
                    '{"version": null, "rules": []}',
                    '{"version": [1], "rules": []}'):
            self._expect_code(bad, "invalid_version")

    def test_invalid_version_wins_over_missing_rules(self):
        self._expect_code('{"version": "1"}', "invalid_version")

    def test_unsupported_version(self):
        self._expect_code('{"version": 0, "rules": []}', "unsupported_version")
        self._expect_code('{"version": 2, "rules": []}', "unsupported_version")
        self._expect_code('{"version": -1, "rules": []}', "unsupported_version")

    def test_unsupported_version_wins_over_missing_rules(self):
        self._expect_code('{"version": 2}', "unsupported_version")

    def test_missing_rules(self):
        self._expect_code('{"version": 1}', "missing_rules")

    def test_missing_rules_wins_over_fingerprint_problems(self):
        self._expect_code(
            '{"version": 1, "fingerprint": "nope"}', "missing_rules"
        )

    def test_rules_not_array(self):
        for bad in ('{"version": 1, "rules": {}}',
                    '{"version": 1, "rules": 5}',
                    '{"version": 1, "rules": "rules"}',
                    '{"version": 1, "rules": null}'):
            self._expect_code(bad, "rules_not_array")

    def test_rules_not_array_wins_over_fingerprint_problems(self):
        self._expect_code(
            '{"version": 1, "rules": {}, "fingerprint": "nope"}',
            "rules_not_array",
        )

    def test_invalid_fingerprint(self):
        good = self._fingerprint(self.RULES)
        for bad_value in (
            '"%s"' % good.upper(),          # uppercase hex
            '"%s"' % good[:-1],             # too short
            '"%sg"' % good[:-1],            # non-hex character
            '"%s"' % (good + "0"),          # too long
            '""',                           # empty
            "5",                            # non-string
            "null",                         # explicit null
            "true",
            "[%s]" % ", ".join('"%s"' % c for c in good[:4]),
        ):
            self._expect_code(
                '{"version": 1, "rules": %s, "fingerprint": %s}'
                % (self.RULES, bad_value),
                "invalid_fingerprint",
            )

    def test_fingerprint_mismatch(self):
        other = self._fingerprint("[]")
        self._expect_code(
            '{"version": 1, "rules": %s, "fingerprint": "%s"}'
            % (self.RULES, other),
            "fingerprint_mismatch",
        )

    def test_fingerprint_mismatch_after_swap(self):
        # a well-formed digest committing to different rules is rejected
        digest = self._fingerprint('[{"effect": "allow"}]')
        self._expect_code(
            '{"version": 1, "rules": [{"effect": "deny"}], '
            '"fingerprint": "%s"}' % digest,
            "fingerprint_mismatch",
        )

    # --- interaction with existing validation ---------------------------

    def test_duplicate_key_in_document_object(self):
        self._expect_code(
            '{"version": 1, "version": 1, "rules": []}', "duplicate_key"
        )
        self._expect_code(
            '{"version": 1, "rules": [], "rules": []}', "duplicate_key"
        )

    def test_rule_not_object_inside_versioned_document(self):
        self._expect_code(
            '{"version": 1, "rules": [{"effect": "allow"}, 5]}',
            "rule_not_object",
        )

    def test_semantic_rule_errors_stay_value_errors(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(
                '{"version": 1, "rules": [{"id": "x"}]}'
            )
        self.assertNotIsInstance(ctx.exception, PolicyConfigError)

    def test_failed_versioned_load_leaves_no_instance(self):
        for document in (
            '{"version": 2, "rules": []}',
            '{"version": 1, "rules": [], "fingerprint": "bad"}',
            self._document(fingerprint=self._fingerprint("[]")),
        ):
            with self.assertRaises(PolicyConfigError):
                PolicyGate.from_json(document)


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
    def setUp(self):
        self.gate = PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read"},
                {"id": "prod-lock", "effect": "deny", "resource": "prod/*"},
            ]
        )
        self.cases = [
            {"subject": "alice", "action": "read", "resource": "dev/x",
             "expected": {"effect": "allow", "rule": "read"}},
            {"subject": "alice", "action": "read", "resource": "prod/db",
             "expected": {"effect": "deny", "rule": "prod-lock"}},
            {"subject": "bob", "action": "write", "resource": "x",
             "expected": {"effect": "deny", "rule": None}},
        ]

    def test_all_pass_structure(self):
        report = self.gate.verify(self.cases)
        self.assertEqual(set(report), {"ok", "failures", "summary"})
        self.assertEqual(
            report["summary"], {"total": 3, "passed": 3, "failed": 0}
        )
        self.assertTrue(report["ok"])
        self.assertEqual(report["failures"], [])

    def test_empty_batch(self):
        self.assertEqual(
            self.gate.verify([]),
            {
                "ok": True,
                "failures": [],
                "summary": {"total": 0, "passed": 0, "failed": 0},
            },
        )
        self.assertTrue(self.gate.verify(())["ok"])

    def test_tuple_batch_accepted(self):
        report = self.gate.verify(tuple(self.cases))
        self.assertTrue(report["ok"])
        self.assertEqual(report["summary"]["total"], 3)

    def test_failure_counts_and_order(self):
        cases = [
            {"subject": "alice", "action": "read", "resource": "dev/x",
             "expected": {"effect": "allow", "rule": "other"}},
            self.cases[0],
            {"subject": "alice", "action": "read", "resource": "dev/x",
             "expected": {"effect": "deny", "rule": None}},
        ]
        report = self.gate.verify(cases)
        self.assertFalse(report["ok"])
        self.assertEqual(
            report["summary"], {"total": 3, "passed": 1, "failed": 2}
        )
        self.assertEqual([f["index"] for f in report["failures"]], [0, 2])
        first, second = report["failures"]
        self.assertEqual(set(first), {"index", "expected", "actual"})
        self.assertEqual(first["expected"], {"effect": "allow", "rule": "other"})
        self.assertEqual(
            first["actual"],
            self.gate.decide("alice", "read", "dev/x"),
        )
        self.assertEqual(second["actual"]["effect"], "allow")

    def test_reason_does_not_participate(self):
        # effect+rule equal but reason differs is still a pass; actual is
        # nevertheless the complete decision including reason
        report = self.gate.verify(
            [
                {"subject": "alice", "action": "read", "resource": "dev/x",
                 "expected": {"effect": "allow", "rule": "read"}},
            ]
        )
        self.assertTrue(report["ok"])
        # force a failure and inspect the carried full decision
        bad = self.gate.verify(
            [
                {"subject": "alice", "action": "read", "resource": "dev/x",
                 "expected": {"effect": "deny", "rule": None}},
            ]
        )
        actual = bad["failures"][0]["actual"]
        self.assertEqual(
            actual,
            {"effect": "allow", "rule": "read",
             "reason": "matched allow rule 'read' (priority 0)"},
        )

    def test_same_effect_different_rule_fails(self):
        gate = PolicyGate(
            [
                {"id": "low", "effect": "allow", "priority": 1},
                {"id": "high", "effect": "allow", "priority": 9},
            ]
        )
        report = gate.verify(
            [
                {"subject": "s", "action": "a", "resource": "r",
                 "expected": {"effect": "allow", "rule": "low"}},
            ]
        )
        self.assertFalse(report["ok"])
        self.assertEqual(report["failures"][0]["actual"]["rule"], "high")

    def test_default_deny_expectation(self):
        report = self.gate.verify(
            [
                {"subject": "bob", "action": "write", "resource": "x",
                 "expected": {"effect": "deny", "rule": None}},
            ]
        )
        self.assertTrue(report["ok"])
        # expecting a rule id on a default-deny request fails
        bad = self.gate.verify(
            [
                {"subject": "bob", "action": "write", "resource": "x",
                 "expected": {"effect": "deny", "rule": "read"}},
            ]
        )
        self.assertFalse(bad["ok"])
        self.assertIsNone(bad["failures"][0]["actual"]["rule"])

    def test_tags_omitted_none_and_mapping(self):
        gate = PolicyGate(
            [{"id": "tagged", "effect": "allow", "tags": {"env": "prod"}}]
        )
        cases = [
            {"subject": "s", "action": "a", "resource": "r",
             "expected": {"effect": "deny", "rule": None}},
            {"subject": "s", "action": "a", "resource": "r", "tags": None,
             "expected": {"effect": "deny", "rule": None}},
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod"},
             "expected": {"effect": "allow", "rule": "tagged"}},
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod", "extra": 1},
             "expected": {"effect": "allow", "rule": "tagged"}},
        ]
        self.assertTrue(gate.verify(cases)["ok"])

    def test_explicit_deny_and_priority_semantics(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow", "priority": 100},
                {"id": "d1", "effect": "deny", "priority": -5},
            ]
        )
        report = gate.verify(
            [
                {"subject": "s", "action": "a", "resource": "r",
                 "expected": {"effect": "deny", "rule": "d1"}},
            ]
        )
        self.assertTrue(report["ok"])

    def test_fnmatch_case_sensitive(self):
        gate = PolicyGate(
            [{"id": "a", "effect": "allow", "action": "read"}]
        )
        self.assertTrue(
            gate.verify(
                [
                    {"subject": "s", "action": "read", "resource": "r",
                     "expected": {"effect": "allow", "rule": "a"}},
                    {"subject": "s", "action": "READ", "resource": "r",
                     "expected": {"effect": "deny", "rule": None}},
                ]
            )["ok"]
        )

    # --- validation --------------------------------------------------

    def _expect_error(self, cases, code, index, field):
        with self.assertRaises(PolicyVerificationError) as ctx:
            self.gate.verify(cases)
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(ctx.exception.index, index)
        self.assertEqual(ctx.exception.field, field)
        self.assertIn(code, str(ctx.exception))

    def test_invalid_batch_type(self):
        for bad in ("nope", None, 1, 1.5, set(), True, {}):
            self._expect_error(bad, "invalid_cases", None, None)

    def test_item_not_mapping(self):
        self._expect_error(["x"], "item_not_mapping", 0, None)
        self._expect_error([42], "item_not_mapping", 0, None)
        self._expect_error([None], "item_not_mapping", 0, None)
        good = {
            "subject": "s", "action": "a", "resource": "r",
            "expected": {"effect": "allow", "rule": None},
        }
        self._expect_error([good, ["not", "mapping"]], "item_not_mapping", 1, None)

    def test_unknown_field(self):
        self._expect_error(
            [
                {
                    "subject": "s", "action": "a", "resource": "r",
                    "expected": {"effect": "allow", "rule": None},
                    "bogus": 1,
                }
            ],
            "unknown_field", 0, "bogus",
        )

    def test_missing_required_fields(self):
        self._expect_error(
            [{"action": "a", "resource": "r",
              "expected": {"effect": "allow", "rule": None}}],
            "missing_field", 0, "subject",
        )
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r"}],
            "missing_field", 0, "expected",
        )

    def test_invalid_field_types(self):
        self._expect_error(
            [{"subject": 1, "action": "a", "resource": "r",
              "expected": {"effect": "allow", "rule": None}}],
            "invalid_field_type", 0, "subject",
        )
        self._expect_error(
            [{"subject": None, "action": "a", "resource": "r",
              "expected": {"effect": "allow", "rule": None}}],
            "invalid_field_type", 0, "subject",
        )
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r", "tags": "k=v",
              "expected": {"effect": "allow", "rule": None}}],
            "invalid_field_type", 0, "tags",
        )
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": "x"}],
            "invalid_field_type", 0, "expected",
        )
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": None}],
            "invalid_field_type", 0, "expected",
        )

    def test_invalid_expectation_values(self):
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": "maybe", "rule": None}}],
            "invalid_expectation", 0, "expected.effect",
        )
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": None, "rule": None}}],
            "invalid_expectation", 0, "expected.effect",
        )
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": True, "rule": None}}],
            "invalid_expectation", 0, "expected.effect",
        )
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": "allow", "rule": 3}}],
            "invalid_expectation", 0, "expected.rule",
        )
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": "allow", "rule": True}}],
            "invalid_expectation", 0, "expected.rule",
        )

    def test_nested_expectation_fields(self):
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": "allow", "rule": None, "x": 1}}],
            "unknown_field", 0, "expected.x",
        )
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"rule": None}}],
            "missing_field", 0, "expected.effect",
        )
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": "allow"}}],
            "missing_field", 0, "expected.rule",
        )

    def test_error_precedence_within_item(self):
        # unknown top-level beats everything
        self._expect_error(
            [{"subject": 1, "bogus": 1,
              "expected": {"effect": "bad"}}],
            "unknown_field", 0, "bogus",
        )
        # missing top-level beats a bad type
        self._expect_error(
            [{"subject": 1, "action": "a",
              "expected": {"effect": "allow", "rule": None}}],
            "missing_field", 0, "resource",
        )
        # field type beats invalid expectation value
        self._expect_error(
            [{"subject": 1, "action": "a", "resource": "r",
              "expected": {"effect": "bad", "rule": None}}],
            "invalid_field_type", 0, "subject",
        )
        # nested missing beats invalid value too
        self._expect_error(
            [{"subject": "s", "action": "a", "resource": "r",
              "expected": {"effect": "bad"}}],
            "missing_field", 0, "expected.rule",
        )

    def test_first_error_aborts_with_no_partial_results(self):
        good = {
            "subject": "alice", "action": "read", "resource": "dev/x",
            "expected": {"effect": "deny", "rule": None},  # would fail
        }
        self._expect_error(
            [good, {"subject": "s", "bogus": 1}],
            "unknown_field", 1, "bogus",
        )

    # --- read-only / repeatable -------------------------------------

    def test_report_is_independent_deep_copy(self):
        nested = {"env": {"k": ["v"]}}
        gate = PolicyGate(
            [{"id": "t", "effect": "allow", "tags": {"env": {"k": ["v"]}}}]
        )
        case = {
            "subject": "s", "action": "a", "resource": "r", "tags": nested,
            "expected": {"effect": "deny", "rule": None},
        }
        first = gate.verify([case])
        first["failures"][0]["actual"]["rule"] = "tampered"
        first["failures"][0]["expected"]["rule"] = "tampered"
        fresh = gate.verify([case])
        self.assertEqual(fresh["failures"][0]["actual"]["rule"], "t")
        self.assertIsNone(fresh["failures"][0]["expected"]["rule"])
        self.assertEqual(nested, {"env": {"k": ["v"]}})

    def test_repeatable_and_read_only(self):
        import copy

        cases_snapshot = copy.deepcopy(self.cases)
        rules_before = [dict(r) for r in self.gate.rules]
        first = self.gate.verify(self.cases)
        for _ in range(20):
            self.assertEqual(self.gate.verify(copy.deepcopy(self.cases)), first)
        self.assertEqual(self.cases, cases_snapshot)
        self.assertEqual([dict(r) for r in self.gate.rules], rules_before)

    def test_from_json_matches_constructor(self):
        loaded = PolicyGate.from_json(
            '[{"id": "read", "effect": "allow", "action": "read"},'
            '{"id": "prod-lock", "effect": "deny", "resource": "prod/*"}]'
        )
        self.assertEqual(loaded.verify(self.cases), self.gate.verify(self.cases))


class TagPatternsTest(unittest.TestCase):
    def test_pattern_match_and_miss(self):
        gate = PolicyGate(
            [{"id": "p", "effect": "allow", "tag_patterns": {"env": "prod-*"}}]
        )
        self.assertEqual(
            gate.decide("s", "a", "r", {"env": "prod-eu"})["rule"], "p"
        )
        self.assertIsNone(gate.decide("s", "a", "r", {"env": "dev-eu"})["rule"])
        # fnmatchcase semantics: case sensitive, character classes work
        self.assertIsNone(gate.decide("s", "a", "r", {"env": "PROD-eu"})["rule"])
        gate = PolicyGate(
            [{"id": "p", "effect": "allow", "tag_patterns": {"env": "prod-?"}}]
        )
        self.assertEqual(
            gate.decide("s", "a", "r", {"env": "prod-1"})["rule"], "p"
        )
        self.assertIsNone(gate.decide("s", "a", "r", {"env": "prod-12"})["rule"])

    def test_missing_key_or_non_string_value_does_not_match(self):
        gate = PolicyGate(
            [{"id": "p", "effect": "allow", "tag_patterns": {"env": "*"}}]
        )
        self.assertIsNone(gate.decide("s", "a", "r")["rule"])
        self.assertIsNone(gate.decide("s", "a", "r", None)["rule"])
        for value in (None, 1, True, ["prod"], {"x": "y"}):
            self.assertIsNone(
                gate.decide("s", "a", "r", {"env": value})["rule"],
                "value %r" % (value,),
            )
        self.assertEqual(gate.decide("s", "a", "r", {"env": ""})["rule"], "p")

    def test_conjunction_with_exact_tags(self):
        gate = PolicyGate(
            [
                {
                    "id": "p",
                    "effect": "allow",
                    "tags": {"team": "core"},
                    "tag_patterns": {"env": "prod-*", "dc": "eu?"},
                }
            ]
        )
        good = {"team": "core", "env": "prod-x", "dc": "eu1"}
        self.assertEqual(gate.decide("s", "a", "r", good)["rule"], "p")
        for mutated in (
            {"team": "core", "env": "prod-x"},  # missing dc
            {"team": "core", "dc": "eu1"},  # missing env
            {"env": "prod-x", "dc": "eu1"},  # missing exact team
            {"team": "other", "env": "prod-x", "dc": "eu1"},
            {"team": "core", "env": "dev-x", "dc": "eu1"},
            {"team": "core", "env": "prod-x", "dc": "eu12"},
        ):
            self.assertIsNone(
                gate.decide("s", "a", "r", mutated)["rule"], repr(mutated)
            )

    def test_deny_priority_and_order_semantics_kept(self):
        gate = PolicyGate(
            [
                {"id": "allow", "effect": "allow", "priority": 10,
                 "tag_patterns": {"env": "prod-*"}},
                {"id": "deny", "effect": "deny", "priority": -1,
                 "tag_patterns": {"env": "*-eu"}},
            ]
        )
        decision = gate.decide("s", "a", "r", {"env": "prod-eu"})
        self.assertEqual((decision["effect"], decision["rule"]), ("deny", "deny"))
        decision = gate.decide("s", "a", "r", {"env": "prod-us"})
        self.assertEqual(
            (decision["effect"], decision["rule"]), ("allow", "allow")
        )

    def test_empty_and_missing_tag_patterns_behave_like_legacy(self):
        self.assertEqual(
            PolicyGate([{"id": "p", "effect": "allow",
                         "tag_patterns": {}}]).to_json(),
            PolicyGate([{"id": "p", "effect": "allow"}]).to_json(),
        )
        gate = PolicyGate([{"id": "p", "effect": "allow", "tag_patterns": {}}])
        self.assertEqual(gate.decide("s", "a", "r")["rule"], "p")

    def test_invalid_tag_patterns_shape(self):
        for bad in (
            "x",
            ["env"],
            ("env",),
            None,
            True,
            1,
            {"env": 1},
            {"env": None},
            {"env": True},
            {"env": ["prod-*"]},
            {1: "prod-*"},
            {"env": "prod-*", 2: "x"},
        ):
            with self.assertRaises(ValueError) as ctx:
                PolicyGate([{"effect": "allow", "tag_patterns": bad}])
            self.assertTrue(
                str(ctx.exception).startswith("invalid_tag_patterns"),
                "%r -> %s" % (bad, ctx.exception),
            )

    def test_invalid_tag_patterns_names_rule_index(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate(
                [{"effect": "allow"}, {"effect": "deny", "tag_patterns": "x"}]
            )
        self.assertIn("rule 1", str(ctx.exception))

    def test_tag_constraint_conflict(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate(
                [
                    {
                        "effect": "allow",
                        "tags": {"env": "prod"},
                        "tag_patterns": {"env": "prod-*"},
                    }
                ]
            )
        self.assertTrue(str(ctx.exception).startswith("tag_constraint_conflict"))
        self.assertIn("'env'", str(ctx.exception))
        # disjoint keys are fine
        gate = PolicyGate(
            [
                {
                    "effect": "allow",
                    "tags": {"team": "core"},
                    "tag_patterns": {"env": "prod-*"},
                }
            ]
        )
        self.assertEqual(
            gate.decide("s", "a", "r", {"team": "core", "env": "prod-x"})["rule"],
            "0",
        )

    def test_from_json_raises_same_value_errors(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(
                '[{"effect": "allow", "tag_patterns": {"env": 1}}]'
            )
        self.assertTrue(str(ctx.exception).startswith("invalid_tag_patterns"))
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(
                '[{"effect": "allow", "tags": {"env": "a"},'
                ' "tag_patterns": {"env": "a*"}}]'
            )
        self.assertTrue(str(ctx.exception).startswith("tag_constraint_conflict"))

    def test_explain_fields_preserved(self):
        gate = PolicyGate(
            [
                {"id": "p", "effect": "allow", "priority": 2,
                 "tag_patterns": {"env": "prod-*"}},
            ]
        )
        explanation = gate.explain("s", "a", "r", {"env": "prod-eu"})
        self.assertEqual(explanation["rule"], "p")
        self.assertEqual(
            explanation["matched_rules"],
            [{"id": "p", "effect": "allow", "priority": 2}],
        )
        explanation = gate.explain("s", "a", "r", {"env": "dev"})
        self.assertIsNone(explanation["rule"])
        self.assertEqual(explanation["matched_rules"], [])

    def test_trace_tags_match_is_conjunction(self):
        gate = PolicyGate(
            [
                {"id": "p", "effect": "allow", "tags": {"team": "core"},
                 "tag_patterns": {"env": "prod-*"}},
            ]
        )

        def tags_match(tags):
            return gate.trace("s", "a", "r", tags)["evaluations"][0]["tags_match"]

        self.assertTrue(tags_match({"team": "core", "env": "prod-eu"}))
        self.assertFalse(tags_match({"team": "core", "env": "dev"}))
        self.assertFalse(tags_match({"team": "core"}))
        self.assertFalse(tags_match({"team": "core", "env": 5}))
        self.assertFalse(tags_match({"env": "prod-eu"}))
        self.assertFalse(tags_match(None))

    def test_batch_entry_points_use_pattern_constraints(self):
        gate = PolicyGate(
            [{"id": "p", "effect": "allow", "tag_patterns": {"env": "prod-*"}}]
        )
        batch = [
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod-eu"}},
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "dev"}},
            {"subject": "s", "action": "a", "resource": "r"},
        ]
        result = gate.decide_many(batch)
        self.assertEqual(result["summary"], {"total": 3, "allow": 1, "deny": 2})
        coverage = gate.coverage(batch)
        self.assertEqual(
            coverage["rules"],
            [{"id": "p", "effect": "allow", "matched": 1, "winner": 1}],
        )
        cases = [
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod-eu"},
             "expected": {"effect": "allow", "rule": "p"}},
            {"subject": "s", "action": "a", "resource": "r",
             "expected": {"effect": "deny", "rule": None}},
        ]
        self.assertTrue(gate.verify(cases)["ok"])

    def test_compare_against_candidate_with_patterns(self):
        baseline = PolicyGate(
            [{"id": "a", "effect": "allow", "tags": {"env": "prod"}}]
        )
        candidate = PolicyGate(
            [{"id": "a", "effect": "allow", "tag_patterns": {"env": "prod-*"}}]
        )
        batch = [
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod-eu"}}
        ]
        report = baseline.compare(candidate, batch)
        self.assertEqual(report["summary"]["changed"], 1)
        self.assertEqual(report["summary"]["deny_to_allow"], 1)

    def test_audit_pattern_overlap_and_witness_replay(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_patterns": {"env": "prod-*"}},
                {"id": "d", "effect": "deny", "tag_patterns": {"env": "*-eu"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "effect_overlap")
        self.assertEqual(finding["winner"], "d")
        witness = finding["witness"]
        self.assertEqual(witness["tags"], {"env": "prod-eu"})
        decision = gate.decide(
            witness["subject"],
            witness["action"],
            witness["resource"],
            witness["tags"],
        )
        self.assertEqual((decision["effect"], decision["rule"]), ("deny", "d"))

    def test_audit_pattern_pair_without_common_string(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_patterns": {"env": "prod-*"}},
                {"id": "d", "effect": "deny",
                 "tag_patterns": {"env": "dev-*"}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_audit_exact_against_pattern(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"env": "prod"}},
                {"id": "d", "effect": "deny", "tag_patterns": {"env": "p*"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["tags"], {"env": "prod"})

        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"env": "dev"}},
                {"id": "d", "effect": "deny", "tag_patterns": {"env": "p*"}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])
        # a non-string exact value can never satisfy a pattern
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"env": 1}},
                {"id": "d", "effect": "deny", "tag_patterns": {"env": "*"}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_audit_unsatisfiable_pattern_never_overlaps(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_patterns": {"env": "[!\x00-\U0010ffff]"}},
                {"id": "d", "effect": "deny"},
            ]
        )
        # the allow rule's pattern matches no string, so the pair can
        # never overlap; the rule itself is reported as unsatisfiable
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "unsatisfiable_rule")
        self.assertEqual(finding["rule"], "a")

    def test_audit_shadowed_identical_tag_patterns(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow",
                 "tag_patterns": {"env": "prod-*"}},
                {"id": "a2", "effect": "allow",
                 "tag_patterns": {"env": "prod-*"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "shadowed_rule")
        self.assertEqual(finding["winner"], "a1")
        self.assertEqual(finding["shadowed"], "a2")
        self.assertEqual(finding["witness"]["tags"], {"env": "prod-"})
        # same effect but different patterns: not identical, no finding
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow",
                 "tag_patterns": {"env": "prod-*"}},
                {"id": "a2", "effect": "allow",
                 "tag_patterns": {"env": "prod-eu*"}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_audit_witness_tags_sorted_and_constrained_only(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"z": 1},
                 "tag_patterns": {"b": "x*"}},
                {"id": "d", "effect": "deny",
                 "tag_patterns": {"a": "y[0-9]", "b": "*1"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        tags = finding["witness"]["tags"]
        self.assertEqual(tags, {"a": "y0", "b": "x1", "z": 1})
        self.assertEqual(list(tags), ["a", "b", "z"])
        decision = gate.decide(
            finding["witness"]["subject"],
            finding["witness"]["action"],
            finding["witness"]["resource"],
            tags,
        )
        self.assertEqual((decision["effect"], decision["rule"]), ("deny", "d"))

    def test_to_json_exports_tag_patterns_after_tags(self):
        gate = PolicyGate(
            [
                {"id": "p", "effect": "allow",
                 "tag_patterns": {"env": "prod-*", "dc": "eu?"}},
            ]
        )
        self.assertEqual(
            gate.to_json(),
            '[{"id":"p","effect":"allow","priority":0,"subject":"*",'
            '"action":"*","resource":"*","tags":{},'
            '"tag_patterns":{"dc":"eu?","env":"prod-*"}}]',
        )

    def test_legacy_snapshot_bytes_and_fingerprint_unchanged(self):
        legacy = PolicyGate([{"id": "x", "effect": "allow", "tags": {"a": "b"}}])
        self.assertEqual(
            legacy.to_json(),
            '[{"id":"x","effect":"allow","priority":0,"subject":"*",'
            '"action":"*","resource":"*","tags":{"a":"b"}}]',
        )
        import hashlib

        self.assertEqual(
            legacy.fingerprint(),
            hashlib.sha256(legacy.to_json().encode("utf-8")).hexdigest(),
        )
        patterned = PolicyGate(
            [{"id": "x", "effect": "allow", "tags": {"a": "b"},
              "tag_patterns": {"env": "*"}}]
        )
        self.assertNotEqual(legacy.fingerprint(), patterned.fingerprint())

    def test_roundtrip_preserves_behavior(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "priority": 3, "subject": "u*",
                 "tags": {"team": "core"},
                 "tag_patterns": {"env": "prod-?", "dc": "*"}},
                {"id": "d", "effect": "deny", "resource": "secret/*",
                 "tag_patterns": {"env": "*"}},
            ]
        )
        loaded = PolicyGate.from_json(gate.to_json())
        self.assertEqual(loaded.to_json(), gate.to_json())
        self.assertEqual(loaded.fingerprint(), gate.fingerprint())
        requests = [
            {"subject": "u1", "action": "read", "resource": "doc",
             "tags": {"team": "core", "env": "prod-1", "dc": "eu"}},
            {"subject": "u1", "action": "read", "resource": "secret/x",
             "tags": {"team": "core", "env": "prod-1", "dc": "eu"}},
            {"subject": "u1", "action": "read", "resource": "doc",
             "tags": {"team": "core", "env": "prod-12", "dc": "eu"}},
            {"subject": "u1", "action": "read", "resource": "doc"},
        ]
        self.assertEqual(loaded.decide_many(requests), gate.decide_many(requests))
        self.assertEqual(loaded.coverage(requests), gate.coverage(requests))
        self.assertEqual(loaded.audit(), gate.audit())
        for item in requests:
            args = (
                item["subject"],
                item["action"],
                item["resource"],
                item.get("tags"),
            )
            self.assertEqual(loaded.explain(*args), gate.explain(*args))
            self.assertEqual(loaded.trace(*args), gate.trace(*args))


class TagExcludePatternsTest(unittest.TestCase):
    def test_exclusion_hit_and_miss(self):
        gate = PolicyGate(
            [
                {
                    "id": "p",
                    "effect": "allow",
                    "tags": {"env": "prod"},
                    "tag_exclude_patterns": {"stage": "tmp-*"},
                }
            ]
        )
        self.assertEqual(
            gate.decide("s", "a", "r", {"env": "prod"})["rule"], "p"
        )
        self.assertEqual(
            gate.decide("s", "a", "r",
                        {"env": "prod", "stage": "stable"})["rule"],
            "p",
        )
        self.assertIsNone(
            gate.decide("s", "a", "r",
                        {"env": "prod", "stage": "tmp-1"})["rule"]
        )
        # fnmatchcase semantics: case sensitive
        self.assertEqual(
            gate.decide("s", "a", "r",
                        {"env": "prod", "stage": "TMP-1"})["rule"],
            "p",
        )

    def test_missing_key_and_non_string_value_pass(self):
        gate = PolicyGate(
            [{"id": "p", "effect": "allow",
              "tag_exclude_patterns": {"stage": "tmp-*"}}]
        )
        self.assertEqual(gate.decide("s", "a", "r")["rule"], "p")
        self.assertEqual(gate.decide("s", "a", "r", None)["rule"], "p")
        for value in (None, 1, True, ["tmp-1"], {"x": "y"}):
            self.assertEqual(
                gate.decide("s", "a", "r", {"stage": value})["rule"],
                "p",
                "value %r" % (value,),
            )
        self.assertIsNone(
            gate.decide("s", "a", "r", {"stage": "tmp-"})["rule"]
        )

    def test_conjunction_with_exact_and_pattern_tags(self):
        gate = PolicyGate(
            [
                {
                    "id": "p",
                    "effect": "allow",
                    "tags": {"team": "core"},
                    "tag_patterns": {"env": "prod-*"},
                    "tag_exclude_patterns": {"stage": "tmp-*", "dc": "old-?"},
                }
            ]
        )
        good = {"team": "core", "env": "prod-eu", "stage": "stable", "dc": "eu1"}
        self.assertEqual(gate.decide("s", "a", "r", good)["rule"], "p")
        for mutated in (
            {"team": "core", "env": "prod-eu", "stage": "tmp-1", "dc": "eu1"},
            {"team": "core", "env": "prod-eu", "stage": "stable", "dc": "old-1"},
            {"team": "core", "env": "dev-eu", "stage": "stable", "dc": "eu1"},
            {"env": "prod-eu", "stage": "stable", "dc": "eu1"},
        ):
            self.assertIsNone(
                gate.decide("s", "a", "r", mutated)["rule"], repr(mutated)
            )

    def test_deny_priority_and_order_semantics_kept(self):
        gate = PolicyGate(
            [
                {"id": "allow", "effect": "allow", "priority": 10,
                 "tag_exclude_patterns": {"stage": "tmp-*"}},
                {"id": "deny", "effect": "deny", "priority": -1,
                 "tag_exclude_patterns": {"stage": "prod-*"}},
            ]
        )
        # both exclusions avoided: both rules match, explicit deny wins
        decision = gate.decide("s", "a", "r", {"stage": "stable"})
        self.assertEqual((decision["effect"], decision["rule"]), ("deny", "deny"))
        # allow's exclusion hit: only the deny matches
        decision = gate.decide("s", "a", "r", {"stage": "tmp-1"})
        self.assertEqual((decision["effect"], decision["rule"]), ("deny", "deny"))
        # deny's exclusion hit: only the allow matches
        decision = gate.decide("s", "a", "r", {"stage": "prod-1"})
        self.assertEqual(
            (decision["effect"], decision["rule"]), ("allow", "allow")
        )

    def test_empty_and_missing_exclude_behave_like_legacy(self):
        self.assertEqual(
            PolicyGate([{"id": "p", "effect": "allow",
                         "tag_exclude_patterns": {}}]).to_json(),
            PolicyGate([{"id": "p", "effect": "allow"}]).to_json(),
        )
        gate = PolicyGate(
            [{"id": "p", "effect": "allow", "tag_exclude_patterns": {}}]
        )
        self.assertEqual(gate.decide("s", "a", "r")["rule"], "p")

    def test_invalid_tag_exclude_patterns_shape(self):
        for bad in (
            "x",
            ["env"],
            ("env",),
            None,
            True,
            1,
            {"env": 1},
            {"env": None},
            {"env": True},
            {"env": ["tmp-*"]},
            {1: "tmp-*"},
            {"env": "tmp-*", 2: "x"},
        ):
            with self.assertRaises(ValueError) as ctx:
                PolicyGate([{"effect": "allow", "tag_exclude_patterns": bad}])
            self.assertTrue(
                str(ctx.exception).startswith("invalid_tag_exclude_patterns"),
                "%r -> %s" % (bad, ctx.exception),
            )

    def test_invalid_tag_exclude_patterns_names_rule_index(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate(
                [{"effect": "allow"},
                 {"effect": "deny", "tag_exclude_patterns": "x"}]
            )
        self.assertIn("rule 1", str(ctx.exception))

    def test_tag_constraint_conflict(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate(
                [
                    {
                        "effect": "allow",
                        "tags": {"env": "prod"},
                        "tag_exclude_patterns": {"env": "*-tmp"},
                    }
                ]
            )
        self.assertTrue(str(ctx.exception).startswith("tag_constraint_conflict"))
        self.assertIn("'env'", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            PolicyGate(
                [
                    {
                        "effect": "allow",
                        "tag_patterns": {"env": "prod-*"},
                        "tag_exclude_patterns": {"env": "*-tmp"},
                    }
                ]
            )
        self.assertTrue(str(ctx.exception).startswith("tag_constraint_conflict"))
        # disjoint keys across the three mappings are fine
        gate = PolicyGate(
            [
                {
                    "effect": "allow",
                    "tags": {"team": "core"},
                    "tag_patterns": {"env": "prod-*"},
                    "tag_exclude_patterns": {"stage": "tmp-*"},
                }
            ]
        )
        self.assertEqual(
            gate.decide(
                "s", "a", "r",
                {"team": "core", "env": "prod-x", "stage": "stable"},
            )["rule"],
            "0",
        )

    def test_from_json_raises_same_value_errors(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(
                '[{"effect": "allow", "tag_exclude_patterns": {"env": 1}}]'
            )
        self.assertTrue(
            str(ctx.exception).startswith("invalid_tag_exclude_patterns")
        )
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(
                '[{"effect": "allow", "tags": {"env": "a"},'
                ' "tag_exclude_patterns": {"env": "a*"}}]'
            )
        self.assertTrue(str(ctx.exception).startswith("tag_constraint_conflict"))
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(
                '[{"effect": "allow", "tag_patterns": {"env": "a*"},'
                ' "tag_exclude_patterns": {"env": "b*"}}]'
            )
        self.assertTrue(str(ctx.exception).startswith("tag_constraint_conflict"))

    def test_trace_tags_match_includes_exclusions(self):
        gate = PolicyGate(
            [
                {"id": "p", "effect": "allow", "tags": {"team": "core"},
                 "tag_exclude_patterns": {"stage": "tmp-*"}},
            ]
        )

        def tags_match(tags):
            return gate.trace("s", "a", "r", tags)["evaluations"][0]["tags_match"]

        self.assertTrue(tags_match({"team": "core"}))
        self.assertTrue(tags_match({"team": "core", "stage": "stable"}))
        self.assertFalse(tags_match({"team": "core", "stage": "tmp-1"}))
        self.assertTrue(tags_match({"team": "core", "stage": 5}))
        self.assertFalse(tags_match({"stage": "stable"}))
        self.assertFalse(tags_match(None))

    def test_batch_entry_points_use_exclusion_constraints(self):
        gate = PolicyGate(
            [{"id": "p", "effect": "allow",
              "tag_exclude_patterns": {"stage": "tmp-*"}}]
        )
        batch = [
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"stage": "stable"}},
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"stage": "tmp-1"}},
            {"subject": "s", "action": "a", "resource": "r"},
        ]
        result = gate.decide_many(batch)
        self.assertEqual(result["summary"], {"total": 3, "allow": 2, "deny": 1})
        coverage = gate.coverage(batch)
        self.assertEqual(
            coverage["rules"],
            [{"id": "p", "effect": "allow", "matched": 2, "winner": 2}],
        )
        traces = gate.trace_many(batch)
        self.assertEqual([t["rule"] for t in traces["traces"]], ["p", None, "p"])
        cases = [
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"stage": "stable"},
             "expected": {"effect": "allow", "rule": "p"}},
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"stage": "tmp-1"},
             "expected": {"effect": "deny", "rule": None}},
        ]
        self.assertTrue(gate.verify(cases)["ok"])

    def test_compare_against_candidate_with_exclusions(self):
        baseline = PolicyGate(
            [{"id": "a", "effect": "allow", "tags": {"env": "prod"}}]
        )
        candidate = PolicyGate(
            [{"id": "a", "effect": "allow", "tags": {"env": "prod"},
              "tag_exclude_patterns": {"stage": "tmp-*"}}]
        )
        batch = [
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod", "stage": "tmp-1"}}
        ]
        report = baseline.compare(candidate, batch)
        self.assertEqual(report["summary"]["changed"], 1)
        self.assertEqual(report["summary"]["allow_to_deny"], 1)

    def test_audit_exclusion_narrows_overlap(self):
        # positive pattern and exclusion on the same key across rules:
        # only values satisfying both keep the overlap alive
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_patterns": {"env": "prod-*"}},
                {"id": "d", "effect": "deny",
                 "tag_exclude_patterns": {"env": "*-tmp"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "effect_overlap")
        self.assertEqual(finding["winner"], "d")
        witness = finding["witness"]
        self.assertEqual(witness["tags"], {"env": "prod-"})
        decision = gate.decide(
            witness["subject"], witness["action"], witness["resource"],
            witness["tags"],
        )
        self.assertEqual((decision["effect"], decision["rule"]), ("deny", "d"))

    def test_audit_exclusion_blocking_all_values_removes_finding(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_patterns": {"env": "prod-?"}},
                {"id": "d", "effect": "deny",
                 "tag_exclude_patterns": {"env": "prod-*"}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_audit_exact_value_against_exclusion(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"env": "prod"}},
                {"id": "d", "effect": "deny",
                 "tag_exclude_patterns": {"env": "*-tmp"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["tags"], {"env": "prod"})

        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"env": "prod-tmp"}},
                {"id": "d", "effect": "deny",
                 "tag_exclude_patterns": {"env": "*-tmp"}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])
        # a non-string exact value never matches an exclusion pattern
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"env": 1}},
                {"id": "d", "effect": "deny",
                 "tag_exclude_patterns": {"env": "*"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["tags"], {"env": 1})

    def test_audit_exclude_only_key_in_witness(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_exclude_patterns": {"stage": "tmp-*"}},
                {"id": "d", "effect": "deny"},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["tags"], {"stage": ""})
        decision = gate.decide(
            finding["witness"]["subject"], finding["witness"]["action"],
            finding["witness"]["resource"], finding["witness"]["tags"],
        )
        self.assertEqual((decision["effect"], decision["rule"]), ("deny", "d"))

    def test_audit_unavoidable_exclusion_removes_finding(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_exclude_patterns": {"stage": "*"}},
                {"id": "d", "effect": "deny"},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_audit_witness_shortest_avoiding_string(self):
        # "prod-" itself is excluded, so the witness must grow by the
        # smallest code point
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_patterns": {"env": "prod-*"}},
                {"id": "d", "effect": "deny",
                 "tag_exclude_patterns": {"env": "prod-"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["tags"], {"env": "prod-\x00"})

    def test_audit_shadowed_identical_exclusions(self):
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow",
                 "tag_exclude_patterns": {"env": "tmp-*"}},
                {"id": "a2", "effect": "allow",
                 "tag_exclude_patterns": {"env": "tmp-*"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "shadowed_rule")
        self.assertEqual(finding["winner"], "a1")
        self.assertEqual(finding["shadowed"], "a2")
        self.assertEqual(finding["witness"]["tags"], {"env": ""})
        # same positive constraints but different exclusions: not identical
        gate = PolicyGate(
            [
                {"id": "a1", "effect": "allow",
                 "tag_exclude_patterns": {"env": "tmp-*"}},
                {"id": "a2", "effect": "allow",
                 "tag_exclude_patterns": {"env": "dev-*"}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_audit_witness_tags_sorted_and_constrained_only(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "tags": {"z": 1},
                 "tag_exclude_patterns": {"b": "tmp-*"}},
                {"id": "d", "effect": "deny",
                 "tag_patterns": {"a": "y[0-9]"},
                 "tag_exclude_patterns": {"b": "*-old"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        tags = finding["witness"]["tags"]
        self.assertEqual(tags, {"a": "y0", "b": "", "z": 1})
        self.assertEqual(list(tags), ["a", "b", "z"])
        decision = gate.decide(
            finding["witness"]["subject"], finding["witness"]["action"],
            finding["witness"]["resource"], tags,
        )
        self.assertEqual((decision["effect"], decision["rule"]), ("deny", "d"))

    def test_to_json_exports_exclude_patterns_after_tag_patterns(self):
        gate = PolicyGate(
            [
                {"id": "p", "effect": "allow",
                 "tag_patterns": {"env": "prod-*"},
                 "tag_exclude_patterns": {"stage": "tmp-*", "dc": "old-?"}},
            ]
        )
        self.assertEqual(
            gate.to_json(),
            '[{"id":"p","effect":"allow","priority":0,"subject":"*",'
            '"action":"*","resource":"*","tags":{},'
            '"tag_patterns":{"env":"prod-*"},'
            '"tag_exclude_patterns":{"dc":"old-?","stage":"tmp-*"}}]',
        )
        # without tag_patterns the exclusion mapping still follows tags
        gate = PolicyGate(
            [{"id": "p", "effect": "allow",
              "tag_exclude_patterns": {"stage": "tmp-*"}}]
        )
        self.assertEqual(
            gate.to_json(),
            '[{"id":"p","effect":"allow","priority":0,"subject":"*",'
            '"action":"*","resource":"*","tags":{},'
            '"tag_exclude_patterns":{"stage":"tmp-*"}}]',
        )

    def test_legacy_snapshot_bytes_and_fingerprint_unchanged(self):
        legacy = PolicyGate([{"id": "x", "effect": "allow", "tags": {"a": "b"}}])
        self.assertEqual(
            legacy.to_json(),
            '[{"id":"x","effect":"allow","priority":0,"subject":"*",'
            '"action":"*","resource":"*","tags":{"a":"b"}}]',
        )
        import hashlib

        self.assertEqual(
            legacy.fingerprint(),
            hashlib.sha256(legacy.to_json().encode("utf-8")).hexdigest(),
        )
        excluding = PolicyGate(
            [{"id": "x", "effect": "allow", "tags": {"a": "b"},
              "tag_exclude_patterns": {"stage": "tmp-*"}}]
        )
        self.assertNotEqual(legacy.fingerprint(), excluding.fingerprint())

    def test_roundtrip_preserves_behavior(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "priority": 3, "subject": "u*",
                 "tags": {"team": "core"},
                 "tag_patterns": {"env": "prod-?"},
                 "tag_exclude_patterns": {"stage": "tmp-*"}},
                {"id": "d", "effect": "deny", "resource": "secret/*",
                 "tag_exclude_patterns": {"dc": "old-?"}},
            ]
        )
        loaded = PolicyGate.from_json(gate.to_json())
        self.assertEqual(loaded.to_json(), gate.to_json())
        self.assertEqual(loaded.fingerprint(), gate.fingerprint())
        requests = [
            {"subject": "u1", "action": "read", "resource": "doc",
             "tags": {"team": "core", "env": "prod-1", "stage": "stable"}},
            {"subject": "u1", "action": "read", "resource": "doc",
             "tags": {"team": "core", "env": "prod-1", "stage": "tmp-1"}},
            {"subject": "u1", "action": "read", "resource": "secret/x",
             "tags": {"team": "core", "env": "prod-1", "dc": "new-1"}},
            {"subject": "u1", "action": "read", "resource": "secret/x",
             "tags": {"team": "core", "env": "prod-1", "dc": "old-1"}},
        ]
        self.assertEqual(loaded.decide_many(requests), gate.decide_many(requests))
        self.assertEqual(loaded.coverage(requests), gate.coverage(requests))
        self.assertEqual(loaded.trace_many(requests), gate.trace_many(requests))
        self.assertEqual(loaded.audit(), gate.audit())
        for item in requests:
            args = (
                item["subject"],
                item["action"],
                item["resource"],
                item.get("tags"),
            )
            self.assertEqual(loaded.explain(*args), gate.explain(*args))
            self.assertEqual(loaded.trace(*args), gate.trace(*args))

    def test_audit_report_mutation_isolated(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_patterns": {"env": "prod-*"}},
                {"id": "d", "effect": "deny",
                 "tag_exclude_patterns": {"env": "*-tmp"}},
            ]
        )
        first = gate.audit()
        for _ in range(10):
            self.assertEqual(gate.audit(), first)
        first["findings"][0]["witness"]["tags"]["env"] = "tampered"
        fresh = gate.audit()
        self.assertEqual(
            fresh["findings"][0]["witness"]["tags"], {"env": "prod-"}
        )
        self.assertEqual(gate.rules[0]["tag_patterns"], {"env": "prod-*"})
        self.assertEqual(
            gate.rules[1]["tag_exclude_patterns"], {"env": "*-tmp"}
        )


class TagPresenceTest(unittest.TestCase):
    def test_required_key_matches_any_value(self):
        gate = PolicyGate(
            [{"id": "p", "effect": "allow",
              "tag_presence": {"env": True}}]
        )
        for tags in ({"env": "prod"}, {"env": 5}, {"env": None},
                     {"env": ["x"]}, {"env": {"a": 1}}, {"env": ""}):
            self.assertEqual(
                gate.decide("s", "a", "r", tags)["rule"], "p", tags
            )
        for tags in ({}, {"team": "core"}, None):
            self.assertIsNone(gate.decide("s", "a", "r", tags)["rule"])

    def test_forbidden_key_must_be_absent(self):
        gate = PolicyGate(
            [{"id": "p", "effect": "allow",
              "tag_presence": {"tmp": False}}]
        )
        self.assertEqual(gate.decide("s", "a", "r")["rule"], "p")
        self.assertEqual(gate.decide("s", "a", "r", {})["rule"], "p")
        self.assertEqual(
            gate.decide("s", "a", "r", {"env": "prod"})["rule"], "p"
        )
        for tags in ({"tmp": "x"}, {"tmp": None}, {"tmp": False}):
            self.assertIsNone(gate.decide("s", "a", "r", tags)["rule"])

    def test_conjunction_with_other_tag_constraints(self):
        gate = PolicyGate(
            [
                {"id": "p", "effect": "allow",
                 "tags": {"team": "core"},
                 "tag_patterns": {"env": "prod-*"},
                 "tag_exclude_patterns": {"stage": "tmp-*"},
                 "tag_presence": {"owner": True, "debug": False}},
            ]
        )

        def matched(tags):
            return gate.decide("s", "a", "r", tags)["rule"] == "p"

        self.assertTrue(matched({"team": "core", "env": "prod-eu",
                                 "stage": "stable", "owner": "ops"}))
        self.assertFalse(matched({"team": "core", "env": "prod-eu",
                                  "stage": "stable"}))
        self.assertFalse(matched({"team": "core", "env": "prod-eu",
                                  "stage": "stable", "owner": "ops",
                                  "debug": 1}))
        self.assertFalse(matched({"team": "core", "env": "dev",
                                  "stage": "stable", "owner": "ops"}))
        self.assertFalse(matched({"team": "core", "env": "prod-eu",
                                  "stage": "tmp-1", "owner": "ops"}))

    def test_deny_priority_and_order_semantics_kept(self):
        gate = PolicyGate(
            [
                {"id": "allow", "effect": "allow", "priority": 9,
                 "tag_presence": {"env": True}},
                {"id": "deny", "effect": "deny", "priority": 1,
                 "tag_presence": {"env": True}},
            ]
        )
        decision = gate.decide("s", "a", "r", {"env": "x"})
        self.assertEqual((decision["effect"], decision["rule"]),
                         ("deny", "deny"))
        gate = PolicyGate(
            [
                {"id": "low", "effect": "allow", "priority": 1,
                 "tag_presence": {"env": True}},
                {"id": "high", "effect": "allow", "priority": 2,
                 "tag_presence": {"env": True}},
            ]
        )
        self.assertEqual(
            gate.decide("s", "a", "r", {"env": "x"})["rule"], "high"
        )

    def test_empty_and_missing_presence_behave_like_legacy(self):
        legacy = PolicyGate([{"id": "p", "effect": "allow"}])
        empty = PolicyGate(
            [{"id": "p", "effect": "allow", "tag_presence": {}}]
        )
        for tags in (None, {}, {"env": "prod"}):
            self.assertEqual(
                legacy.decide("s", "a", "r", tags),
                empty.decide("s", "a", "r", tags),
            )
        self.assertEqual(legacy.to_json(), empty.to_json())
        self.assertEqual(legacy.fingerprint(), empty.fingerprint())

    def test_invalid_tag_presence_shape(self):
        for bad in (
            "x",
            ["env"],
            ("env",),
            None,
            True,
            1,
            {"env": 1},
            {"env": 0},
            {"env": None},
            {"env": "true"},
            {"env": ["yes"]},
            {1: True},
            {"env": True, 2: False},
        ):
            with self.assertRaises(ValueError) as ctx:
                PolicyGate([{"effect": "allow", "tag_presence": bad}])
            self.assertTrue(
                str(ctx.exception).startswith("invalid_tag_presence"),
                "%r -> %s" % (bad, ctx.exception),
            )

    def test_invalid_tag_presence_names_rule_index(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate(
                [{"effect": "allow"}, {"effect": "deny",
                                       "tag_presence": "x"}]
            )
        self.assertIn("rule 1", str(ctx.exception))

    def test_tag_presence_conflict(self):
        for rule in (
            {"tags": {"env": "prod"}, "tag_presence": {"env": True}},
            {"tag_patterns": {"env": "prod-*"},
             "tag_presence": {"env": False}},
            {"tag_exclude_patterns": {"env": "tmp-*"},
             "tag_presence": {"env": True}},
        ):
            with self.assertRaises(ValueError) as ctx:
                PolicyGate([dict(effect="allow", **rule)])
            self.assertTrue(
                str(ctx.exception).startswith("tag_presence_conflict"),
                "%r -> %s" % (rule, ctx.exception),
            )
            self.assertIn("'env'", str(ctx.exception))
        # disjoint keys are fine
        gate = PolicyGate(
            [
                {"effect": "allow", "tags": {"team": "core"},
                 "tag_presence": {"env": True}},
            ]
        )
        self.assertEqual(
            gate.decide("s", "a", "r", {"team": "core", "env": 1})["rule"],
            "0",
        )

    def test_from_json_raises_same_value_errors(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(
                '[{"effect": "allow", "tag_presence": {"env": 1}}]'
            )
        self.assertTrue(str(ctx.exception).startswith("invalid_tag_presence"))
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(
                '[{"effect": "allow", "tags": {"env": "a"},'
                ' "tag_presence": {"env": true}}]'
            )
        self.assertTrue(str(ctx.exception).startswith("tag_presence_conflict"))

    def test_trace_tags_match_includes_presence(self):
        gate = PolicyGate(
            [
                {"id": "p", "effect": "allow", "tags": {"team": "core"},
                 "tag_presence": {"env": True, "debug": False}},
            ]
        )

        def tags_match(tags):
            return gate.trace("s", "a", "r", tags)["evaluations"][0][
                "tags_match"
            ]

        self.assertTrue(tags_match({"team": "core", "env": "prod"}))
        self.assertTrue(tags_match({"team": "core", "env": 5}))
        self.assertFalse(tags_match({"team": "core"}))
        self.assertFalse(tags_match({"team": "core", "env": "prod",
                                     "debug": None}))
        self.assertFalse(tags_match({"env": "prod"}))
        self.assertFalse(tags_match(None))

    def test_batch_entry_points_use_presence_constraints(self):
        gate = PolicyGate(
            [{"id": "p", "effect": "allow",
              "tag_presence": {"env": True, "tmp": False}}]
        )
        batch = [
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"env": "prod"}},
            {"subject": "s", "action": "a", "resource": "r",
             "tags": {"tmp": 1}},
            {"subject": "s", "action": "a", "resource": "r"},
        ]
        result = gate.decide_many(batch)
        self.assertEqual(
            [d["rule"] for d in result["decisions"]], ["p", None, None]
        )
        traces = gate.trace_many(batch)
        self.assertEqual(
            [t["rule"] for t in traces["traces"]], ["p", None, None]
        )
        coverage = gate.coverage(batch)
        self.assertEqual(coverage["rules"][0]["matched"], 1)
        self.assertEqual(coverage["rules"][0]["winner"], 1)
        verification = gate.verify(
            [
                dict(batch[0], expected={"effect": "allow", "rule": "p"}),
                dict(batch[1], expected={"effect": "deny", "rule": None}),
                dict(batch[2], expected={"effect": "deny", "rule": None}),
            ]
        )
        self.assertTrue(verification["ok"])

    def test_compare_against_candidate_with_presence(self):
        baseline = PolicyGate([{"id": "p", "effect": "allow"}])
        candidate = PolicyGate(
            [{"id": "p", "effect": "allow",
              "tag_presence": {"env": True}}]
        )
        result = baseline.compare(
            candidate,
            [
                {"subject": "s", "action": "a", "resource": "r",
                 "tags": {"env": "prod"}},
                {"subject": "s", "action": "a", "resource": "r"},
            ],
        )
        self.assertEqual(result["summary"]["changed"], 1)
        self.assertEqual(result["changes"][0]["kind"], "allow_to_deny")
        self.assertEqual(result["changes"][0]["index"], 1)

    def test_audit_presence_contradiction_removes_finding(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_presence": {"env": True}},
                {"id": "d", "effect": "deny",
                 "tag_presence": {"env": False}},
            ]
        )
        self.assertEqual(
            gate.audit()["summary"], {"total": 0, "error": 0, "warning": 0}
        )

    def test_audit_forbidden_key_against_exact_or_pattern(self):
        for other in (
            {"tags": {"env": "prod"}},
            {"tag_patterns": {"env": "prod-*"}},
        ):
            gate = PolicyGate(
                [
                    {"id": "a", "effect": "allow",
                     "tag_presence": {"env": False}},
                    dict(id="d", effect="deny", **other),
                ]
            )
            self.assertEqual(gate.audit()["findings"], [], other)

    def test_audit_forbidden_key_passes_exclusion_by_absence(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_presence": {"tmp": False}},
                {"id": "d", "effect": "deny",
                 "tag_exclude_patterns": {"tmp": "*"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertNotIn("tmp", finding["witness"]["tags"])
        decision = gate.decide(
            finding["witness"]["subject"], finding["witness"]["action"],
            finding["witness"]["resource"], finding["witness"]["tags"],
        )
        self.assertEqual((decision["effect"], decision["rule"]),
                         ("deny", "d"))

    def test_audit_presence_only_key_witness_is_shortest_string(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_presence": {"env": True}},
                {"id": "d", "effect": "deny", "tags": {"team": "core"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "effect_overlap")
        self.assertEqual(
            finding["witness"]["tags"], {"env": "", "team": "core"}
        )
        self.assertEqual(list(finding["witness"]["tags"]), ["env", "team"])
        decision = gate.decide(
            finding["witness"]["subject"], finding["witness"]["action"],
            finding["witness"]["resource"], finding["witness"]["tags"],
        )
        self.assertEqual((decision["effect"], decision["rule"]),
                         ("deny", "d"))

    def test_audit_shared_required_key_witness(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_presence": {"env": True}},
                {"id": "d", "effect": "deny",
                 "tag_patterns": {"env": "prod-*"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["tags"], {"env": "prod-"})
        decision = gate.decide(
            finding["witness"]["subject"], finding["witness"]["action"],
            finding["witness"]["resource"], finding["witness"]["tags"],
        )
        self.assertEqual((decision["effect"], decision["rule"]),
                         ("deny", "d"))

    def test_audit_shadowed_identical_presence(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_presence": {"env": True}},
                {"id": "b", "effect": "allow",
                 "tag_presence": {"env": True}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "shadowed_rule")
        self.assertEqual(finding["severity"], "warning")
        self.assertEqual(finding["shadowed"], "b")
        # different presence mappings are not identical selectors
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_presence": {"env": True}},
                {"id": "b", "effect": "allow",
                 "tag_presence": {"env": True, "tmp": False}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_to_json_exports_presence_after_exclude_patterns(self):
        gate = PolicyGate(
            [
                {"id": "p", "effect": "allow",
                 "tag_patterns": {"env": "prod-*"},
                 "tag_exclude_patterns": {"stage": "tmp-*"},
                 "tag_presence": {"owner": True, "debug": False}},
            ]
        )
        self.assertEqual(
            gate.to_json(),
            '[{"id":"p","effect":"allow","priority":0,"subject":"*",'
            '"action":"*","resource":"*","tags":{},'
            '"tag_patterns":{"env":"prod-*"},'
            '"tag_exclude_patterns":{"stage":"tmp-*"},'
            '"tag_presence":{"debug":false,"owner":true}}]',
        )
        # without pattern fields the presence mapping still follows tags
        gate = PolicyGate(
            [{"id": "p", "effect": "allow",
              "tag_presence": {"env": True}}]
        )
        self.assertEqual(
            gate.to_json(),
            '[{"id":"p","effect":"allow","priority":0,"subject":"*",'
            '"action":"*","resource":"*","tags":{},'
            '"tag_presence":{"env":true}}]',
        )

    def test_legacy_snapshot_bytes_and_fingerprint_unchanged(self):
        legacy = PolicyGate([{"id": "x", "effect": "allow", "tags": {"a": "b"}}])
        self.assertEqual(
            legacy.to_json(),
            '[{"id":"x","effect":"allow","priority":0,"subject":"*",'
            '"action":"*","resource":"*","tags":{"a":"b"}}]',
        )
        import hashlib

        self.assertEqual(
            legacy.fingerprint(),
            hashlib.sha256(legacy.to_json().encode("utf-8")).hexdigest(),
        )
        present = PolicyGate(
            [{"id": "x", "effect": "allow", "tags": {"a": "b"},
              "tag_presence": {"env": True}}]
        )
        self.assertNotEqual(legacy.fingerprint(), present.fingerprint())

    def test_roundtrip_preserves_behavior(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "priority": 3, "subject": "u*",
                 "tags": {"team": "core"},
                 "tag_patterns": {"env": "prod-?"},
                 "tag_exclude_patterns": {"stage": "tmp-*"},
                 "tag_presence": {"owner": True, "debug": False}},
                {"id": "d", "effect": "deny", "resource": "secret/*",
                 "tag_presence": {"locked": False}},
            ]
        )
        loaded = PolicyGate.from_json(gate.to_json())
        self.assertEqual(loaded.to_json(), gate.to_json())
        self.assertEqual(loaded.fingerprint(), gate.fingerprint())
        requests = [
            {"subject": "u1", "action": "read", "resource": "doc",
             "tags": {"team": "core", "env": "prod-1", "stage": "stable",
                      "owner": "ops"}},
            {"subject": "u1", "action": "read", "resource": "doc",
             "tags": {"team": "core", "env": "prod-1", "stage": "stable"}},
            {"subject": "u1", "action": "read", "resource": "doc",
             "tags": {"team": "core", "env": "prod-1", "stage": "stable",
                      "owner": "ops", "debug": True}},
            {"subject": "u1", "action": "read", "resource": "secret/x",
             "tags": {"team": "core", "env": "prod-1", "owner": "ops"}},
            {"subject": "u1", "action": "read", "resource": "secret/x",
             "tags": {"team": "core", "env": "prod-1", "owner": "ops",
                      "locked": "y"}},
        ]
        self.assertEqual(loaded.decide_many(requests), gate.decide_many(requests))
        self.assertEqual(loaded.coverage(requests), gate.coverage(requests))
        self.assertEqual(loaded.trace_many(requests), gate.trace_many(requests))
        self.assertEqual(loaded.audit(), gate.audit())
        for item in requests:
            args = (
                item["subject"],
                item["action"],
                item["resource"],
                item.get("tags"),
            )
            self.assertEqual(loaded.explain(*args), gate.explain(*args))
            self.assertEqual(loaded.trace(*args), gate.trace(*args))


class SelectorExclusionTest(unittest.TestCase):
    def test_excluded_value_falls_through_to_default_deny(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "resource": "data/*",
                 "resource_exclude": "data/secret*"},
            ]
        )
        self.assertEqual(
            gate.decide("s", "x", "data/ok"),
            {"effect": "allow", "rule": "a",
             "reason": "matched allow rule 'a' (priority 0)"},
        )
        self.assertEqual(
            gate.decide("s", "x", "data/secret1"),
            {"effect": "deny", "rule": None, "reason": "default deny"},
        )

    def test_each_dimension_excludes_independently(self):
        gate = PolicyGate(
            [
                {"id": "r", "effect": "allow",
                 "subject": "*", "subject_exclude": "tmp-*",
                 "action": "read", "action_exclude": "read-all",
                 "resource": "doc/*", "resource_exclude": "doc/old/*"},
            ]
        )
        self.assertEqual(
            gate.decide("alice", "read", "doc/a")["effect"], "allow"
        )
        self.assertEqual(
            gate.decide("tmp-1", "read", "doc/a")["effect"], "deny"
        )
        self.assertEqual(
            gate.decide("alice", "read-all", "doc/a")["effect"], "deny"
        )
        self.assertEqual(
            gate.decide("alice", "read", "doc/old/a")["effect"], "deny"
        )

    def test_empty_string_exclusion_has_real_fnmatch_semantics(self):
        gate = PolicyGate(
            [{"id": "e", "effect": "allow", "subject_exclude": ""}]
        )
        # "" only matches (and therefore excludes) the empty string
        self.assertEqual(gate.decide("bob", "a", "r")["effect"], "allow")
        self.assertEqual(gate.decide("", "a", "r")["effect"], "deny")
        self.assertIsNone(gate.decide("", "a", "r")["rule"])

    def test_omitted_exclusion_changes_nothing(self):
        rules = [
            {"id": "read", "effect": "allow", "action": "read"},
            {"id": "lock", "effect": "deny", "resource": "prod/*"},
        ]
        gate = PolicyGate(rules)
        self.assertIsNone(gate.rules[0]["subject_exclude"])
        self.assertIsNone(gate.rules[0]["action_exclude"])
        self.assertIsNone(gate.rules[0]["resource_exclude"])
        self.assertEqual(gate.decide("a", "read", "prod/db")["rule"], "lock")
        self.assertEqual(gate.decide("a", "read", "dev/db")["rule"], "read")

    def test_exclusion_does_not_weaken_explicit_deny_or_priority(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "priority": 100},
                {"id": "d", "effect": "deny", "priority": -5,
                 "subject_exclude": "nobody"},
            ]
        )
        result = gate.decide("alice", "x", "y")
        self.assertEqual(result["effect"], "deny")
        self.assertEqual(result["rule"], "d")
        self.assertIn("overrides allow", result["reason"])
        # the deny rule excludes "nobody", so the allow wins there
        self.assertEqual(gate.decide("nobody", "x", "y")["rule"], "a")

    def test_exclusion_participates_in_winner_tie_break(self):
        gate = PolicyGate(
            [
                {"id": "low", "effect": "allow", "priority": 1},
                {"id": "high", "effect": "allow", "priority": 9,
                 "action_exclude": "read"},
            ]
        )
        self.assertEqual(gate.decide("s", "write", "r")["rule"], "high")
        self.assertEqual(gate.decide("s", "read", "r")["rule"], "low")

    # --- load-time validation --------------------------------------

    def _expect_exclusion_error(self, rules, index, field):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate(rules)
        message = str(ctx.exception)
        self.assertTrue(
            message.startswith("invalid_selector_exclusion"), message
        )
        self.assertIn("rule %d" % index, message)
        self.assertIn(field, message)

    def test_non_string_exclusions_rejected(self):
        for field in ("subject_exclude", "action_exclude",
                      "resource_exclude"):
            for bad in (1, 1.5, None, True, ["x"], {"k": "v"}):
                self._expect_exclusion_error(
                    [{"effect": "allow", field: bad}], 0, field
                )

    def test_error_names_first_offending_index(self):
        self._expect_exclusion_error(
            [
                {"id": "ok", "effect": "allow", "subject_exclude": "tmp*"},
                {"id": "bad", "effect": "deny", "resource_exclude": 3},
            ],
            1,
            "resource_exclude",
        )

    def test_from_json_raises_same_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate.from_json(
                '[{"effect": "allow"},'
                '{"effect": "deny", "action_exclude": ["read"]}]'
            )
        self.assertNotIsInstance(ctx.exception, PolicyConfigError)
        message = str(ctx.exception)
        self.assertTrue(message.startswith("invalid_selector_exclusion"))
        self.assertIn("rule 1", message)
        self.assertIn("action_exclude", message)

    def test_empty_string_exclusion_loads(self):
        gate = PolicyGate.from_json(
            '[{"effect": "allow", "subject_exclude": ""}]'
        )
        self.assertEqual(gate.rules[0]["subject_exclude"], "")

    def test_unknown_fields_still_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            PolicyGate([{"effect": "allow", "subject_exclud": "x"}])
        self.assertIn("unsupported field", str(ctx.exception))

    # --- trace / explain --------------------------------------------

    def test_trace_flags_are_positive_match_and_exclusion_conjunction(self):
        gate = PolicyGate(
            [
                {"id": "r", "effect": "allow",
                 "subject": "a*", "subject_exclude": "admin*",
                 "action": "read", "action_exclude": "",
                 "resource": "doc/*", "resource_exclude": "doc/x"},
            ]
        )
        excluded_subject = gate.trace("admin1", "read", "doc/a")
        ev = excluded_subject["evaluations"][0]
        self.assertFalse(ev["subject_match"])
        self.assertTrue(ev["action_match"])
        self.assertTrue(ev["resource_match"])
        self.assertFalse(ev["matched"])
        # empty-string exclusion fails the empty action only
        empty_action = gate.trace("alice", "", "doc/a")
        self.assertFalse(empty_action["evaluations"][0]["action_match"])
        excluded_resource = gate.trace("alice", "read", "doc/x")
        self.assertFalse(excluded_resource["evaluations"][0]["resource_match"])
        ok = gate.trace("alice", "read", "doc/a")
        self.assertTrue(ok["evaluations"][0]["matched"])
        self.assertTrue(ok["evaluations"][0]["selected"])
        self.assertEqual(ok["rule"], "r")

    def test_explain_lists_only_unexcluded_rules(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "resource": "data/*", "resource_exclude": "data/s*"},
                {"id": "b", "effect": "allow", "resource": "data/*"},
            ]
        )
        explanation = gate.explain("s", "x", "data/secret")
        self.assertEqual(
            explanation["matched_rules"],
            [{"id": "b", "effect": "allow", "priority": 0}],
        )

    # --- batch APIs --------------------------------------------------

    def test_batch_apis_honor_exclusions(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "resource": "data/*",
                 "resource_exclude": "data/secret*"},
            ]
        )
        requests = [
            {"subject": "s", "action": "x", "resource": "data/ok"},
            {"subject": "s", "action": "x", "resource": "data/secret9"},
        ]
        decisions = gate.decide_many(requests)
        self.assertEqual(
            [d["effect"] for d in decisions["decisions"]], ["allow", "deny"]
        )
        self.assertEqual(
            decisions["summary"], {"total": 2, "allow": 1, "deny": 1}
        )
        traces = gate.trace_many(requests)
        self.assertTrue(traces["traces"][0]["evaluations"][0]["matched"])
        self.assertFalse(traces["traces"][1]["evaluations"][0]["matched"])
        coverage = gate.coverage(requests)
        self.assertEqual(
            coverage["rules"],
            [{"id": "a", "effect": "allow", "matched": 1, "winner": 1}],
        )
        self.assertEqual(coverage["summary"]["default_deny"], 1)
        self.assertEqual(coverage["summary"]["matched_request"], 1)
        verification = gate.verify(
            [
                {"subject": "s", "action": "x", "resource": "data/ok",
                 "expected": {"effect": "allow", "rule": "a"}},
                {"subject": "s", "action": "x", "resource": "data/secret9",
                 "expected": {"effect": "deny", "rule": None}},
            ]
        )
        self.assertTrue(verification["ok"])
        self.assertEqual(
            verification["summary"], {"total": 2, "passed": 2, "failed": 0}
        )

    def test_compare_sees_exclusion_effect(self):
        baseline = PolicyGate(
            [{"id": "a", "effect": "allow", "resource": "data/*"}]
        )
        candidate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "resource": "data/*",
                 "resource_exclude": "data/secret*"},
            ]
        )
        report = baseline.compare(
            candidate,
            [
                {"subject": "s", "action": "x", "resource": "data/ok"},
                {"subject": "s", "action": "x", "resource": "data/secret9"},
            ],
        )
        self.assertEqual(report["summary"]["allow_to_deny"], 1)
        self.assertEqual(report["changes"][0]["index"], 1)
        self.assertIsNone(report["changes"][0]["after"]["rule"])

    # --- snapshot ----------------------------------------------------

    def test_unused_fields_keep_legacy_snapshot_bytes(self):
        gate = PolicyGate(
            [
                {"id": "read", "effect": "allow", "action": "read"},
                {"effect": "deny", "resource": "secret/*",
                 "tags": {"env": "prod"}},
            ]
        )
        self.assertEqual(
            gate.to_json(),
            '[{"id":"read","effect":"allow","priority":0,"subject":"*",'
            '"action":"read","resource":"*","tags":{}},'
            '{"id":"1","effect":"deny","priority":0,"subject":"*",'
            '"action":"*","resource":"secret/*","tags":{"env":"prod"}}]',
        )

    def test_exclusions_export_after_resource_in_fixed_order(self):
        gate = PolicyGate(
            [
                {"effect": "allow", "resource_exclude": "x*",
                 "subject_exclude": "tmp*",
                 "action_exclude": "", "tags": {"k": "v"}},
            ]
        )
        import json

        keys = list(json.loads(gate.to_json())[0])
        self.assertEqual(
            keys,
            ["id", "effect", "priority", "subject", "action", "resource",
             "subject_exclude", "action_exclude", "resource_exclude",
             "tags"],
        )
        document = gate.to_json()
        self.assertIn('"subject_exclude":"tmp*"', document)
        self.assertIn('"action_exclude":""', document)
        self.assertIn('"resource_exclude":"x*"', document)

    def test_fingerprint_changes_with_exclusions(self):
        plain = PolicyGate([{"effect": "allow"}])
        excluded = PolicyGate(
            [{"effect": "allow", "subject_exclude": "tmp*"}]
        )
        self.assertNotEqual(plain.fingerprint(), excluded.fingerprint())
        import hashlib

        self.assertEqual(
            excluded.fingerprint(),
            hashlib.sha256(excluded.to_json().encode("utf-8")).hexdigest(),
        )

    def test_roundtrip_preserves_exclusion_behavior(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "resource": "data/*",
                 "resource_exclude": "data/secret*", "priority": 3},
                {"id": "d", "effect": "deny", "subject_exclude": "",
                 "action_exclude": "read-all"},
            ]
        )
        loaded = PolicyGate.from_json(gate.to_json())
        self.assertEqual(loaded.to_json(), gate.to_json())
        self.assertEqual(loaded.fingerprint(), gate.fingerprint())
        requests = [
            {"subject": "s", "action": "x", "resource": "data/ok"},
            {"subject": "s", "action": "x", "resource": "data/secret1"},
            {"subject": "", "action": "read", "resource": "r"},
            {"subject": "s", "action": "read-all", "resource": "r"},
        ]
        self.assertEqual(loaded.decide_many(requests),
                         gate.decide_many(requests))
        self.assertEqual(loaded.trace_many(requests),
                         gate.trace_many(requests))
        self.assertEqual(loaded.coverage(requests), gate.coverage(requests))
        self.assertEqual(loaded.audit(), gate.audit())
        for item in requests:
            args = (item["subject"], item["action"], item["resource"])
            self.assertEqual(loaded.decide(*args), gate.decide(*args))
            self.assertEqual(loaded.explain(*args), gate.explain(*args))

    # --- audit ---------------------------------------------------------

    def test_audit_exclusion_can_remove_overlap(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "resource": "data/*"},
                {"id": "d", "effect": "deny", "resource": "data/*",
                 "resource_exclude": "data/*"},
            ]
        )
        # the deny rule's exclusion swallows every string its positive
        # pattern allows, so the pair never overlaps; the rule itself
        # is reported as unsatisfiable instead
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "unsatisfiable_rule")
        self.assertEqual(finding["rule"], "d")

    def test_audit_overlap_around_exclusion(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "resource": "data/*"},
                {"id": "d", "effect": "deny", "resource": "data/*",
                 "resource_exclude": "data/sec*"},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "effect_overlap")
        self.assertEqual(finding["winner"], "d")
        self.assertEqual(finding["witness"]["resource"], "data/")

    def test_identical_selectors_require_identical_exclusions(self):
        different = PolicyGate(
            [
                {"id": "a", "effect": "allow", "action": "read"},
                {"id": "d", "effect": "deny", "action": "read",
                 "action_exclude": "readx"},
            ]
        )
        (finding,) = different.audit()["findings"]
        self.assertEqual(finding["code"], "effect_overlap")
        same = PolicyGate(
            [
                {"id": "a", "effect": "allow", "action": "read",
                 "action_exclude": "readx"},
                {"id": "d", "effect": "deny", "action": "read",
                 "action_exclude": "readx"},
            ]
        )
        (finding,) = same.audit()["findings"]
        self.assertEqual(finding["code"], "shadowed_rule")
        self.assertEqual(finding["severity"], "error")
        self.assertEqual(finding["winner"], "d")
        self.assertEqual(finding["shadowed"], "a")
        self.assertEqual(finding["witness"]["action"], "read")

    def test_witness_avoids_both_sides_exclusions(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "subject": "[a-c]*",
                 "subject_exclude": "a*"},
                {"id": "d", "effect": "deny", "subject": "*",
                 "subject_exclude": "b?*"},
            ]
        )
        (finding,) = gate.audit()["findings"]
        # "a*" excluded by the allow, "b"+char excluded by the deny, so
        # the shortest common subject is "b"
        self.assertEqual(finding["witness"]["subject"], "b")
        self.assertWitnessTriggers(gate, finding)

    def test_witness_shortest_then_codepoint_order_with_exclusions(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "action": "?"},
                {"id": "d", "effect": "deny", "action": "*",
                 "action_exclude": "a"},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["action"], "\x00")
        self.assertWitnessTriggers(gate, finding)

    def test_unsatisfiable_dimension_means_no_finding(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "subject": "x",
                 "subject_exclude": "x"},
                {"id": "d", "effect": "deny"},
            ]
        )
        # the allow rule can never match, so the pair yields no
        # finding; the rule itself is reported as unsatisfiable
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "unsatisfiable_rule")
        self.assertEqual(finding["rule"], "a")

    def test_empty_string_exclusion_carves_out_empty_witness(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "action": "[ab]"},
                {"id": "d", "effect": "deny", "action": "*",
                 "action_exclude": ""},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["witness"]["action"], "a")
        self.assertWitnessTriggers(gate, finding)

    def test_audit_stable_and_mutation_isolated_with_exclusions(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "resource": "data/*"},
                {"id": "d", "effect": "deny", "resource": "data/*",
                 "resource_exclude": "data/sec*"},
            ]
        )
        first = gate.audit()
        for _ in range(10):
            self.assertEqual(gate.audit(), first)
        first["findings"][0]["witness"]["resource"] = "tampered"
        fresh = gate.audit()
        self.assertEqual(fresh["findings"][0]["witness"]["resource"],
                         "data/")

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
                "witness %r does not match rule %r" % (witness, rid),
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


class RuleChangeReportTest(unittest.TestCase):
    def _gates(self):
        baseline = PolicyGate(
            [
                {"id": "same", "effect": "allow", "priority": 1,
                 "subject": "u*", "tags": {"z": 1, "a": "b"}},
                {"id": "moved", "effect": "allow", "action": "read"},
                {"id": "gone", "effect": "deny", "resource": "secret/*"},
                {"id": "mod", "effect": "allow", "priority": 5,
                 "tag_presence": {"env": True}},
                {"id": "reorder", "effect": "allow"},
            ]
        )
        candidate = PolicyGate(
            [
                {"id": "same", "effect": "allow", "priority": 1,
                 "subject": "u*", "tags": {"a": "b", "z": 1}},
                {"id": "new1", "effect": "deny"},
                {"id": "reorder", "effect": "allow"},
                {"id": "moved", "effect": "allow", "action": "read"},
                {"id": "mod", "effect": "deny", "priority": 5,
                 "tag_presence": {"env": True},
                 "subject_exclude": "x*", "tags": {"k": "v"}},
            ]
        )
        return baseline, candidate

    def test_report_shape_and_ordering(self):
        baseline, candidate = self._gates()
        report = baseline.rule_change_report(candidate)
        self.assertEqual(
            list(report), ["added", "removed", "changed", "unchanged",
                           "summary"]
        )
        self.assertEqual([r["id"] for r in report["added"]], ["new1"])
        self.assertEqual([r["id"] for r in report["removed"]], ["gone"])
        self.assertEqual(report["unchanged"], ["same"])
        self.assertEqual(
            [c["id"] for c in report["changed"]],
            ["moved", "mod", "reorder"],
        )
        self.assertEqual(
            report["summary"],
            {"baseline_total": 5, "candidate_total": 5,
             "added": 1, "removed": 1, "changed": 3, "unchanged": 1},
        )

    def test_changed_entry_shape_and_fields(self):
        baseline, candidate = self._gates()
        report = baseline.rule_change_report(candidate)
        by_id = {c["id"]: c for c in report["changed"]}

        moved = by_id["moved"]
        self.assertEqual(
            list(moved),
            ["id", "before", "after", "fields",
             "before_index", "after_index"],
        )
        self.assertEqual(moved["fields"], ["declaration_order"])
        self.assertEqual((moved["before_index"], moved["after_index"]),
                         (1, 3))
        self.assertEqual(moved["before"], moved["after"])

        reorder = by_id["reorder"]
        self.assertEqual(reorder["fields"], ["declaration_order"])
        self.assertEqual((reorder["before_index"], reorder["after_index"]),
                         (4, 2))

        mod = by_id["mod"]
        self.assertEqual(
            mod["fields"],
            ["effect", "subject_exclude", "tags", "declaration_order"],
        )
        self.assertEqual((mod["before_index"], mod["after_index"]), (3, 4))
        self.assertNotIn("subject_exclude", mod["before"])
        self.assertEqual(mod["after"]["subject_exclude"], "x*")

    def test_declaration_order_only_still_changed(self):
        baseline = PolicyGate(
            [{"id": "a", "effect": "allow"},
             {"id": "b", "effect": "allow"}]
        )
        candidate = PolicyGate(
            [{"id": "b", "effect": "allow"},
             {"id": "a", "effect": "allow"}]
        )
        report = baseline.rule_change_report(candidate)
        self.assertEqual(report["unchanged"], [])
        self.assertEqual([c["id"] for c in report["changed"]], ["a", "b"])
        self.assertTrue(
            all(c["fields"] == ["declaration_order"]
                for c in report["changed"])
        )
        self.assertEqual(report["summary"]["changed"], 2)

    def test_snapshots_match_to_json_elements(self):
        import json

        baseline, candidate = self._gates()
        report = baseline.rule_change_report(candidate)
        base_json = {r["id"]: r for r in json.loads(baseline.to_json())}
        cand_json = {r["id"]: r for r in json.loads(candidate.to_json())}
        self.assertEqual(report["removed"][0], base_json["gone"])
        self.assertEqual(report["added"][0], cand_json["new1"])
        by_id = {c["id"]: c for c in report["changed"]}
        self.assertEqual(by_id["mod"]["before"], base_json["mod"])
        self.assertEqual(by_id["mod"]["after"], cand_json["mod"])
        # rule-level key order follows to_json exactly
        self.assertEqual(
            list(report["added"][0]),
            ["id", "effect", "priority", "subject", "action", "resource",
             "tags"],
        )
        self.assertEqual(
            list(by_id["mod"]["after"]),
            ["id", "effect", "priority", "subject", "action", "resource",
             "subject_exclude", "tags", "tag_presence"],
        )
        # nested tag keys are Unicode-sorted and _index never leaks
        tagged = PolicyGate([{"id": "t", "effect": "allow",
                              "tags": {"z": 1, "a": 2}}])
        other = PolicyGate([{"id": "t", "effect": "deny",
                             "tags": {"z": 1, "a": 2}}])
        changed = tagged.rule_change_report(other)["changed"][0]
        self.assertEqual(list(changed["before"]["tags"]), ["a", "z"])
        self.assertNotIn('"_index":', json.dumps(report))

    def test_field_order_in_changed_fields(self):
        baseline = PolicyGate(
            [{"id": "r", "effect": "allow", "priority": 1,
              "subject": "a", "action": "a", "resource": "a",
              "subject_exclude": "s*", "action_exclude": "s*",
              "resource_exclude": "s*",
              "tags": {"k": "1"}, "tag_patterns": {"p": "1*"},
              "tag_exclude_patterns": {"e": "1*"},
              "tag_presence": {"x": True}}]
        )
        candidate = PolicyGate(
            [{"id": "r", "effect": "deny", "priority": 2,
              "subject": "b", "action": "b", "resource": "b",
              "subject_exclude": "t*", "action_exclude": "t*",
              "resource_exclude": "t*",
              "tags": {"k": "2"}, "tag_patterns": {"p": "2*"},
              "tag_exclude_patterns": {"e": "2*"},
              "tag_presence": {"x": False}}]
        )
        fields = baseline.rule_change_report(candidate)["changed"][0]["fields"]
        self.assertEqual(
            fields,
            ["effect", "priority", "subject", "action", "resource",
             "subject_exclude", "action_exclude", "resource_exclude",
             "tags", "tag_patterns", "tag_exclude_patterns",
             "tag_presence"],
        )

    def test_selector_exclusion_added_and_removed_classified(self):
        baseline = PolicyGate(
            [{"id": "r", "effect": "allow", "subject_exclude": "a*"}]
        )
        candidate = PolicyGate(
            [{"id": "r", "effect": "allow", "action_exclude": "b*"}]
        )
        fields = baseline.rule_change_report(candidate)["changed"][0]["fields"]
        self.assertEqual(fields, ["subject_exclude", "action_exclude"])

    def test_tag_constraint_differences_classified(self):
        baseline = PolicyGate(
            [{"id": "r", "effect": "allow",
              "tag_patterns": {"env": "dev*"},
              "tag_exclude_patterns": {"x": "y*"}}]
        )
        candidate = PolicyGate(
            [{"id": "r", "effect": "allow",
              "tag_patterns": {"env": "prd*"},
              "tag_exclude_patterns": {"x": "z*"}}]
        )
        fields = baseline.rule_change_report(candidate)["changed"][0]["fields"]
        self.assertEqual(fields, ["tag_patterns",
                                  "tag_exclude_patterns"])

    def test_added_removed_follow_declaration_order(self):
        baseline = PolicyGate(
            [{"id": "b1", "effect": "allow"},
             {"id": "b2", "effect": "allow"}]
        )
        candidate = PolicyGate(
            [{"id": "c1", "effect": "allow"},
             {"id": "c2", "effect": "allow"},
             {"id": "c3", "effect": "allow"}]
        )
        report = baseline.rule_change_report(candidate)
        self.assertEqual([r["id"] for r in report["added"]],
                         ["c1", "c2", "c3"])
        reverse = candidate.rule_change_report(baseline)
        self.assertEqual([r["id"] for r in reverse["removed"]],
                         ["c1", "c2", "c3"])
        self.assertEqual([r["id"] for r in reverse["added"]],
                         ["b1", "b2"])

    def test_empty_gates(self):
        empty = PolicyGate([])
        report = empty.rule_change_report(empty)
        self.assertEqual(
            report,
            {"added": [], "removed": [], "changed": [], "unchanged": [],
             "summary": {"baseline_total": 0, "candidate_total": 0,
                         "added": 0, "removed": 0, "changed": 0,
                         "unchanged": 0}},
        )

    def test_candidate_type_error(self):
        gate = PolicyGate([])
        for bad in ([], {}, None, "gate", 1, object()):
            with self.assertRaises(TypeError):
                gate.rule_change_report(bad)

    def test_non_json_value_raises_value_error(self):
        gate = PolicyGate([{"id": "r", "effect": "allow"}])
        weird = PolicyGate([{"id": "w", "effect": "allow",
                             "tags": {"k": {1, 2}}}])
        with self.assertRaises(ValueError) as ctx:
            gate.rule_change_report(weird)
        self.assertIn("non_json_value", str(ctx.exception))
        with self.assertRaises(ValueError) as ctx:
            weird.rule_change_report(gate)
        self.assertIn("non_json_value", str(ctx.exception))

        tuple_field = PolicyGate([{"id": "r", "effect": "allow"}])
        tuple_field.rules[0]["priority"] = (1,)
        with self.assertRaises(ValueError) as ctx:
            gate.rule_change_report(tuple_field)
        self.assertIn("non_json_value", str(ctx.exception))

    def test_read_only_deterministic_and_isolated(self):
        import json

        baseline, candidate = self._gates()
        before_json = baseline.to_json()
        before_fp = baseline.fingerprint()
        first = baseline.rule_change_report(candidate)
        for _ in range(5):
            self.assertEqual(
                baseline.rule_change_report(candidate), first
            )
        first["changed"][0]["fields"].append("hacked")
        first["added"][0]["tags"]["h"] = 1
        fresh = baseline.rule_change_report(candidate)
        self.assertNotIn("hacked", fresh["changed"][0]["fields"])
        self.assertNotIn("h", fresh["added"][0]["tags"])
        self.assertEqual(baseline.to_json(), before_json)
        self.assertEqual(baseline.fingerprint(), before_fp)
        # existing decisions are untouched
        decision = baseline.decide(
            "u1", "x", "r", {"a": "b", "z": 1}
        )
        self.assertEqual(decision["rule"], "same")
        json.dumps(fresh)  # whole report is strict-JSON serializable

    def test_unchanged_despite_input_key_insertion_order(self):
        baseline = PolicyGate(
            [{"id": "r", "effect": "allow", "tags": {"z": 1, "a": 2}}]
        )
        candidate = PolicyGate.from_json(
            '[{"id":"r","effect":"allow","tags":{"a":2,"z":1}}]'
        )
        report = baseline.rule_change_report(candidate)
        self.assertEqual(report["unchanged"], ["r"])
        self.assertEqual(report["changed"], [])
        self.assertEqual(report["summary"]["unchanged"], 1)


class DiagnoseManyTests(unittest.TestCase):
    def _gate(self):
        return PolicyGate(
            [
                {"id": "admins", "effect": "allow", "priority": 10,
                 "subject": "admin-*"},
                {"id": "deny-tmp", "effect": "deny",
                 "tag_patterns": {"env": "tmp-*"}},
                {"id": "readers", "effect": "allow", "action": "read",
                 "resource_exclude": "secret-*"},
            ]
        )

    def _batch(self):
        return [
            {"subject": "admin-1", "action": "write", "resource": "doc"},
            {"subject": "bob", "action": "read", "resource": "doc",
             "tags": {"env": "tmp-1"}},
            {"subject": "bob", "action": "read", "resource": "secret-1"},
            {"subject": "bob", "action": "write", "resource": "doc",
             "tags": None},
        ]

    def test_diagnoses_match_single_diagnose_in_order(self):
        gate = self._gate()
        batch = self._batch()
        result = gate.diagnose_many(batch)
        self.assertEqual(set(result), {"diagnoses", "summary"})
        expected = [
            gate.diagnose(item["subject"], item["action"], item["resource"],
                          item.get("tags"))
            for item in batch
        ]
        self.assertEqual(result["diagnoses"], expected)
        self.assertEqual(
            [d["rule"] for d in result["diagnoses"]],
            ["admins", "deny-tmp", None, None],
        )
        # full per-rule evaluations, in declaration order, on every item
        for diagnosis in result["diagnoses"]:
            self.assertEqual(
                [e["id"] for e in diagnosis["evaluations"]],
                ["admins", "deny-tmp", "readers"],
            )

    def test_failure_classification_matches_diagnose(self):
        gate = self._gate()
        batch = [
            {"subject": "bob", "action": "read", "resource": "secret-1"},
        ]
        (diagnosis,) = gate.diagnose_many(batch)["diagnoses"]
        failures = {
            e["id"]: e["failure"] for e in diagnosis["evaluations"]
        }
        self.assertEqual(
            failures["admins"],
            {"field": "subject", "key": None, "kind": "selector_mismatch"},
        )
        self.assertEqual(
            failures["deny-tmp"],
            {"field": "tags", "key": "env",
             "kind": "tag_pattern_inapplicable"},
        )
        self.assertEqual(
            failures["readers"],
            {"field": "resource", "key": None, "kind": "selector_excluded"},
        )

    def test_summary_counts(self):
        gate = self._gate()
        summary = gate.diagnose_many(self._batch())["summary"]
        self.assertEqual(
            summary,
            {"total": 4, "allow": 1, "deny": 3, "default_deny": 2,
             "matched_request": 2},
        )

    def test_empty_batch_and_empty_rule_set(self):
        gate = self._gate()
        self.assertEqual(
            gate.diagnose_many([]),
            {"diagnoses": [],
             "summary": {"total": 0, "allow": 0, "deny": 0,
                         "default_deny": 0, "matched_request": 0}},
        )
        empty = PolicyGate([])
        result = empty.diagnose_many(
            [{"subject": "s", "action": "a", "resource": "r"}]
        )
        self.assertEqual(
            result["summary"],
            {"total": 1, "allow": 0, "deny": 1, "default_deny": 1,
             "matched_request": 0},
        )
        self.assertEqual(result["diagnoses"][0]["evaluations"], [])
        self.assertEqual(result["diagnoses"][0]["rule"], None)

    def test_tuple_batch_and_tags_variants(self):
        gate = self._gate()
        batch = (
            {"subject": "admin-1", "action": "a", "resource": "r"},
            {"subject": "admin-1", "action": "a", "resource": "r",
             "tags": None},
            {"subject": "admin-1", "action": "a", "resource": "r",
             "tags": {}},
        )
        result = gate.diagnose_many(batch)
        self.assertEqual(result["summary"]["total"], 3)
        self.assertEqual(
            result["diagnoses"],
            [gate.diagnose("admin-1", "a", "r")] * 3,
        )

    def test_validation_errors_abort_without_partial_results(self):
        gate = self._gate()
        good = {"subject": "s", "action": "a", "resource": "r"}

        with self.assertRaises(PolicyBatchError) as ctx:
            gate.diagnose_many("not-a-batch")
        self.assertEqual(ctx.exception.code, "invalid_batch")
        self.assertIsNone(ctx.exception.index)

        with self.assertRaises(PolicyBatchError) as ctx:
            gate.diagnose_many([good, 42])
        self.assertEqual(ctx.exception.code, "item_not_mapping")
        self.assertEqual(ctx.exception.index, 1)

        with self.assertRaises(PolicyBatchError) as ctx:
            gate.diagnose_many([dict(good, bogus=1)])
        self.assertEqual(ctx.exception.code, "unknown_field")
        self.assertEqual(ctx.exception.field, "bogus")

        with self.assertRaises(PolicyBatchError) as ctx:
            gate.diagnose_many([{"subject": "s", "action": "a"}])
        self.assertEqual(ctx.exception.code, "missing_field")
        self.assertEqual(ctx.exception.field, "resource")

        with self.assertRaises(PolicyBatchError) as ctx:
            gate.diagnose_many([dict(good, action=1)])
        self.assertEqual(ctx.exception.code, "invalid_field_type")
        self.assertEqual(ctx.exception.field, "action")

        with self.assertRaises(PolicyBatchError) as ctx:
            gate.diagnose_many([dict(good, tags=[1])])
        self.assertEqual(ctx.exception.code, "invalid_field_type")
        self.assertEqual(ctx.exception.field, "tags")

    def test_read_only_isolated_and_json_equivalent(self):
        gate = self._gate()
        batch = self._batch()
        before_json = gate.to_json()
        before_fp = gate.fingerprint()
        first = gate.diagnose_many(batch)
        for _ in range(3):
            self.assertEqual(gate.diagnose_many(batch), first)
        # mutating the report never affects later calls
        first["diagnoses"][0]["evaluations"][0]["selected"] = "hacked"
        first["diagnoses"][0]["effect"] = "hacked"
        first["summary"]["total"] = 99
        fresh = gate.diagnose_many(batch)
        self.assertEqual(fresh["summary"]["total"], 4)
        self.assertNotEqual(
            fresh["diagnoses"][0]["evaluations"][0]["selected"], "hacked"
        )
        self.assertEqual(fresh["diagnoses"][0]["effect"], "allow")
        # rules and inputs untouched
        self.assertEqual(gate.to_json(), before_json)
        self.assertEqual(gate.fingerprint(), before_fp)
        self.assertNotIn("tags", batch[0])
        self.assertIsNone(batch[3]["tags"])
        # direct construction and from_json agree value for value
        loaded = PolicyGate.from_json(gate.to_json())
        self.assertEqual(loaded.diagnose_many(batch), fresh)


class UnsatisfiableRuleAuditTest(unittest.TestCase):
    def test_positive_pattern_matching_no_string(self):
        gate = PolicyGate([{"id": "a", "effect": "allow", "resource": "[z-a]"}])
        report = gate.audit()
        self.assertEqual(
            report["summary"], {"total": 1, "error": 1, "warning": 0}
        )
        (finding,) = report["findings"]
        self.assertEqual(
            finding,
            {
                "code": "unsatisfiable_rule",
                "severity": "error",
                "rule": "a",
                "other_rule": None,
                "winner": None,
                "shadowed": None,
                "reason": finding["reason"],
                "witness": None,
            },
        )
        self.assertIn("'resource'", finding["reason"])
        self.assertIn("matches no string", finding["reason"])

    def test_exclusion_swallowing_every_value(self):
        cases = [
            ("x", "x"),
            ("*", "*"),
            ("data/*", "data/*"),
            ("", ""),
            ("[a-c]*", "?*"),
        ]
        for positive, exclude in cases:
            gate = PolicyGate(
                [
                    {"id": "a", "effect": "allow", "subject": positive,
                     "subject_exclude": exclude},
                ]
            )
            report = gate.audit()
            self.assertEqual(
                report["summary"], {"total": 1, "error": 1, "warning": 0},
                "subject %r excluded by %r must be unsatisfiable"
                % (positive, exclude),
            )
            (finding,) = report["findings"]
            self.assertEqual(finding["code"], "unsatisfiable_rule")
            self.assertEqual(finding["rule"], "a")
            self.assertIn("'subject'", finding["reason"])
            self.assertIn("excluded by 'subject_exclude'", finding["reason"])

    def test_partial_exclusion_stays_reachable(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "subject": "[a-c]*",
                 "subject_exclude": "a*"},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_first_failing_field_follows_unicode_order(self):
        # action < resource < subject < tag_patterns in Unicode order
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "subject": "[z-a]", "action": "[z-a]",
                 "resource": "[z-a]",
                 "tag_patterns": {"env": "[z-a]"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertIn("'action'", finding["reason"])

        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "subject": "[z-a]", "resource": "[z-a]",
                 "tag_patterns": {"env": "[z-a]"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertIn("'resource'", finding["reason"])

        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "subject": "[z-a]", "tag_patterns": {"env": "[z-a]"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertIn("'subject'", finding["reason"])

    def test_tag_patterns_matching_no_string(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_patterns": {"env": "[!\x00-\U0010ffff]"}},
            ]
        )
        (finding,) = gate.audit()["findings"]
        self.assertEqual(finding["code"], "unsatisfiable_rule")
        self.assertIn("'tag_patterns'", finding["reason"])
        self.assertIn("'env'", finding["reason"])
        self.assertIn("matches no string", finding["reason"])

    def test_exact_presence_and_exclusion_only_keys_stay_reachable(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow",
                 "tag_exclude_patterns": {"env": "*"}},
                {"id": "b", "effect": "allow",
                 "tag_presence": {"env": True, "tmp": False}},
                {"id": "c", "effect": "allow", "tags": {"env": "prod"}},
            ]
        )
        self.assertEqual(gate.audit()["findings"], [])

    def test_one_finding_per_rule_in_declaration_order(self):
        gate = PolicyGate(
            [
                {"id": "ok", "effect": "allow"},
                {"id": "u1", "effect": "allow", "subject": "x",
                 "subject_exclude": "x", "action": "[z-a]"},
                {"id": "u2", "effect": "deny", "resource": "[z-a]"},
            ]
        )
        findings = gate.audit()["findings"]
        self.assertEqual([f["rule"] for f in findings], ["u1", "u2"])
        self.assertEqual(
            [f["code"] for f in findings],
            ["unsatisfiable_rule", "unsatisfiable_rule"],
        )
        # u1 fails on two dimensions but is reported only once, on the
        # first field in Unicode key order
        self.assertIn("'action'", findings[0]["reason"])

    def test_unsatisfiable_findings_precede_pair_findings(self):
        gate = PolicyGate(
            [
                {"id": "a", "effect": "allow", "resource": "data/*"},
                {"id": "u", "effect": "allow", "subject": "x",
                 "subject_exclude": "x"},
                {"id": "d", "effect": "deny", "resource": "data/sec*"},
            ]
        )
        report = gate.audit()
        self.assertEqual(
            report["summary"], {"total": 2, "error": 2, "warning": 0}
        )
        findings = report["findings"]
        self.assertEqual(
            [f["code"] for f in findings],
            ["unsatisfiable_rule", "effect_overlap"],
        )
        self.assertEqual(findings[0]["rule"], "u")
        self.assertEqual(findings[0]["severity"], "error")
        self.assertEqual(
            (findings[1]["rule"], findings[1]["other_rule"]), ("a", "d")
        )

    def test_identical_unsatisfiable_rules_yield_no_pair_finding(self):
        gate = PolicyGate(
            [
                {"id": "u1", "effect": "allow", "subject": "x",
                 "subject_exclude": "x"},
                {"id": "u2", "effect": "deny", "subject": "x",
                 "subject_exclude": "x"},
            ]
        )
        findings = gate.audit()["findings"]
        self.assertEqual(
            [f["code"] for f in findings],
            ["unsatisfiable_rule", "unsatisfiable_rule"],
        )
        self.assertEqual([f["rule"] for f in findings], ["u1", "u2"])

    def test_from_json_equivalent_stable_and_mutation_isolated(self):
        rules = [
            {"id": "a", "effect": "allow", "resource": "data/*"},
            {"id": "u", "effect": "deny", "action": "[z-a]",
             "tag_patterns": {"env": "prod-*"}},
        ]
        gate = PolicyGate(rules)
        loaded = PolicyGate.from_json(gate.to_json())
        self.assertEqual(gate.audit(), loaded.audit())
        first = gate.audit()
        for _ in range(5):
            self.assertEqual(gate.audit(), first)
        first["findings"][0]["reason"] = "tampered"
        first["summary"]["total"] = 99
        fresh = gate.audit()
        self.assertNotEqual(fresh["findings"][0]["reason"], "tampered")
        self.assertEqual(fresh["summary"]["total"], 1)

    def test_decisions_and_other_views_unaffected(self):
        gate = PolicyGate(
            [
                {"id": "u", "effect": "allow", "subject": "x",
                 "subject_exclude": "x"},
                {"id": "a", "effect": "allow", "priority": 5},
            ]
        )
        before = gate.decide("s", "read", "doc")
        gate.audit()
        self.assertEqual(gate.decide("s", "read", "doc"), before)
        self.assertEqual(
            before,
            {"effect": "allow", "rule": "a",
             "reason": "matched allow rule 'a' (priority 5)"},
        )
        self.assertEqual(
            gate.decide("x", "read", "doc")["rule"], "a"
        )


if __name__ == "__main__":
    unittest.main()
