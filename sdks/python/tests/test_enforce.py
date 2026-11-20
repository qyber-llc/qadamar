import copy
import datetime
import unittest

from qadamar import (
    MASKED_TEXT, AccessDeniedError, ObligationError, PdpResponseError, PepError, enforce,
)


def allowed(**obligations):
    return {"decision": True, "context": {
        "rules": ["viewer"], "reasons": ["fixture"],
        "obligations": {"redact": [], "maskClasses": [], "notify": [], **obligations},
        "policy_version": "pv.test", "would_deny": []}}


class Enforce(unittest.TestCase):
    def test_allow_deep_copies_and_redacts_top_level_and_dotted_fields(self):
        original = {"title": "Case", "informant_name": "Sensitive Name", "nested": {"secret": "hidden", "visible": 42},
                    "content": [{"class": "public.summary", "text": "summary"}]}
        result = enforce(allowed(redact=["informant_name", "nested.secret"]), original)
        self.assertIsNot(result, original)
        self.assertIsNot(result["nested"], original["nested"])
        self.assertIsNot(result["content"], original["content"])
        self.assertIsNone(result["informant_name"])
        self.assertEqual(result["nested"], {"secret": None, "visible": 42})
        self.assertEqual(original["informant_name"], "Sensitive Name")
        self.assertEqual(original["nested"]["secret"], "hidden")

    def test_field_allowlist_keeps_selected_dotted_fields_and_composes_with_redaction(self):
        record = {"title": "Case", "private": "no", "nested": {"visible": "yes", "secret": "no", "amount": 20}}
        before = copy.deepcopy(record)
        self.assertEqual(enforce(allowed(fieldAllowlist=["title", "nested.visible"]), record),
                         {"title": "Case", "nested": {"visible": "yes"}})
        self.assertEqual(enforce(allowed(fieldAllowlist=["nested"], redact=["nested.secret"]), record),
                         {"nested": {"visible": "yes", "secret": None, "amount": 20}})
        self.assertEqual(enforce(allowed(fieldAllowlist=[]), record), {})
        self.assertEqual(record, before)

    def test_mask_classes_masks_every_matching_fragment_and_keeps_other_text(self):
        original = {"content": [{"class": "finance.amount", "text": "AED 900,000"},
                                {"class": "public.summary", "text": "Procurement summary"},
                                {"class": "finance.amount", "text": "AED 12"}]}
        result = enforce(allowed(maskClasses=["finance.amount"]), original)
        self.assertEqual(result["content"], [{"class": "finance.amount", "text": MASKED_TEXT},
                                             {"class": "public.summary", "text": "Procurement summary"},
                                             {"class": "finance.amount", "text": MASKED_TEXT}])
        self.assertEqual(original["content"][0]["text"], "AED 900,000")

    def test_masking_refuses_absent_unlocated_or_malformed_content(self):
        records = [{}, {"content": []}, {"content": [{"class": "public.summary", "text": "safe"}]},
                   {"content": "AED 900,000"}, {"content": [{"class": "finance.amount"}]},
                   {"content": [{"text": "AED 900,000"}]}, {"content": [{"class": "finance.amount", "text": None}]}]
        for record in records:
            with self.subTest(record=record), self.assertRaises(ObligationError):
                enforce(allowed(maskClasses=["finance.amount"]), record)
        with self.assertRaises(ObligationError):
            enforce(allowed(fieldAllowlist=["title"], maskClasses=["finance.amount"]), {"title": "no content returned"})

    def test_deny_refuses_and_never_mutates_the_record(self):
        record = {"informant_name": "Sensitive Name"}
        with self.assertRaises(AccessDeniedError) as caught:
            enforce({**allowed(), "decision": False}, record)
        self.assertEqual(caught.exception.code, "access_denied")
        self.assertNotIn("Sensitive Name", str(caught.exception))
        self.assertEqual(record, {"informant_name": "Sensitive Name"})

    def test_malformed_decisions_and_unknown_obligation_keys_fail_closed(self):
        good = allowed()
        context = good["context"]
        malformed = [
            None, {}, {"decision": "true"}, {"decision": True}, {**good, "context": None}, {**good, "extra": 1},
            {**good, "context": {**context, "obligations": {"redact": "informant_name", "maskClasses": [], "notify": []}}},
            {**good, "context": {**context, "obligations": {"redact": [], "maskClasses": [], "notify": [], "unexpected": []}}},
            {**good, "context": {**context, "rules": "viewer"}},
            {**good, "context": {**context, "policy_version": 7}},
            {**good, "decision": 1},
        ]
        for decision in malformed:
            with self.subTest(decision=decision), self.assertRaises(PepError) as caught:
                enforce(decision, {"value": "not released"})
            self.assertIsInstance(caught.exception, (PdpResponseError, AccessDeniedError))

    def test_notify_refuses_and_decision_token_metadata_does_not_alter_a_record(self):
        with self.assertRaises(ObligationError):
            enforce(allowed(notify=["security-officer"]), {"value": 1})
        self.assertEqual(enforce(allowed(decisionToken={"ttlSeconds": 15, "resourceVersion": 8}), {"value": 1},
                                 decision_token_consumed=True), {"value": 1})
        for token in ({"ttlSeconds": 0, "resourceVersion": 8}, {"ttlSeconds": 15}, {"ttlSeconds": 15, "resourceVersion": 1.5},
                      {"ttlSeconds": True, "resourceVersion": None}, {"ttlSeconds": 15, "resourceVersion": None, "postState": False}):
            with self.subTest(token=token), self.assertRaises(PdpResponseError):
                enforce(allowed(decisionToken=token), {"value": 1})

    def test_field_paths_reject_prototype_related_or_malformed_segments(self):
        for field in ["__proto__.secret", "constructor.prototype.secret", ".secret", "secret.", "a..b"]:
            with self.subTest(field=field), self.assertRaises(ObligationError):
                enforce(allowed(redact=[field]), {"value": 1})
        self.assertEqual(enforce(allowed(redact=["toString", "nested.missing", "value.deeper"]), {"value": 1}), {"value": 1})
        # an array on the path cannot be redacted by key: refuse rather than release it unredacted
        with self.assertRaises(ObligationError):
            enforce(allowed(redact=["owner.ssn"]), {"owner": [{"ssn": "123"}]})

    def test_non_json_cyclic_non_finite_and_too_deep_records_are_refused(self):
        cyclic = {}
        cyclic["self"] = cyclic
        deep = cursor = {}
        for _ in range(110):
            cursor["next"] = {}
            cursor = cursor["next"]
        invalid = [{"value": object()}, {"value": {1, 2}}, {"value": b"bytes"}, {"value": float("nan")},
                   {"value": float("inf")}, {"value": datetime.date(2026, 1, 1)}, {1: "non-string key"}, cyclic, deep,
                   ["not", "an", "object"]]
        for record in invalid:
            with self.subTest(record=type(record)), self.assertRaises(ObligationError):
                enforce(allowed(), record)
        shared = {"a": 1}
        self.assertEqual(enforce(allowed(), {"x": shared, "y": shared, "t": (1, 2)}),
                         {"x": {"a": 1}, "y": {"a": 1}, "t": [1, 2]}, "a shared value is not a cycle")


if __name__ == "__main__":
    unittest.main()


class EnforceDecisionToken(unittest.TestCase):
    def test_decision_token_refused_unless_consumption_is_acknowledged_and_notify_stays_refused(self):
        decision = allowed(decisionToken={"ttlSeconds": 60, "resourceVersion": 1})
        with self.assertRaisesRegex(ObligationError, "single-use"):
            enforce(decision, {"a": 1})
        self.assertEqual(enforce(decision, {"a": 1}, decision_token_consumed=True), {"a": 1})
        with self.assertRaises(ObligationError):
            enforce(allowed(notify=["x"]), {"a": 1}, decision_token_consumed=True)
