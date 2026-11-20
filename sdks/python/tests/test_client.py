import ssl
import unittest
import urllib.request

from qadamar import (
    MASKED_TEXT, PdpClient, PdpHttpError, PdpNetworkError, PdpResponseError, PepClient, PepError, create_pep_client,
)
from qadamar.client import build_opener

from fake_pdp import FakePdp

API_KEY = "unit-test-api-key"
EVALUATION = {"decision": True, "context": {
    "rules": ["viewer"], "reasons": ["allowed"], "policy_version": "pv.test", "would_deny": [],
    "obligations": {"redact": ["informant_name"], "maskClasses": ["finance.amount"], "notify": []}}}
REQUEST = {"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"},
           "resource": {"type": "case", "id": "CASE-14"},
           "context": {"network": "trusted", "networkSensorId": "sensor-1", "attestations": {"network": "signed-network-jws"}}}
BINDING = {"audience": "http://backend:8080", "method": "GET", "path": "/cases/CASE-14",
           "bodySha256": "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"}
REFS = {"results": [{"type": "case", "id": "CASE-14"}], "page": {"next_token": ""}}
EXPLAIN = {"decision": True, "rules": ["RBAC.viewer"], "reasons": [], "obligations": EVALUATION["context"]["obligations"],
           "trace": [{"stage": "rbac", "rule": "RBAC.viewer", "outcome": "pass"}], "wouldDeny": [], "policyVersion": "pv.test"}
REGISTERED = {"items": [{"type": "case", "id": "CASE-100", "status": "created", "version": 1}],
              "counts": {"created": 1, "updated": 0, "unchanged": 0, "retired": 0, "proposed": 0}}
RECORD = {"type": "case", "id": "CASE-100", "level": 1, "compartments": [], "integrity": "system", "contentClasses": []}


class Client(unittest.TestCase):
    def setUp(self):
        self.pdp = FakePdp()
        self.client = PepClient(self.pdp.url + "/", API_KEY)

    def tearDown(self):
        self.pdp.close()

    def test_every_route_posts_json_with_bearer_auth_and_returns_validated_answers(self):
        routes = [
            ("evaluate", "/access/v1/evaluation", REQUEST, EVALUATION),
            ("evaluate_batch", "/access/v1/evaluations", {**REQUEST, "evaluations": [{}]}, {"evaluations": [EVALUATION]}),
            ("search_resources", "/access/v1/search/resource", {**REQUEST, "resource": {"type": "case"}}, REFS),
            ("search_subjects", "/access/v1/search/subject", {**REQUEST, "subject": {"type": "user"}}, REFS),
            ("search_actions", "/access/v1/search/action", REQUEST, {"results": [{"name": "read"}]}),
            ("explain", "/x/v1/explain", REQUEST, EXPLAIN),
            ("filter", "/x/v1/filter", {**REQUEST, "resource": {"type": "case"}, "columns": {"resource.id": "id"}},
             {"residual": {"op": "true"}, "sql": {"text": "TRUE", "params": [1, "a", None]}}),
            ("consume_token", "/x/v1/tokens/consume", {"token": "t", "action": "approve", "resource": REQUEST["resource"],
                                                       "resourceVersion": 4}, {"ok": True, "reservation": "r-1"}),
            ("report_outcome", "/x/v1/tokens/outcome", {"reservation": "r-1", "outcome": "completed"},
             {"ok": True, "reservation": "r-1", "outcome": "completed"}),
            ("evaluate_asserted", "/x/v1/assertions/evaluation", {**REQUEST, "request": BINDING}, {**EVALUATION, "assertion": "a.b.c"}),
            ("assert_list", "/x/v1/assertions/list", {**REQUEST, "resource": {"type": "case"}, "request": BINDING},
             {"decision": True, "policy_version": "pv", "assertion": "a.b.c"}),
            ("list_resources", "/x/v1/resources/list", {"type": "case", "limit": 10},
             {"resources": [{"type": "case", "id": "CASE-1", "version": 3}], "next_cursor": ""}),
        ]
        for method, path, body, answer in routes:
            with self.subTest(method=method):
                self.pdp.answer(answer)
                self.assertEqual(getattr(self.client, method)(body), answer)
                sent = self.pdp.requests[-1]
                self.assertEqual((sent["method"], sent["path"], sent["body"]), ("POST", path, body))
                headers = {k.lower(): v for k, v in sent["headers"].items()}
                self.assertEqual(headers["authorization"], f"Bearer {API_KEY}")
                self.assertEqual(headers["content-type"], "application/json")
                self.assertEqual(headers["accept"], "application/json")
        self.assertIs(PdpClient, PepClient)
        self.assertIsInstance(create_pep_client(self.pdp.url, API_KEY, timeout=1), PepClient)
        self.assertNotIn(API_KEY, repr(self.client))

    def test_open_and_close_session_pass_the_token_and_validate_answers(self):
        opened = {"token": "session-jws", "sessionId": "pdp-id", "issuedAt": "2026-11-08T10:00:00.000Z",
                  "expiresAt": "2026-11-08T11:00:00.000Z", "idleSeconds": 900}
        self.pdp.answer(opened, 201)
        self.assertEqual(self.client.open_session({"type": "user", "id": "carol"}), opened)
        self.assertEqual(self.pdp.requests[-1]["body"], {"subject": {"type": "user", "id": "carol"}})
        self.pdp.answer({"ok": True})
        self.assertEqual(self.client.close_session(opened["token"]), {"ok": True})
        self.assertEqual(self.pdp.requests[-1]["body"], {"token": opened["token"]})
        self.assertEqual([r["path"] for r in self.pdp.requests], ["/x/v1/sessions", "/x/v1/sessions/close"])
        for bad in [{**opened, "idleSeconds": 0}, {**opened, "extra": True}]:
            self.pdp.answer(bad, 201)
            with self.assertRaises(PdpResponseError):
                self.client.open_session({"type": "user", "id": "carol"})
        self.pdp.answer({"ok": False})
        with self.assertRaises(PdpResponseError):
            self.client.close_session("session-jws")

    def test_client_enforce_evaluates_then_applies_obligations(self):
        self.pdp.answer(EVALUATION)
        record = {"informant_name": "Ann", "content": [{"class": "finance.amount", "text": "AED 1"}]}
        self.assertEqual(self.client.enforce(REQUEST, record),
                         {"informant_name": None, "content": [{"class": "finance.amount", "text": MASKED_TEXT}]})
        self.assertEqual(record["informant_name"], "Ann")

    def test_http_errors_expose_status_code_and_retry_after_without_response_secrets(self):
        self.pdp.answer({"error": "unauthenticated", "message": f"do not echo {API_KEY}"}, 401, {"retry-after": "12"})
        with self.assertRaises(PdpHttpError) as caught:
            self.client.evaluate(REQUEST)
        error = caught.exception
        self.assertEqual((error.status, error.code, error.retry_after), (401, "unauthenticated", "12"))
        self.assertNotIn(API_KEY, f"{error!r} {error} {vars(error)}")
        cases = [(b"<html>oops</html>", {}, "http_error", None), ({"error": "Bad Code!"}, {"retry-after": "x" * 65}, "http_error", None),
                 ({"error": "rate_limited"}, {"retry-after": "Wed, 11 Nov 2026 10:00:00 GMT"}, "rate_limited", "Wed, 11 Nov 2026 10:00:00 GMT")]
        for payload, headers, code, retry in cases:
            self.pdp.answer(payload, 429, headers)
            with self.assertRaises(PdpHttpError) as caught:
                self.client.evaluate(REQUEST)
            self.assertEqual((caught.exception.status, caught.exception.code, caught.exception.retry_after), (429, code, retry))

    def test_redirects_are_not_followed(self):
        target = FakePdp()
        try:
            self.pdp.answer({}, 307, {"location": target.url + "/access/v1/evaluation"})
            with self.assertRaises(PdpHttpError) as caught:
                self.client.evaluate(REQUEST)
            self.assertEqual(caught.exception.status, 307)
            self.assertEqual(target.requests, [], "the bearer key never reaches the redirect target")
        finally:
            target.close()

    def test_malformed_success_json_and_shapes_are_rejected_for_each_family(self):
        for raw in (b"{", b"NaN", b'{"decision": true, "context": Infinity}', b"\xff"):
            self.pdp.answer(raw)
            with self.subTest(raw=raw), self.assertRaises(PdpResponseError):
                self.client.evaluate(REQUEST)
        invalid = [
            ("evaluate", REQUEST, {"decision": True}),
            ("evaluate", REQUEST, {**EVALUATION, "context": {**EVALUATION["context"], "policy_version": ""}}),
            ("evaluate_batch", {"evaluations": []}, {"evaluations": [{"decision": True}]}),
            ("search_resources", REQUEST, {"results": [{"type": "case"}], "page": {"next_token": ""}}),
            ("search_subjects", REQUEST, {"results": [], "page": {}}),
            ("search_actions", REQUEST, {"results": [{"id": "read"}]}),
            ("explain", REQUEST, {**EXPLAIN, "extra": 1}),
            ("explain", REQUEST, {**EXPLAIN, "trace": ["not an object"]}),
            ("filter", REQUEST, {"residual": "true", "sql": {"text": "TRUE", "params": []}}),
            ("consume_token", {}, {"ok": False}),
            ("consume_token", {}, {"ok": True, "reservation": 7}),
            ("report_outcome", {}, {"ok": True, "reservation": "r", "outcome": "done"}),
            ("list_resources", {"type": "case"}, {"resources": [{"type": "case", "id": "x", "version": "1"}], "next_cursor": ""}),
        ]
        for method, body, answer in invalid:
            self.pdp.answer(answer)
            with self.subTest(method=method, answer=answer), self.assertRaises(PdpResponseError):
                getattr(self.client, method)(body)

    def test_network_errors_and_timeouts_are_sanitized_and_distinguishable(self):
        closed = FakePdp()
        url = closed.url
        closed.close()
        with self.assertRaises(PdpNetworkError) as caught:
            PepClient(url, API_KEY).evaluate(REQUEST)
        self.assertEqual(caught.exception.code, "network_error")
        self.assertNotIn(API_KEY, str(caught.exception))
        self.pdp.answer(EVALUATION)
        self.pdp.set_delay(0.5)
        with self.assertRaises(PdpNetworkError) as caught:
            PepClient(self.pdp.url, API_KEY, timeout=0.1).evaluate(REQUEST)
        self.assertEqual(caught.exception.code, "request_timeout")

    def test_invalid_construction_and_unserializable_requests_fail_without_exposing_data(self):
        for base_url in ["file:///tmp/pdp", "https://user:pass@pdp.test", "https://pdp.test/?key=secret", "https://pdp.test/#x",
                         "https://pdp.test?", "pdp.test", "https://", "https://pdp.test:99999", None]:
            with self.subTest(base_url=base_url), self.assertRaises(TypeError):
                PepClient(base_url, API_KEY)
        for key in ["", f"bad\n{API_KEY}", None]:
            with self.assertRaises(TypeError):
                PepClient("https://pdp.test", key)
        for timeout in [0, -1, float("inf"), True]:
            with self.assertRaises(TypeError):
                PepClient("https://pdp.test", API_KEY, timeout=timeout)
        circular = {"secret": "do-not-log"}
        circular["request"] = circular
        for body in (circular, {"x": float("nan")}, {"x": object()}):
            with self.assertRaises(PepError) as caught:
                self.client.evaluate(body)
            self.assertEqual(caught.exception.code, "invalid_request")
            self.assertNotIn("do-not-log", str(caught.exception))
        self.assertEqual(self.pdp.requests, [])

    def test_tls_is_verified_by_default_and_a_custom_ca_file_is_loaded(self):
        https = next(h for h in build_opener().handlers if isinstance(h, urllib.request.HTTPSHandler))
        self.assertEqual(https._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(https._context.check_hostname)
        with self.assertRaises((OSError, ssl.SSLError)):
            PepClient("https://pdp.test", API_KEY, ca_file="/nonexistent/ca.pem")

    def test_assertion_routes_an_allow_must_carry_an_assertion_and_a_deny_must_not(self):
        body = {**REQUEST, "request": BINDING}
        for bad in [EVALUATION, {**EVALUATION, "decision": False, "assertion": "a.b.c"}, {**EVALUATION, "assertion": ""},
                    {**EVALUATION, "assertion": "x", "extra": 1}]:
            self.pdp.answer(bad)
            with self.assertRaises(PdpResponseError):
                self.client.evaluate_asserted(body)
        self.pdp.answer({**EVALUATION, "decision": False})
        self.assertFalse(self.client.evaluate_asserted(body)["decision"])
        listed = {**REQUEST, "resource": {"type": "case"}, "request": BINDING}
        self.pdp.answer({"decision": False, "policy_version": "pv"})
        self.assertEqual(self.client.assert_list(listed), {"decision": False, "policy_version": "pv"})
        for bad in [{"decision": True, "policy_version": "pv"}, {"decision": False, "policy_version": "pv", "assertion": "a"},
                    {"decision": "yes", "policy_version": "pv"}, {"decision": False, "policy_version": "pv", "x": 1}]:
            self.pdp.answer(bad)
            with self.assertRaises(PdpResponseError):
                self.client.assert_list(listed)

    def test_resource_registration_checks_requests_before_they_leave_and_answers_before_they_return(self):
        self.pdp.answer(REGISTERED, 201)
        self.assertEqual(self.client.register_resource(RECORD)["items"][0]["status"], "created")
        self.client.retire_resource({"type": "case", "id": "CASE-100"})
        self.client.sync_resources({"resources": [RECORD], "retire": [{"type": "case", "id": "CASE-7"}]})
        self.assertEqual([r["path"] for r in self.pdp.requests], ["/x/v1/resources", "/x/v1/resources/retire", "/x/v1/resources/sync"])
        self.assertEqual(self.pdp.requests[0]["body"], {"resource": RECORD})
        sent = len(self.pdp.requests)
        bad_records = [{**RECORD, "level": 4}, {**RECORD, "level": True}, {**RECORD, "compartments": ["a", "a"]},
                       {**RECORD, "integrity": "trusted"}, {k: v for k, v in RECORD.items() if k != "contentClasses"},
                       {**RECORD, "owner": None}, {**RECORD, "parent": {"type": "folder"}}, {**RECORD, "version": -1},
                       {**RECORD, "attrs": []}, {**RECORD, "extra": 1}, {**RECORD, "id": "bad\nid"}, {**RECORD, "id": "x" * 257}]
        for record in bad_records:
            with self.subTest(record=record), self.assertRaises(PepError) as caught:
                self.client.register_resource(record)
            self.assertEqual(caught.exception.code, "invalid_request")
        for call, body in [("retire_resource", {"type": "case"}), ("sync_resources", {}), ("sync_resources", {"resources": [RECORD] * 1001}),
                           ("sync_resources", {"retire": "CASE-7"}), ("list_resources", {"type": ""}),
                           ("list_resources", {"type": "case", "limit": 0}), ("list_resources", {"type": "case", "cursor": 5})]:
            with self.subTest(call=call), self.assertRaises(PepError):
                getattr(self.client, call)(body)
        self.assertEqual(len(self.pdp.requests), sent, "refused requests never left")
        for answer in [{"items": [{"type": "case", "id": "x", "status": "proposed"}], "counts": REGISTERED["counts"]},
                       {"items": [{"type": "case", "id": "x", "status": "created", "changeId": "c"}], "counts": REGISTERED["counts"]},
                       {"items": [], "counts": {"created": 1}}, {"items": [{"type": "case", "id": "x", "status": "gone"}], "counts": REGISTERED["counts"]}]:
            self.pdp.answer(answer)
            with self.assertRaises(PdpResponseError):
                self.client.register_resource(RECORD)
        proposed = {"items": [{"type": "case", "id": "x", "status": "proposed", "changeId": "c-1", "ignored": True}], "counts": REGISTERED["counts"]}
        self.pdp.answer(proposed, 202)
        self.assertEqual(self.client.register_resource(RECORD)["items"], [{"type": "case", "id": "x", "status": "proposed", "changeId": "c-1"}])


if __name__ == "__main__":
    unittest.main()
