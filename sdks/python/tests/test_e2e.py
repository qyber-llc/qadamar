"""End to end against the real PDP: `node packages/pdp-http/src/main.ts`, demo profile on 127.0.0.1, a temporary
DATA_DIR. Skipped when node (or the repository around this SDK) is not available. Credentials are read from
INITIAL-CREDENTIALS.txt and never printed."""
import calendar
import json
import os
import queue
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.request
from pathlib import Path

from qadamar import (
    MASKED_TEXT, AccessDeniedError, AssertionVerifier, GateAssertionError, PdpHttpError, PepClient, body_sha256,
)
from qadamar.client import build_opener

ROOT = Path(__file__).resolve().parents[3]
MAIN = ROOT / "packages" / "pdp-http" / "src" / "main.ts"
NODE = shutil.which("node")
CLOCK = (2026, 11, 8, 10, 0, 0)
AUDIENCE = "http://127.0.0.1:9999"


def evaluation(subject="bob", resource="CASE-14", action="read", network=None):
    request = {"subject": {"type": "user", "id": subject}, "action": {"name": action},
               "resource": {"type": "payment" if resource.startswith("PAY") else "case", "id": resource}}
    return {**request, "context": {"network": network}} if network else request


@unittest.skipUnless(NODE and MAIN.exists(), "node or the PDP sources are not available")
class RealPdp(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data_dir = tempfile.mkdtemp(prefix="gate-pysdk-")
        env = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", cls.data_dir), "DATA_DIR": cls.data_dir,
               "PORT": "0", "HOST": "127.0.0.1", "GATE_PROFILE": "demo", "CLOCK": "fixed:2026-11-08T10:00:00Z",
               "SOD_HISTORY": "caller"}  # the token test asserts its maker (makerId), as the TypeScript e2e does
        cls.process = subprocess.Popen([NODE, str(MAIN)], cwd=ROOT, env=env, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True)
        try:
            cls.url = cls._listening_url()
            with open(os.path.join(cls.data_dir, "INITIAL-CREDENTIALS.txt"), encoding="utf-8") as file:
                credentials = json.load(file)
        except BaseException:
            cls._stop()  # tearDownClass does not run when setUpClass fails or skips
            raise
        cls.pep = PepClient(cls.url, credentials["pepApiKey"])
        cls.lina_password = credentials["passwords"]["lina"]

    @classmethod
    def _listening_url(cls):
        lines: "queue.Queue[str]" = queue.Queue()
        threading.Thread(target=lambda: [lines.put(line) for line in cls.process.stdout], daemon=True).start()
        output = []
        while True:
            try:
                line = lines.get(timeout=30)
            except queue.Empty:
                raise RuntimeError("the PDP did not start within 30 s") from None
            output.append(line)
            if line.startswith("PDP listening at "):
                return line.split()[-1]
            if cls.process.poll() is not None and lines.empty():
                if "EPERM" in "".join(output):
                    raise unittest.SkipTest("the sandbox forbids listening on localhost (EPERM)")
                raise RuntimeError("the PDP exited at start")

    @classmethod
    def _stop(cls):
        cls.process.terminate()
        try:
            cls.process.wait(10)
        except subprocess.TimeoutExpired:
            cls.process.kill()
        shutil.rmtree(cls.data_dir, ignore_errors=True)

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    def test_reference_pep_redacts_masks_and_refuses_a_deny(self):
        request = evaluation("bob", "CASE-14", network="trusted")
        decision = self.pep.evaluate(request)
        self.assertTrue(decision["decision"])
        self.assertEqual(decision["context"]["obligations"]["redact"], ["informant_name"])
        self.assertEqual(decision["context"]["obligations"]["maskClasses"], ["finance.amount"])
        self.assertTrue(decision["context"]["policy_version"].startswith("pv."))
        original = {"id": "CASE-14", "title": "Procurement irregularities", "informant_name": "Confidential Informant",
                    "content": [{"class": "public.summary", "text": "Procurement summary remains readable"},
                                {"class": "finance.amount", "text": "AED 900,000"}]}
        released = self.pep.enforce(request, original)
        self.assertIsNone(released["informant_name"])
        self.assertEqual(released["content"][1]["text"], MASKED_TEXT)
        self.assertEqual(released["content"][0]["text"], "Procurement summary remains readable")
        self.assertEqual(original["content"][1]["text"], "AED 900,000")
        with self.assertRaises(AccessDeniedError):
            self.pep.enforce(evaluation("bob", "CASE-7"), original)

    def test_batch_searches_explain_and_sql_filter(self):
        bob = evaluation("bob", "CASE-14", network="trusted")
        batch = self.pep.evaluate_batch({**bob, "evaluations": [{}, {"resource": {"type": "case", "id": "CASE-7"}}, {}],
                                         "options": {"evaluations_semantic": "deny_on_first_deny"}})
        self.assertEqual([e["decision"] for e in batch["evaluations"]], [True, False])
        first = self.pep.search_resources({**bob, "resource": {"type": "case"}, "page": {"limit": 1}})
        self.assertEqual(len(first["results"]), 1)
        self.assertTrue(first["page"]["next_token"])
        following = self.pep.search_resources({**bob, "resource": {"type": "case"},
                                               "page": {"limit": 1, "token": first["page"]["next_token"]}})
        self.assertNotEqual(first["results"], following["results"])
        subjects = [s["id"] for s in self.pep.search_subjects({**bob, "subject": {"type": "user"}})["results"]]
        self.assertIn("bob", subjects)
        self.assertNotIn("frank", subjects)
        actions = [a["name"] for a in self.pep.search_actions(bob)["results"]]
        self.assertIn("read", actions)
        self.assertNotIn("delete", actions)
        explained = self.pep.explain(bob)
        self.assertTrue(explained["decision"])
        self.assertTrue(any(step.get("stage") == "need_to_know" for step in explained["trace"]))
        with self.assertRaises(PdpHttpError) as caught:
            self.pep.explain(evaluation("bob", "CASE-7"))
        self.assertEqual(caught.exception.status, 404)
        compiled = self.pep.filter({**bob, "resource": {"type": "case"}, "dialect": "postgres", "columns": {
            "resource.level": {"column": "level", "type": "number"},
            "resource.compartments": {"column": "compartments", "kind": "text[]"}, "resource.id": "id"}})
        self.assertIsInstance(compiled["sql"]["text"], str)
        self.assertTrue(compiled["sql"]["params"])
        self.assertIn("op", compiled["residual"])

    def test_open_and_close_session_share_a_mark_that_cannot_be_reset(self):
        first = self.pep.open_session({"type": "user", "id": "carol"})

        def point(resource, action, token):
            return {"subject": {"type": "user", "id": "carol"}, "action": {"name": action},
                    "resource": {"type": "case", "id": resource},
                    "context": {"network": "trusted", "sessionToken": token, **({} if action == "read" else {"sessionLevel": 1})}}

        self.assertTrue(self.pep.evaluate(point("CASE-14", "read", first["token"]))["decision"])
        second = self.pep.open_session({"type": "user", "id": "carol"})
        denied = self.pep.evaluate(point("CASE-11", "update", second["token"]))
        self.assertEqual((denied["decision"], denied["context"]["rules"]), (False, ["BLP.HIGH_WATER"]))
        self.assertEqual(self.pep.close_session(first["token"]), {"ok": True})
        with self.assertRaises(PdpHttpError) as caught:
            self.pep.evaluate(point("CASE-14", "read", first["token"]))
        self.assertEqual((caught.exception.status, caught.exception.code), (403, "invalid_session_token"))
        self.pep.close_session(second["token"])

    def test_single_use_decision_token_and_outcome_report(self):
        certified = self.pep.evaluate({"subject": {"type": "user", "id": "henry"}, "action": {"name": "approve"},
                                       "resource": {"type": "payment", "id": "PAY-3"},
                                       "context": {"network": "trusted", "makerId": "grace"}})
        self.assertTrue(certified["decision"])
        consume = {"token": certified["context"]["decision_token"], "action": "approve",
                   "resource": {"type": "payment", "id": "PAY-3"}, "resourceVersion": 4}
        reservation = self.pep.consume_token(consume)["reservation"]
        with self.assertRaises(PdpHttpError) as caught:
            self.pep.consume_token(consume)
        self.assertEqual((caught.exception.status, caught.exception.code), (409, "conflict"))
        done = {"ok": True, "reservation": reservation, "outcome": "completed"}
        self.assertEqual(self.pep.report_outcome({"reservation": reservation, "outcome": "completed"}), done)
        self.assertEqual(self.pep.report_outcome({"reservation": reservation, "outcome": "completed"}), done)
        with self.assertRaises(PdpHttpError) as caught:
            self.pep.report_outcome({"reservation": reservation, "outcome": "failed"})
        self.assertEqual(caught.exception.status, 409)

    def _admin(self, method, path, body, session=None):
        opener = build_opener()
        request = urllib.request.Request(f"{self.url}{path}", data=json.dumps(body).encode(), method=method,
                                         headers={"content-type": "application/json", **(session or {})})
        with opener.open(request, timeout=10) as response:
            return response.status, response.headers, json.loads(response.read())

    def test_type_bound_credential_registers_syncs_lists_and_retires_records(self):
        _, headers, signed_in = self._admin("POST", "/admin/v1/session", {"username": "lina", "password": self.lina_password})
        session = {"cookie": headers["set-cookie"].split(";")[0], "x-csrf-token": signed_in["csrfToken"]}
        status, _, issued = self._admin("POST", "/admin/v1/pep-credentials", {"name": "case-app", "resourceTypes": ["case", "folder"]}, session)
        self.assertEqual(status, 201)
        app = PepClient(self.url, issued["secret"])
        record = {"type": "case", "id": "CASE-100", "level": 1, "compartments": [], "integrity": "system",
                  "contentClasses": [], "owner": "carol", "parent": {"type": "folder", "id": "FOLDER-A"}}

        def bob_reads():
            return self.pep.evaluate(evaluation("bob", "CASE-100"))["decision"]

        self.assertFalse(bob_reads())
        self.assertEqual(app.register_resource(record)["items"], [{"type": "case", "id": "CASE-100", "status": "created", "version": 1}])
        self.assertTrue(bob_reads())
        raised = app.sync_resources({"resources": [{**record, "level": 2}, {**record, "id": "CASE-101"}]})
        self.assertEqual(raised["counts"], {"created": 1, "updated": 1, "unchanged": 0, "retired": 0, "proposed": 0})
        proposed = app.register_resource({**record, "level": 1})["items"][0]
        self.assertEqual(proposed["status"], "proposed")
        self.assertTrue(proposed["changeId"])
        listed = [r for r in app.list_resources({"type": "case", "limit": 1000})["resources"] if r["id"].startswith("CASE-10")]
        self.assertEqual(listed, [{"type": "case", "id": "CASE-100", "version": 2}, {"type": "case", "id": "CASE-101", "version": 1}])
        with self.assertRaises(PdpHttpError) as caught:
            self.pep.register_resource(record)
        self.assertEqual(caught.exception.status, 403, "the bootstrap credential writes no resources")
        self.assertEqual(app.retire_resource({"type": "case", "id": "CASE-100"})["counts"]["retired"], 1)
        self.assertFalse(bob_reads())

    def test_decision_assertions_verify_against_the_real_jwks(self):
        verifier = AssertionVerifier(f"{self.url}/.well-known/jwks.json", AUDIENCE, now=lambda: calendar.timegm(CLOCK))
        binding = {"audience": AUDIENCE, "method": "GET", "path": "/cases/CASE-14?view=full", "bodySha256": body_sha256(b"")}
        allowed = self.pep.evaluate_asserted({**evaluation("bob", "CASE-14", network="trusted"), "request": binding})
        self.assertTrue(allowed["decision"])
        token = allowed["assertion"]
        with self.assertRaises(GateAssertionError) as caught:
            verifier.verify("GET", "/cases/CASE-14", b"", token)
        self.assertEqual(caught.exception.code, "assertion_mismatch")
        claims = verifier.verify("GET", "/cases/CASE-14?view=full", b"", token)
        self.assertEqual((claims["sub"], claims["act"], claims["res"]),
                         ({"type": "user", "id": "bob"}, "read", {"type": "case", "id": "CASE-14"}))
        self.assertTrue(claims["pv"].startswith("pv."))
        with self.assertRaises(GateAssertionError) as caught:
            verifier.verify("GET", "/cases/CASE-14?view=full", b"", token)
        self.assertEqual(caught.exception.code, "assertion_replayed")
        denied = self.pep.evaluate_asserted({**evaluation("bob", "CASE-7"), "request": binding})
        self.assertNotIn("assertion", denied)
        body = b'{"q":"all"}'
        post = {"audience": AUDIENCE, "method": "POST", "path": "/cases", "bodySha256": body_sha256(body)}
        listed = self.pep.assert_list({"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"},
                                       "resource": {"type": "case"}, "request": post})
        self.assertTrue(listed["decision"])
        self.assertEqual(verifier.verify("POST", "/cases", body, listed["assertion"])["res"], {"type": "case"})
        with self.assertRaises(GateAssertionError) as caught:
            AssertionVerifier(f"{self.url}/.well-known/jwks.json", AUDIENCE).verify("POST", "/cases", body, listed["assertion"])
        self.assertEqual(caught.exception.code, "assertion_expired", "the fixed demo clock is in the past for a real clock")


if __name__ == "__main__":
    unittest.main()
