"""Response validation, mirroring packages/sdk/src/validation.ts: every PDP answer is checked against its exact shape
and anything unexpected fails closed with PdpResponseError. Validators return fresh copies."""
from __future__ import annotations

import json as _json
import math
from typing import Any, Dict, List, NoReturn

from .errors import PdpResponseError

MAX_SAFE_INTEGER = 2**53 - 1
EVALUATION_KEYS = {"decision", "context"}
CONTEXT_KEYS = {"rules", "reasons", "obligations", "policy_version", "would_deny", "decision_token"}
OBLIGATION_KEYS = {"fieldAllowlist", "redact", "maskClasses", "notify", "decisionToken"}
EXPLAIN_KEYS = {"decision", "rules", "reasons", "obligations", "trace", "wouldDeny", "policyVersion"}


def _malformed() -> NoReturn:
    raise PdpResponseError()


def _reject_constant(_: str) -> NoReturn:
    raise ValueError("NaN and Infinity are not JSON")


def loads(text: str) -> Any:
    """json.loads without NaN/Infinity, which JSON.parse refuses too."""
    return _json.loads(text, parse_constant=_reject_constant)


def is_number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def is_safe_integer(value: Any) -> bool:
    return type(value) is int and -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER


def obj(value: Any) -> Dict[str, Any]:
    if type(value) is not dict:
        _malformed()
    return value


def _only_keys(value: Dict[str, Any], allowed: set) -> None:
    if any(key not in allowed for key in value):
        _malformed()


def _string(value: Any) -> str:
    if type(value) is not str or len(value) == 0:
        _malformed()
    return value


def _strings(value: Any) -> List[str]:
    if type(value) is not list or any(type(item) is not str for item in value):
        _malformed()
    return list(value)


def json_value(value: Any, depth: int = 0) -> Any:
    if depth > 100:
        _malformed()
    if value is None or type(value) in (str, bool):
        return value
    if type(value) in (int, float):
        if not math.isfinite(value):
            _malformed()
        return value
    if type(value) is list:
        return [json_value(item, depth + 1) for item in value]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            _malformed()
        return {key: json_value(item, depth + 1) for key, item in value.items()}
    _malformed()


def obligations(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, OBLIGATION_KEYS)
    result: Dict[str, Any] = {
        "redact": _strings(source.get("redact")),
        "maskClasses": _strings(source.get("maskClasses")),
        "notify": _strings(source.get("notify")),
    }
    if "fieldAllowlist" in source:
        result["fieldAllowlist"] = _strings(source["fieldAllowlist"])
    if "decisionToken" in source:
        token = obj(source["decisionToken"])
        _only_keys(token, {"ttlSeconds", "resourceVersion", "postState"})
        if "postState" in token and token["postState"] is not True:
            _malformed()
        ttl = token.get("ttlSeconds")
        if not is_number(ttl) or ttl <= 0:
            _malformed()
        if "resourceVersion" not in token:
            _malformed()
        version = token["resourceVersion"]
        if version is not None and not is_safe_integer(version):
            _malformed()
        result["decisionToken"] = {"ttlSeconds": ttl, "resourceVersion": version}
        if token.get("postState") is True:
            result["decisionToken"]["postState"] = True
    return result


def _context(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, CONTEXT_KEYS)
    result: Dict[str, Any] = {
        "rules": _strings(source.get("rules")),
        "reasons": _strings(source.get("reasons")),
        "obligations": obligations(source.get("obligations")),
        "policy_version": _string(source.get("policy_version")),
        "would_deny": _strings(source.get("would_deny")),
    }
    if "decision_token" in source:
        result["decision_token"] = _string(source["decision_token"])
    return result


def evaluation(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, EVALUATION_KEYS)
    if type(source.get("decision")) is not bool:
        _malformed()
    return {"decision": source["decision"], "context": _context(source.get("context"))}


def batch(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, {"evaluations"})
    if type(source.get("evaluations")) is not list:
        _malformed()
    return {"evaluations": [evaluation(item) for item in source["evaluations"]]}


def opened_session(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, {"token", "sessionId", "issuedAt", "expiresAt", "idleSeconds"})
    idle = source.get("idleSeconds")
    if not is_safe_integer(idle) or idle <= 0:
        _malformed()
    return {"token": _string(source.get("token")), "sessionId": _string(source.get("sessionId")),
            "issuedAt": _string(source.get("issuedAt")), "expiresAt": _string(source.get("expiresAt")), "idleSeconds": idle}


def closed_session(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, {"ok"})
    if source.get("ok") is not True:
        _malformed()
    return {"ok": True}


def _ref(value: Any) -> Dict[str, str]:
    source = obj(value)
    _only_keys(source, {"type", "id"})
    return {"type": _string(source.get("type")), "id": _string(source.get("id"))}


def references(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, {"results", "page"})
    if type(source.get("results")) is not list:
        _malformed()
    page = obj(source.get("page"))
    _only_keys(page, {"next_token"})
    if type(page.get("next_token")) is not str:
        _malformed()
    return {"results": [_ref(item) for item in source["results"]], "page": {"next_token": page["next_token"]}}


def actions(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, {"results"})
    if type(source.get("results")) is not list:
        _malformed()
    results = []
    for item in source["results"]:
        action = obj(item)
        _only_keys(action, {"name"})
        results.append({"name": _string(action.get("name"))})
    return {"results": results}


def explained(value: Any) -> Dict[str, Any]:
    """The engine Decision of /x/v1/explain (not in the TypeScript client): exact keys, trace entries as JSON objects."""
    source = obj(value)
    if set(source) != EXPLAIN_KEYS or type(source["decision"]) is not bool or type(source["trace"]) is not list:
        _malformed()
    return {
        "decision": source["decision"], "rules": _strings(source["rules"]), "reasons": _strings(source["reasons"]),
        "obligations": obligations(source["obligations"]),
        "trace": [obj(json_value(step)) for step in source["trace"]],
        "wouldDeny": _strings(source["wouldDeny"]), "policyVersion": _string(source["policyVersion"]),
    }


def filtered(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, {"residual", "sql"})
    residual = json_value(source.get("residual"))
    if type(residual) is not dict:
        _malformed()
    sql = obj(source.get("sql"))
    _only_keys(sql, {"text", "params"})
    if type(sql.get("text")) is not str or type(sql.get("params")) is not list:
        _malformed()
    return {"residual": residual, "sql": {"text": sql["text"], "params": [json_value(item) for item in sql["params"]]}}


def consumed(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, {"ok", "reservation"})
    if source.get("ok") is not True:
        _malformed()
    return {"ok": True} if "reservation" not in source else {"ok": True, "reservation": _string(source["reservation"])}


def reported(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, {"ok", "reservation", "outcome"})
    if source.get("ok") is not True or source.get("outcome") not in ("completed", "failed"):
        _malformed()
    return {"ok": True, "reservation": _string(source.get("reservation")), "outcome": source["outcome"]}


def asserted(value: Any) -> Dict[str, Any]:
    """An allow without an assertion is malformed: the gateway would have nothing to prove the decision with."""
    rest = dict(obj(value))
    has_assertion = "assertion" in rest
    assertion = rest.pop("assertion", None)
    result = evaluation(rest)
    if result["decision"] != has_assertion:
        _malformed()
    if has_assertion:
        result["assertion"] = _string(assertion)
    return result


def list_asserted(value: Any) -> Dict[str, Any]:
    source = obj(value)
    _only_keys(source, {"decision", "policy_version", "assertion"})
    if type(source.get("decision")) is not bool or source["decision"] != ("assertion" in source):
        _malformed()
    result = {"decision": source["decision"], "policy_version": _string(source.get("policy_version"))}
    if "assertion" in source:
        result["assertion"] = _string(source["assertion"])
    return result
