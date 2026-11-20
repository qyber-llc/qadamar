"""Resource registration (docs/API.md section 2.2), mirroring packages/sdk/src/resources.ts: requests are checked before
they leave (the PDP checks them again against its policy schema), answers are checked before they are returned."""
from __future__ import annotations

import re
from typing import Any, Dict, NoReturn

from .errors import PdpResponseError, PepError
from .validation import is_safe_integer, json_value, obj

MAX_SYNC = 1000
STATUSES = ("created", "updated", "unchanged", "retired", "proposed")
INTEGRITY = ("derived", "extracted", "system", "verified")
RECORD_KEYS = {"type", "id", "level", "compartments", "integrity", "contentClasses", "owner", "parent", "version", "attrs"}
_CONTROL = re.compile("[\u0000-\u001f\u007f]")


def _invalid(message: str) -> NoReturn:
    raise PepError("invalid_request", message)


def _text(value: Any) -> bool:
    return type(value) is str and 0 < len(value) <= 256 and not _CONTROL.search(value)


def _texts(value: Any) -> bool:
    return (type(value) in (list, tuple) and len(value) <= 64 and all(type(x) is str for x in value)
            and len(set(value)) == len(value))


def check_ref(value: Any, where: str = "resource") -> Dict[str, str]:
    if (not isinstance(value, dict) or any(k not in ("type", "id") for k in value)
            or not _text(value.get("type")) or not _text(value.get("id"))):
        _invalid(f"{where} must be {{ type, id }}")
    return {"type": value["type"], "id": value["id"]}


def check_record(record: Any, where: str = "resource") -> Dict[str, Any]:
    if not isinstance(record, dict):
        _invalid(f"{where} must be an object")
    if any(k not in RECORD_KEYS for k in record):
        _invalid(f"{where} has an unknown field")
    check_ref({"type": record.get("type"), "id": record.get("id")}, where)
    level = record.get("level")
    if type(level) is not int or not 0 <= level <= 3:
        _invalid(f"{where}.level must be an integer 0..3")
    if not _texts(record.get("compartments")):
        _invalid(f"{where}.compartments must be a list of distinct strings")
    if record.get("integrity") not in INTEGRITY:
        _invalid(f"{where}.integrity must be derived, extracted, system or verified")
    if not _texts(record.get("contentClasses")):
        _invalid(f"{where}.contentClasses must be a list of distinct strings (empty when scanned and clean)")
    if "owner" in record and not _text(record["owner"]):
        _invalid(f"{where}.owner must be a non-empty string")
    if "parent" in record:
        check_ref(record["parent"], f"{where}.parent")
    if "version" in record and (not is_safe_integer(record["version"]) or record["version"] < 0):
        _invalid(f"{where}.version must be a non-negative integer")
    if "attrs" in record and not isinstance(record["attrs"], dict):
        _invalid(f"{where}.attrs must be an object")
    return record


def check_sync(request: Any) -> Dict[str, Any]:
    if not isinstance(request, dict):
        _invalid("A sync request must be an object")
    resources = request.get("resources", [])
    retire = request.get("retire", [])
    if type(resources) not in (list, tuple) or type(retire) not in (list, tuple):
        _invalid("resources and retire must be lists")
    if not 1 <= len(resources) + len(retire) <= MAX_SYNC:
        _invalid(f"A sync names 1..{MAX_SYNC} resources")
    for i, record in enumerate(resources):
        check_record(record, f"resources[{i}]")
    for i, ref in enumerate(retire):
        check_ref(ref, f"retire[{i}]")
    return request


def check_list(request: Any) -> Dict[str, Any]:
    if not isinstance(request, dict) or not _text(request.get("type")):
        _invalid("type must be a non-empty string")
    if "limit" in request and (type(request["limit"]) is not int or not 1 <= request["limit"] <= MAX_SYNC):
        _invalid(f"limit must be an integer 1..{MAX_SYNC}")
    if "cursor" in request and type(request["cursor"]) is not str:
        _invalid("cursor must be a string")
    return request


def _malformed() -> NoReturn:
    raise PdpResponseError()


def _item(value: Any) -> Dict[str, Any]:
    v = obj(value)
    if not _text(v.get("type")) or not _text(v.get("id")) or v.get("status") not in STATUSES:
        _malformed()
    if "version" in v and not is_safe_integer(v["version"]):
        _malformed()
    change_id = v.get("changeId")
    if (v["status"] == "proposed") != (type(change_id) is str and len(change_id) > 0):
        _malformed()
    item: Dict[str, Any] = {"type": v["type"], "id": v["id"], "status": v["status"]}
    if "version" in v:
        item["version"] = v["version"]
    if "changeId" in v:
        item["changeId"] = change_id
    return item


def registration(value: Any) -> Dict[str, Any]:
    v = obj(value)
    if type(v.get("items")) is not list:
        _malformed()
    counts = obj(v.get("counts"))
    if not all(is_safe_integer(counts.get(s)) for s in STATUSES):
        _malformed()
    return {"items": [_item(x) for x in v["items"]], "counts": {s: counts[s] for s in STATUSES}}


def listed(value: Any) -> Dict[str, Any]:
    v = obj(value)
    if type(v.get("resources")) is not list or type(v.get("next_cursor")) is not str:
        _malformed()
    resources = []
    for x in v["resources"]:
        r = obj(json_value(x))
        if not _text(r.get("type")) or not _text(r.get("id")) or not is_safe_integer(r.get("version")):
            _malformed()
        resources.append({"type": r["type"], "id": r["id"], "version": r["version"]})
    return {"resources": resources, "next_cursor": v["next_cursor"]}
