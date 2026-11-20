"""Obligation enforcement, mirroring packages/sdk/src/enforce.ts: a deep copy of a JSON record is released only on a
valid allow; redaction and allowlisting take dotted object paths; masking uses only explicit record["content"]
fragments; a deny, an unknown obligation key, notify, an unconsumed decisionToken, or a class that cannot be located is refused."""
from __future__ import annotations

import math
from typing import Any, Dict, List, Sequence, Set, Tuple

from .errors import AccessDeniedError, ObligationError
from .validation import evaluation as _validate_evaluation

MASKED_TEXT = "[MASKED]"
FORBIDDEN_SEGMENTS = {"__proto__", "prototype", "constructor"}


def _clone(value: Any, seen: Set[int], depth: int) -> Any:
    if depth > 100:
        raise ObligationError("The JSON record is too deeply nested")
    if value is None or isinstance(value, (str, bool)):
        return value
    if isinstance(value, (int, float)):
        if not math.isfinite(value):
            raise ObligationError("The record must contain only finite JSON numbers")
        return value
    if not isinstance(value, (dict, list, tuple)):
        raise ObligationError("The record must contain only JSON values")
    if id(value) in seen:
        raise ObligationError("The record must not contain cycles")
    seen.add(id(value))
    try:
        if isinstance(value, (list, tuple)):
            return [_clone(item, seen, depth + 1) for item in value]
        if any(not isinstance(key, str) for key in value):
            raise ObligationError("The record must contain only plain JSON objects")
        return {key: _clone(item, seen, depth + 1) for key, item in value.items()}
    finally:
        seen.discard(id(value))


def _path(value: str) -> List[str]:
    parts = value.split(".")
    if any(len(part) == 0 or part in FORBIDDEN_SEGMENTS for part in parts):
        raise ObligationError("An obligation contains an unsafe or empty field path")
    return parts


def _read(source: Dict[str, Any], parts: Sequence[str]) -> Tuple[bool, Any]:
    current: Any = source
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _write(target: Dict[str, Any], parts: Sequence[str], value: Any) -> None:
    current = target
    for part in parts[:-1]:
        existing = current.get(part)
        if not isinstance(existing, dict):
            existing = {}
            current[part] = existing
        current = existing
    current[parts[-1]] = value


def _allowlisted(source: Dict[str, Any], fields: Sequence[str]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for parts in sorted((_path(f) for f in fields), key=len):
        found, value = _read(source, parts)
        if found:
            _write(result, parts, value)
    return result


def _redact(record: Dict[str, Any], fields: Sequence[str]) -> None:
    for field in fields:
        parts = _path(field)
        current: Any = record
        for index, part in enumerate(parts):
            # an array on the path cannot be redacted by key: refuse rather than release it unredacted
            if isinstance(current, list):
                raise ObligationError("A redaction path crosses an array; no record was released")
            if not isinstance(current, dict) or part not in current:
                break
            if index == len(parts) - 1:
                current[part] = None
            else:
                current = current[part]


def _mask(record: Dict[str, Any], classes: Sequence[str]) -> None:
    if not classes:
        return
    fragments = record.get("content")
    if not isinstance(fragments, list):
        raise ObligationError("Masked content requires record.content to be an array of class/text fragments")
    for fragment in fragments:
        if not isinstance(fragment, dict) or type(fragment.get("class")) is not str or type(fragment.get("text")) is not str:
            raise ObligationError("Every record.content fragment must have string class and text fields")
    for required in classes:
        if not any(fragment["class"] == required for fragment in fragments):
            raise ObligationError("A required content class could not be located; no record was released")
    for fragment in fragments:
        if fragment["class"] in classes:
            fragment["text"] = MASKED_TEXT


def enforce(decision: Any, record: Dict[str, Any], *, decision_token_consumed: bool = False) -> Dict[str, Any]:
    """The record as it may be released under `decision` (an evaluation answer); the input is never modified."""
    valid = _validate_evaluation(decision)
    if not valid["decision"]:
        raise AccessDeniedError()
    obligations = valid["context"]["obligations"]
    if obligations["notify"]:
        raise ObligationError("Notification obligations require a notification-capable PEP")
    # single-use consumption is the PEP's job: refuse unless the caller says consume_token already succeeded
    if "decisionToken" in obligations and decision_token_consumed is not True:
        raise ObligationError("A decision token must be consumed (single-use) before release; pass the consumed acknowledgement once consumeToken succeeded")
    cloned = _clone(record, set(), 0)
    if not isinstance(cloned, dict):
        raise ObligationError("The record must be a JSON object")
    result = cloned if "fieldAllowlist" not in obligations else _allowlisted(cloned, obligations["fieldAllowlist"])
    _redact(result, obligations["redact"])
    _mask(result, obligations["maskClasses"])
    return result
