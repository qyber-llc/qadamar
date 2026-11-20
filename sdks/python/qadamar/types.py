"""Shapes of the requests and answers (docs/API.md), as in packages/sdk/src/types.ts. Every value is a plain dict or
list as json produces it; these TypedDicts only describe them for type checkers."""
from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional, TypedDict


class Ref(TypedDict):
    type: str
    id: str


class Action(TypedDict):
    name: str


class _DevicePostureRequired(TypedDict):
    managed: bool
    compliant: bool


class DevicePosture(_DevicePostureRequired, total=False):
    id: str


ContextSignal = Literal["network", "ip", "country", "device", "authTime", "mfaTime", "authMethods", "riskScore", "sessionLevel"]


class EvaluationContext(TypedDict, total=False):
    network: Literal["trusted", "untrusted"]
    networkSensorId: str
    attestations: Dict[ContextSignal, str]
    ip: str
    country: str
    device: DevicePosture
    authTime: str
    mfaTime: str
    authMethods: List[str]
    riskScore: int
    sessionLevel: int
    sessionToken: str
    sessionId: str
    sessionExpired: bool
    makerId: str
    priorActions: List[str]
    attrs: Dict[str, Any]
    input: Dict[str, Any]


class _EvaluationRequired(TypedDict):
    subject: Ref
    action: Action
    resource: Ref


class EvaluationRequest(_EvaluationRequired, total=False):
    context: EvaluationContext  # sessionToken (PDP-issued) or legacy sessionId


class DecisionToken(TypedDict, total=False):
    ttlSeconds: float
    resourceVersion: Optional[int]
    postState: Literal[True]


class _ObligationsRequired(TypedDict):
    redact: List[str]
    maskClasses: List[str]
    notify: List[str]


class Obligations(_ObligationsRequired, total=False):
    fieldAllowlist: List[str]
    decisionToken: DecisionToken


class _DecisionContextRequired(TypedDict):
    rules: List[str]
    reasons: List[str]
    obligations: Obligations
    policy_version: str
    would_deny: List[str]


class DecisionContext(_DecisionContextRequired, total=False):
    decision_token: str


class Evaluation(TypedDict):
    decision: bool
    context: DecisionContext


class RequestBinding(TypedDict):
    audience: str
    method: str
    path: str
    bodySha256: str


class _ResourceRecordRequired(TypedDict):
    type: str
    id: str
    level: int
    compartments: List[str]
    integrity: Literal["derived", "extracted", "system", "verified"]
    contentClasses: List[str]


class ResourceRecord(_ResourceRecordRequired, total=False):
    owner: str
    parent: Ref
    version: int
    attrs: Dict[str, Any]


class AssertionClaims(TypedDict):
    sub: Ref
    act: str
    res: Dict[str, str]  # {type, id?}: no id for a list request
    did: str
    pv: str
    aud: str
    htm: str
    htp: str
    bsh: str
    iat: int
    exp: int
    nonce: str
