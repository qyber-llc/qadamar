"""PDP client for PEPs and backends, mirroring packages/sdk/src/client.ts. Standard library only (urllib)."""
from __future__ import annotations

import http.client
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Mapping, Optional, TypeVar
from urllib.parse import urlsplit

from . import validation as v
from .enforce import enforce as _enforce
from .errors import PdpHttpError, PdpNetworkError, PdpResponseError, PepError
from .resources import check_list, check_record, check_ref, check_sync, listed, registration

T = TypeVar("T")
_ERROR_CODE = re.compile(r"^[a-z0-9_.-]{1,64}$")
_CHUNK = 65536


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # a redirect would resend the bearer key elsewhere (urllib keeps Authorization): a 3xx is an HTTP error instead
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def build_opener(ca_file: Optional[str] = None) -> urllib.request.OpenerDirector:
    """TLS verified with the system trust store (or `ca_file`), no redirects, no proxy from the environment."""
    context = ssl.create_default_context(cafile=ca_file)
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _NoRedirect(), urllib.request.HTTPSHandler(context=context))


def read_bounded(response: Any, deadline: float, limit: Optional[int] = None) -> bytes:
    # shortcut: the deadline is checked between reads, each read bounded by the socket timeout; a total timer would need a thread
    chunks = []
    size = 0
    while True:
        if time.monotonic() > deadline:
            raise socket.timeout("deadline")
        chunk = response.read(_CHUNK)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if limit is not None and size > limit:
            raise ValueError("response too large")
        chunks.append(chunk)


def _timed_out(error: BaseException) -> bool:
    reason = getattr(error, "reason", None)
    return isinstance(error, socket.timeout) or isinstance(reason, socket.timeout)


class PepClient:
    """`base_url` the PDP origin (and base path); `api_key` a PEP credential; `timeout` seconds for the whole request."""

    def __init__(self, base_url: str, api_key: str, timeout: float = 10.0, ca_file: Optional[str] = None,
                 opener: Optional[urllib.request.OpenerDirector] = None) -> None:
        try:
            url = urlsplit(base_url)
            url.port  # noqa: B018 - raises ValueError on a bad port
        except (TypeError, ValueError, AttributeError):
            raise TypeError("baseUrl must be an HTTP(S) URL without credentials, query, or fragment") from None
        if (url.scheme not in ("http", "https") or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment or "?" in base_url or "#" in base_url):
            raise TypeError("baseUrl must be an HTTP(S) URL without credentials, query, or fragment")
        if type(api_key) is not str or not api_key or "\r" in api_key or "\n" in api_key:
            raise TypeError("apiKey must be a non-empty header-safe string")
        if not v.is_number(timeout) or timeout <= 0:
            raise TypeError("timeout must be positive and finite")
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = float(timeout)
        self._opener = opener or build_opener(ca_file)

    def __repr__(self) -> str:  # never shows the key
        return f"PepClient({self._base_url!r})"

    def open_session(self, subject: Mapping[str, Any]) -> Dict[str, Any]:
        return self._post("/x/v1/sessions", {"subject": subject}, v.opened_session)

    def close_session(self, token: str) -> Dict[str, Any]:
        return self._post("/x/v1/sessions/close", {"token": token}, v.closed_session)

    def evaluate(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        return self._post("/access/v1/evaluation", request, v.evaluation)

    def evaluate_batch(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        return self._post("/access/v1/evaluations", request, v.batch)

    def search_resources(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        return self._post("/access/v1/search/resource", request, v.references)

    def search_subjects(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        return self._post("/access/v1/search/subject", request, v.references)

    def search_actions(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        return self._post("/access/v1/search/action", request, v.actions)

    def explain(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """The engine Decision with its trace; a record the subject may not read is 404, as a missing one."""
        return self._post("/x/v1/explain", request, v.explained)

    def filter(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        return self._post("/x/v1/filter", request, v.filtered)

    def consume_token(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        return self._post("/x/v1/tokens/consume", request, v.consumed)

    def report_outcome(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """After running a consumed certified command: what became of it. Once per reservation (the same report again
        is answered alike; another outcome is refused, 409). Unsure whether it ran: do not report; it stays reserved."""
        return self._post("/x/v1/tokens/outcome", request, v.reported)

    def evaluate_asserted(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """An evaluation plus, on allow, a decision assertion signed by the PDP for the backend (docs/API.md 2.0.2)."""
        return self._post("/x/v1/assertions/evaluation", request, v.asserted)

    def assert_list(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """A list request: an assertion when the subject may act on some item of the type; the PEP filters the items."""
        return self._post("/x/v1/assertions/list", request, v.list_asserted)

    def register_resource(self, resource: Mapping[str, Any]) -> Dict[str, Any]:
        """Registers or updates one record of a type this credential is bound to; a change that could widen access to
        a known record comes back `proposed` with the id of the change awaiting a second person (HTTP 202)."""
        check_record(resource, "resource")
        return self._post("/x/v1/resources", {"resource": resource}, registration)

    def retire_resource(self, resource: Mapping[str, Any]) -> Dict[str, Any]:
        """Retires a record: decisions on it fail closed (CORE.UNKNOWN_ID) from then on. Retiring it again is a no-op."""
        ref = check_ref(resource, "resource")
        return self._post("/x/v1/resources/retire", {"resource": ref}, registration)

    def sync_resources(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """Registers and retires up to 1000 records at once, all or nothing."""
        check_sync(request)
        return self._post("/x/v1/resources/sync", request, registration)

    def list_resources(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        """The registered ids and versions of one bound type, in id order; pass `next_cursor` back until it is empty."""
        check_list(request)
        return self._post("/x/v1/resources/list", request, listed)

    def enforce(self, request: Mapping[str, Any], record: Dict[str, Any]) -> Dict[str, Any]:
        # no token option: a certified command is consumed through consume_token and enforce(decision, ..., decision_token_consumed=True)
        return _enforce(self.evaluate(request), record)

    def _post(self, path: str, body: Any, validate: Callable[[Any], T]) -> T:
        try:
            serialized = json.dumps(body, allow_nan=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            raise PepError("invalid_request", "The request body must be JSON-serializable") from None
        request = urllib.request.Request(f"{self._base_url}{path}", data=serialized, method="POST", headers={
            "accept": "application/json", "content-type": "application/json", "authorization": f"Bearer {self._api_key}"})
        deadline = time.monotonic() + self._timeout
        status = 0
        retry: Optional[str] = None
        try:
            try:
                with self._opener.open(request, timeout=self._timeout) as response:
                    status = response.status
                    data = read_bounded(response, deadline)
            except urllib.error.HTTPError as error:
                status = error.code
                retry = error.headers.get("retry-after") if error.headers is not None else None
                data = read_bounded(error, deadline)
        except (OSError, http.client.HTTPException, ValueError) as error:
            if _timed_out(error):
                raise PdpNetworkError("request_timeout", "The PDP request timed out") from None
            raise PdpNetworkError("network_error", "The PDP could not be reached") from None

        if not 200 <= status < 300:
            code = "http_error"
            try:
                parsed = v.loads(data.decode("utf-8"))
                candidate = parsed.get("error") if type(parsed) is dict else None
                if type(candidate) is str and _ERROR_CODE.match(candidate):
                    code = candidate
            except (ValueError, RecursionError):
                pass  # a non-JSON error response still produces a sanitized HTTP error
            retry_after = retry if retry is not None and len(retry) <= 64 and not re.search(r"[\r\n\0]", retry) else None
            raise PdpHttpError(status, code, retry_after)
        try:
            value = v.loads(data.decode("utf-8"))
        except (ValueError, RecursionError):
            raise PdpResponseError("PDP returned invalid JSON") from None
        return validate(value)


PdpClient = PepClient


def create_pep_client(base_url: str, api_key: str, **options: Any) -> PepClient:
    return PepClient(base_url, api_key, **options)
