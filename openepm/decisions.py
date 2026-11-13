"""Typed client for current shared application-admin decisions."""
from __future__ import annotations

from typing import Any, Literal, Mapping

from .client import Transport
from .model import Application


class ApplicationDecisions:
    """Operate on one current decision per stable identifier."""

    def __init__(self, transport: Transport, application: Application):
        self.transport, self.application = transport, application

    def _read(self, action: str, arguments: dict) -> Mapping[str, Any]:
        return self.transport.call("read_v2_program", {**self.application.to_wire(),
            "program": {"languageVersion": 2, "function": "application.decision." + action,
                        "arguments": arguments}})

    def _write(self, action: str, arguments: dict, request_key: str) -> Mapping[str, Any]:
        return self.transport.call("execute_v2_application_decision", {
            **self.application.to_wire(), "idempotency_key": request_key,
            "program": {"languageVersion": 2, "function": "application.decision." + action,
                        "arguments": arguments}})

    def create(self, decision_id: str, *, title: str, text: str,
               provenance: Literal["UserDecision", "AgentInterpretation"], request_key: str,
               rationale: str = "", source_reference: str = "") -> Mapping[str, Any]:
        return self._write("create", {"decisionId": decision_id, "title": title, "text": text,
            "provenance": provenance, "rationale": rationale, "sourceReference": source_reference}, request_key)

    def replace(self, decision_id: str, *, expected_state_token: str, title: str, text: str,
                provenance: Literal["UserDecision", "AgentInterpretation"], request_key: str,
                rationale: str = "", source_reference: str = "") -> Mapping[str, Any]:
        return self._write("replace", {"decisionId": decision_id,
            "expectedStateToken": expected_state_token, "title": title, "text": text,
            "provenance": provenance, "rationale": rationale,
            "sourceReference": source_reference}, request_key)

    def withdraw(self, decision_id: str, *, expected_state_token: str,
                 request_key: str) -> Mapping[str, Any]:
        return self._write("withdraw", {"decisionId": decision_id,
            "expectedStateToken": expected_state_token}, request_key)

    def read(self, decision_id: str) -> Mapping[str, Any]:
        return self._read("read", {"decisionId": decision_id})

    def list(self, *, limit: int = 25, after_decision_id: str | None = None,
             expected_collection_token: str | None = None) -> Mapping[str, Any]:
        return self._read("list", {"limit": limit,
            **({"afterDecisionId": after_decision_id} if after_decision_id is not None else {}),
            **({"expectedCollectionToken": expected_collection_token}
               if expected_collection_token is not None else {})})
