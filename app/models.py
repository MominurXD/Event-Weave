from __future__ import annotations

from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field

Severity = Literal['info','low','medium','high','critical']

class EvidenceEvent(BaseModel):
    timestamp: datetime
    source: str
    event_type: str
    actor: str | None = None
    host: str | None = None
    ip: str | None = None
    process: str | None = None
    file_path: str | None = None
    file_hash: str | None = None
    action: str | None = None
    outcome: str | None = None
    details: str | None = None

class EvidenceItem(BaseModel):
    id: str
    name: str
    sha256: str
    size_bytes: int
    imported_at: datetime
    source_type: str
    event_count: int

class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    severity: Severity
    summary: str
    event_ids: list[int] = []
    entities: list[str] = []

class CaseSummary(BaseModel):
    event_count: int
    finding_count: int
    high_risk_count: int
    evidence_count: int
    first_event: datetime | None = None
    last_event: datetime | None = None
    integrity_ok: bool = True

class CaseResponse(BaseModel):
    case_id: str
    name: str
    summary: CaseSummary
    evidence: list[EvidenceItem]
    events: list[EvidenceEvent]
    findings: list[Finding]
    entity_links: list[dict]

class AuditEntry(BaseModel):
    id: int
    created_at: datetime
    action: str
    subject: str
    detail: str
