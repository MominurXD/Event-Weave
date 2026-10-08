from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from uuid import uuid4
from .detectors import detect
from .models import EvidenceEvent, EvidenceItem, CaseSummary, CaseResponse


def _links(events: list[EvidenceEvent]):
    links=[]; seen=set()
    def add(a,b,kind):
        if not a or not b or a==b: return
        key=(a,b,kind)
        if key in seen: return
        seen.add(key); links.append({'source':a,'target':b,'kind':kind})
    for e in events:
        add(e.actor,e.ip,'used_ip')
        add(e.actor,e.host,'accessed_host')
        add(e.host,e.process,'ran_process')
        add(e.process,e.file_path,'touched_file')
        add(e.ip,e.host,'connected_to')
    return links[:120]


def build_case(name: str, raw_name: str, raw_bytes: bytes, events_payload: list[dict]):
    sha = hashlib.sha256(raw_bytes).hexdigest()
    events = sorted([EvidenceEvent(**e) for e in events_payload], key=lambda e:e.timestamp)
    evidence = EvidenceItem(
        id=str(uuid4()), name=raw_name, sha256=sha, size_bytes=len(raw_bytes),
        imported_at=datetime.now(timezone.utc), source_type='json', event_count=len(events)
    )
    findings = detect(events)
    summary = CaseSummary(
        event_count=len(events), finding_count=len(findings),
        high_risk_count=sum(1 for f in findings if f.severity in {'high','critical'}),
        evidence_count=1, first_event=events[0].timestamp if events else None,
        last_event=events[-1].timestamp if events else None, integrity_ok=True
    )
    return CaseResponse(
        case_id=str(uuid4()), name=name, summary=summary, evidence=[evidence],
        events=events, findings=findings, entity_links=_links(events)
    )


def verify_hash(raw_bytes: bytes, expected: str):
    return hashlib.sha256(raw_bytes).hexdigest() == expected.lower()
