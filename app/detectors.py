from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from uuid import uuid4
from .models import EvidenceEvent, Finding

SUSPICIOUS_PROCESSES = {'powershell.exe','pwsh.exe','cmd.exe','rundll32.exe','certutil.exe','mshta.exe'}
SENSITIVE_TERMS = ('credentials','password','secrets','id_rsa','.env','shadow','sam')


def detect(events: list[EvidenceEvent]) -> list[Finding]:
    findings: list[Finding] = []

    for idx, event in enumerate(events):
        proc = (event.process or '').lower()
        if proc in SUSPICIOUS_PROCESSES and any(x in (event.action or '').lower() + ' ' + (event.details or '').lower() for x in ['download','encoded','bypass','invoke','remote']):
            findings.append(Finding(
                id=str(uuid4()), rule_id='PROC-001', title='Suspicious command execution', severity='high',
                summary=f'{event.process} executed with suspicious remote/download behaviour.',
                event_ids=[idx], entities=[x for x in [event.actor,event.host,event.ip,event.process] if x]
            ))
        if event.file_path and any(term in event.file_path.lower() for term in SENSITIVE_TERMS):
            findings.append(Finding(
                id=str(uuid4()), rule_id='FILE-002', title='Sensitive file access', severity='medium',
                summary=f'Sensitive path accessed: {event.file_path}', event_ids=[idx],
                entities=[x for x in [event.actor,event.host,event.file_path] if x]
            ))
        if (event.action or '').lower() in {'add_admin','privilege_escalation','role_change'}:
            findings.append(Finding(
                id=str(uuid4()), rule_id='IAM-003', title='Privilege change', severity='high',
                summary=f'Privilege-related action recorded for {event.actor or "unknown actor"}.',
                event_ids=[idx], entities=[x for x in [event.actor,event.host,event.ip] if x]
            ))

    failed_by_actor: dict[str, list[tuple[int,EvidenceEvent]]] = defaultdict(list)
    success_by_actor: dict[str, list[tuple[int,EvidenceEvent]]] = defaultdict(list)
    for idx, e in enumerate(events):
        if e.actor and e.event_type.lower() in {'login','authentication'}:
            if (e.outcome or '').lower() in {'failed','failure','denied'}:
                failed_by_actor[e.actor].append((idx,e))
            if (e.outcome or '').lower() in {'success','successful','accepted'}:
                success_by_actor[e.actor].append((idx,e))

    for actor, failures in failed_by_actor.items():
        failures.sort(key=lambda x: x[1].timestamp)
        for start in range(len(failures)):
            window = [item for item in failures[start:] if item[1].timestamp - failures[start][1].timestamp <= timedelta(minutes=10)]
            if len(window) >= 5:
                ids = [i for i,_ in window[:8]]
                entities = {actor}
                entities.update(e.ip for _,e in window if e.ip)
                findings.append(Finding(
                    id=str(uuid4()), rule_id='AUTH-004', title='Authentication burst', severity='high',
                    summary=f'{len(window)} failed sign-ins for {actor} occurred within 10 minutes.',
                    event_ids=ids, entities=sorted(entities)
                ))
                break

        successes = success_by_actor.get(actor, [])
        for _, fail in failures:
            for idx, success in successes:
                if timedelta(0) <= success.timestamp - fail.timestamp <= timedelta(minutes=15) and fail.ip and success.ip and fail.ip != success.ip:
                    findings.append(Finding(
                        id=str(uuid4()), rule_id='AUTH-005', title='Rapid IP change after failed login', severity='critical',
                        summary=f'{actor} authenticated from {success.ip} shortly after failures from {fail.ip}.',
                        event_ids=[idx], entities=[actor, fail.ip, success.ip]
                    ))
                    break

    dedup = {}
    for finding in findings:
        key = (finding.rule_id, tuple(sorted(finding.entities)))
        dedup.setdefault(key, finding)
    return list(dedup.values())
