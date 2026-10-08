import json
from pathlib import Path
from app.models import EvidenceEvent
from app.detectors import detect


def events():
    data=json.loads((Path(__file__).parent.parent/'sample'/'incident.json').read_text())
    return [EvidenceEvent(**e) for e in data]


def test_detects_authentication_burst():
    assert any(f.rule_id=='AUTH-004' for f in detect(events()))

def test_detects_rapid_ip_change():
    assert any(f.rule_id=='AUTH-005' for f in detect(events()))

def test_detects_suspicious_process():
    assert any(f.rule_id=='PROC-001' for f in detect(events()))

def test_detects_sensitive_file_access():
    assert any(f.rule_id=='FILE-002' for f in detect(events()))

def test_detects_privilege_change():
    assert any(f.rule_id=='IAM-003' for f in detect(events()))
