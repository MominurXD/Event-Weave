import os
from pathlib import Path
os.environ['EVENTWEAVE_DB']='/tmp/eventweave-test.sqlite3'
Path(os.environ['EVENTWEAVE_DB']).unlink(missing_ok=True)
from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def test_health():
    assert client.get('/api/health').json()['status']=='ok'

def test_demo_case():
    r=client.post('/api/demo')
    assert r.status_code==200
    body=r.json()
    assert body['summary']['event_count']>=10
    assert body['summary']['high_risk_count']>=2
    assert len(body['evidence'][0]['sha256'])==64

def test_audit_records_action():
    client.post('/api/demo')
    r=client.get('/api/audit')
    assert r.status_code==200
    assert r.json()

def test_bad_upload_rejected():
    r=client.post('/api/cases/import',files={'evidence':('bad.json',b'nope','application/json')},data={'case_name':'Bad'})
    assert r.status_code==422
