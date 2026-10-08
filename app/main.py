from __future__ import annotations

import json
from pathlib import Path
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from .service import build_case
from .store import audit, list_audit, save_case, load_case

app = FastAPI(title='EventWeave', version='1.0.0', description='Digital forensics incident reconstruction platform.')

@app.get('/api/health')
def health():
    return {'status':'ok','service':'EventWeave','version':'1.0.0'}

@app.post('/api/cases/import')
async def import_case(case_name: str = Form('Imported investigation'), evidence: UploadFile = File(...)):
    raw = await evidence.read()
    try:
        payload = json.loads(raw.decode('utf-8-sig'))
    except Exception as exc:
        raise HTTPException(status_code=422, detail='Evidence file must be valid UTF-8 JSON.') from exc
    if not isinstance(payload, list):
        raise HTTPException(status_code=422, detail='Evidence JSON must be an array of event objects.')
    case = build_case(case_name, evidence.filename or 'evidence.json', raw, payload)
    save_case(case.case_id, case.name, case.model_dump(mode='json'))
    audit('evidence_imported', case.case_id, f'{evidence.filename}: {len(payload)} events; SHA-256 {case.evidence[0].sha256}')
    return case

@app.get('/api/cases/{case_id}')
def get_case(case_id: str):
    payload = load_case(case_id)
    if not payload: raise HTTPException(status_code=404, detail='Case not found')
    return payload

@app.get('/api/audit')
def get_audit():
    return list_audit(50)

SAMPLE = Path(__file__).resolve().parent.parent / 'sample' / 'incident.json'
@app.post('/api/demo')
def demo():
    raw = SAMPLE.read_bytes()
    payload = json.loads(raw)
    case = build_case('Operation Lantern', SAMPLE.name, raw, payload)
    save_case(case.case_id, case.name, case.model_dump(mode='json'))
    audit('demo_case_created', case.case_id, f'{len(payload)} events loaded from built-in demo dataset.')
    return case

WEB = Path(__file__).resolve().parent.parent / 'web'
app.mount('/', StaticFiles(directory=WEB, html=True), name='web')
