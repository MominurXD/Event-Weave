# EventWeave

**Digital Forensics & Incident Reconstruction Platform**

Personal project by **Mohammed Mominur Rahman Miah**.

EventWeave is a full-stack forensic investigation platform that ingests security evidence, preserves file integrity with SHA-256 hashing, reconstructs a chronological incident timeline, correlates entities across multiple data sources, applies explainable detection rules, and records investigation actions in a SQLite chain-of-custody log.

The project is designed to demonstrate practical Computer Science fundamentals across **digital forensics, algorithms, databases, security engineering and backend development**.

## Core capabilities

- Import JSON evidence bundles.
- Compute SHA-256 evidence hashes before analysis.
- Normalise and sort events into a UTC timeline.
- Correlate users, IPs, hosts, processes and files.
- Detect:
  - authentication bursts;
  - rapid IP changes after failed authentication;
  - suspicious command execution;
  - sensitive file access;
  - privilege changes.
- Maintain a SQLite case store and chain-of-custody audit trail.
- Visualise evidence in an interactive responsive dashboard.
- Export-ready case structure with transparent rule IDs and provenance.
- Built-in synthetic incident dataset for reproducible demonstrations.
- Automated tests, Docker and GitHub Actions CI.

## Why it is useful academically

EventWeave maps directly onto core Computer Science topics:

- **Computer Forensics:** evidence integrity, provenance, chain of custody and timeline reconstruction.
- **Algorithms & Data Structures:** sorting event streams, entity correlation and time-window detection logic.
- **Databases:** SQLite persistence for cases and audit records.
- **Cyber Security:** authentication anomalies, privilege changes, process/file/network indicators.
- **Software Engineering:** FastAPI REST endpoints, Pydantic validation, testing, CI and Docker.

## Example forensic workflow

1. Import an evidence bundle.
2. Hash the original artefact with SHA-256.
3. Parse and normalise events.
4. Reconstruct the timeline.
5. Correlate actors, IPs, hosts, processes and files.
6. Apply transparent forensic detection rules.
7. Review the findings and linked entities.
8. Preserve the case snapshot and investigation action in the audit trail.

## Sample incident

The included `sample/incident.json` reconstructs a synthetic account-compromise sequence involving:

- repeated failed VPN logins;
- successful authentication from a different IP;
- suspicious PowerShell execution;
- SSH private-key access;
- privilege escalation;
- external network activity;
- sensitive finance-file access.

All sample data is fictional.

## Stack

- Python 3.12
- FastAPI
- Pydantic
- SQLite
- HTML / CSS / JavaScript
- Pytest
- Docker
- GitHub Actions

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
PYTHONPATH=. uvicorn app.main:app --reload
```

Open `http://localhost:8000`.

## Tests

```bash
PYTHONPATH=. pytest -q
node --check web/app.js
```

Production Docker build:

```bash
docker build -t eventweave .
```

## API

- `GET /api/health`
- `POST /api/demo`
- `POST /api/cases/import`
- `GET /api/cases/{case_id}`
- `GET /api/audit`

Interactive FastAPI docs are available at `/docs` while the app is running.

## Evidence format

```json
[
  {
    "timestamp": "2026-09-14T08:17:05Z",
    "source": "edr",
    "event_type": "process",
    "actor": "analyst.user",
    "host": "WS-22",
    "ip": "10.10.4.22",
    "process": "powershell.exe",
    "action": "download remote payload",
    "outcome": "success",
    "details": "Encoded command observed"
  }
]
```

## Integrity boundary

EventWeave is an investigation aid, not a replacement for professional forensic procedure. Its built-in detections are transparent rules intended for portfolio demonstration and reproducible analysis. Evidence should be handled according to the relevant organisational/legal process in real investigations.

## Licence

MIT.
