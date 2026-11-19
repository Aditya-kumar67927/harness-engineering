# Harness Engineering Safety API

FastAPI safety-classification service for the harness-engineering assignment.

## Run locally

```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

## Test

```powershell
python -m pytest -v
```

Endpoints:

- `GET /`
- `GET /health`
- `POST /classify`

The `/classify` endpoint expects profile `agent-harness-2026-09`, preserves `batchId`,
and returns one decision object for each case.
