# ThreatForge

ThreatForge is a multi-agent cybersecurity incident investigation platform.

## Prerequisites

- Node.js 18+
- Python 3.10+

## Frontend

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:3000.

## Backend

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

API documentation is available at http://localhost:8000/docs.

Copy `.env.example` to `.env` and add provider credentials only when available. Future investigation results should be clearly labeled when synthetic data is used.

## Investigation graph

ThreatForge uses exactly five specialized LangGraph agents:

1. Triage Agent
2. Threat Intelligence Agent
3. Log Analysis Agent
4. Threat Detection & Correlation Agent
5. Risk Assessment & Reporting Agent

Flow:
`Investigation Input -> Triage -> (Threat Intelligence + Log Analysis) -> Threat Detection & Correlation -> Risk Assessment & Reporting -> Final Report`

Input and Final Report are workflow stages, not agents. The API exposes `POST /investigations`, `GET /investigations`, and `GET /investigations/{id}`. Results include real extracted evidence, agent execution records, provider availability, missing information, and uncertainty-aware report fields.
