import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from fastapi import HTTPException
from uuid import uuid4

from graph import build_investigation_graph, utc_now
from csv_loader import load_network_flow_sample, parse_network_flow_csv_text


def load_environment() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        os.environ.setdefault(key, value)


load_environment()

app = FastAPI(
    title="ThreatForge API",
    description="Autonomous multi-agent cybersecurity incident investigation API",
    version="0.1.0",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]

allowed_origin_regex = os.getenv("CORS_ALLOWED_ORIGIN_REGEX", "").strip() or None

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=allowed_origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class HealthResponse(BaseModel):
    status: str
    service: str


class InvestigationRequest(BaseModel):
    prompt: str
    network_sample_size: int = 0


class InvestigationSummary(BaseModel):
    id: str
    prompt: str
    status: str
    report_status: str
    created_at: str


investigation_store: dict[str, dict] = {}
investigation_graph = build_investigation_graph()


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status="ok", service="threatforge-api")


@app.get("/network-sample")
def network_sample(row_count: int = 100) -> dict:
    try:
        result = load_network_flow_sample(row_count)
    except (ValueError, FileNotFoundError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return result


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "ThreatForge API", "docs": "/docs"}


@app.post("/investigations", response_model=InvestigationSummary, status_code=201)
def create_investigation(request: InvestigationRequest) -> InvestigationSummary:
    submitted_prompt = request.prompt
    prompt = request.prompt
    network_dataset: dict = {}
    network_records: list[dict] = []

    try:
        pasted_network_dataset = parse_network_flow_csv_text(request.prompt)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if pasted_network_dataset and request.network_sample_size:
        raise HTTPException(
            status_code=422,
            detail="Provide either pasted network-flow CSV or network_sample_size, not both",
        )

    if pasted_network_dataset:
        network_records = pasted_network_dataset["records"]
        network_dataset = {
            "row_count": pasted_network_dataset["row_count"],
            "feature_count": pasted_network_dataset["feature_count"],
            "feature_columns": pasted_network_dataset["feature_columns"],
            "missing_value_count": pasted_network_dataset["missing_value_count"],
        }
        prompt = f"Analyze {len(network_records)} bounded network-flow records"

    if request.network_sample_size:
        try:
            network_dataset = load_network_flow_sample(request.network_sample_size)
            network_records = network_dataset["records"]
            network_dataset = {
                "row_count": network_dataset["row_count"],
                "feature_count": network_dataset["feature_count"],
                "feature_columns": [
                    column
                    for column in network_dataset["feature_columns"]
                    if column not in {"Label", "ClassLabel"}
                ],
                "missing_value_count": network_dataset["missing_value_count"],
            }
        except (ValueError, FileNotFoundError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    if not request.prompt.strip() and not network_records:
        raise HTTPException(status_code=422, detail="Prompt is required")
    if not submitted_prompt.strip() and not prompt:
        prompt = f"Analyze {len(network_records)} bounded network-flow records"
    if not submitted_prompt.strip():
        submitted_prompt = prompt

    investigation_id = str(uuid4())
    initial_state = {
        "investigation_id": investigation_id,
        "prompt": prompt,
        "evidence": [],
        "agent_executions": [],
        "triage": {},
        "threat_intelligence": {},
        "log_analysis": {},
        "correlation": {},
        "risk_report": {},
        "report_status": "in_progress",
        "network_records": network_records,
        "network_dataset": network_dataset,
    }
    try:
        result = investigation_graph.invoke(initial_state)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Investigation processing failed: {exc}",
        ) from exc

    record = {
        "id": investigation_id,
        "prompt": submitted_prompt,
        "status": "completed" if result["report_status"] == "generated" else "error",
        "report_status": result["report_status"],
        "created_at": utc_now(),
        "result": result,
    }
    investigation_store[investigation_id] = record
    return InvestigationSummary(
        id=record["id"],
        prompt=record["prompt"],
        status=record["status"],
        report_status=record["report_status"],
        created_at=record["created_at"],
    )


@app.get("/investigations")
def list_investigations() -> list[dict]:
    return [
        {
            "id": record["id"],
            "prompt": record["prompt"],
            "status": record["status"],
            "report_status": record["report_status"],
            "created_at": record["created_at"],
        }
        for record in reversed(list(investigation_store.values()))
    ]


@app.get("/investigations/{investigation_id}")
def get_investigation(investigation_id: str) -> dict:
    record = investigation_store.get(investigation_id)
    if not record:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return record
