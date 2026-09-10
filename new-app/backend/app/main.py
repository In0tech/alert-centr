from datetime import UTC, datetime, timedelta
from typing import Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.adapters.alerts import AlertsRepository
from app.adapters.metrics import MetricsRepository
from app.adapters.mitigations import MitigationsRepository
from app.core.config import get_settings


class Alert(BaseModel):
    alert_uid: str
    target_cidr: str
    level: int | None = None
    status: Literal["active", "closed"]
    start_time: datetime
    end_time: datetime | None = None
    max_bps: float = Field(default=0, ge=0)
    current_max_bps: float = Field(default=0, ge=0)
    traffic_gbps: float = Field(default=0, ge=0)
    dp_blocks: int = Field(default=0, ge=0)
    waf_blocks: int = Field(default=0, ge=0)


class Mitigation(BaseModel):
    cidr: str
    target_network_int: int
    target_broadcast_int: int
    mitigation: str | None = None
    update_time_unix: int | None = None
    update_time: datetime | None = None


settings = get_settings()
app = FastAPI(
    title="Alert Centre API",
    version="0.2.0",
    description="REST API extracted from the legacy Flask/Dash Alert Centre.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

alerts_repository = AlertsRepository()
mitigations_repository = MitigationsRepository()
metrics_repository = MetricsRepository()


def _to_alert(item: dict) -> Alert:
    end_time = item.get("end_time")
    current_bps = float(item.get("current_max_bps") or item.get("max_bps") or 0)
    return Alert(
        alert_uid=str(item["alert_uid"]),
        target_cidr=str(item["target_cidr"]),
        level=int(item["level"]) if item.get("level") is not None else None,
        status="closed" if end_time else "active",
        start_time=item["start_time"],
        end_time=end_time,
        max_bps=float(item.get("max_bps") or 0),
        current_max_bps=current_bps,
        traffic_gbps=current_bps / 1_000_000_000,
        dp_blocks=int(item.get("dp_blocks") or 0),
        waf_blocks=int(item.get("waf_blocks") or 0),
    )


@app.get("/health", tags=["system"])
def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.app_env}


@app.get("/api/v1/alerts", response_model=list[Alert], tags=["alerts"])
def list_alerts(
    status: Literal["active", "closed"] | None = Query(default=None),
    level: int | None = Query(default=None, ge=1, le=3),
) -> list[Alert]:
    alerts = [_to_alert(item) for item in alerts_repository.get_all()]
    if status is not None:
        alerts = [alert for alert in alerts if alert.status == status]
    if level is not None:
        alerts = [alert for alert in alerts if alert.level == level]
    return alerts


@app.get("/api/v1/alerts/{alert_uid}", response_model=Alert, tags=["alerts"])
def get_alert(alert_uid: str) -> Alert:
    item = alerts_repository.get_by_id(alert_uid)
    if not item:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _to_alert(item)


@app.get("/api/v1/mitigations", response_model=list[Mitigation], tags=["mitigations"])
def list_mitigations() -> list[Mitigation]:
    return [Mitigation(**item) for item in mitigations_repository.get_current()]


@app.get("/api/v1/mitigations/history", tags=["mitigations"])
def mitigation_history(days: int = Query(default=7, ge=1, le=365)) -> list[dict]:
    return mitigations_repository.get_history(days)


@app.get("/api/v1/metrics/summary", tags=["metrics"])
def metrics_summary(
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict:
    effective_end = end or datetime.now(UTC)
    effective_start = start or (effective_end - timedelta(hours=24))
    return metrics_repository.get_summary(effective_start, effective_end)
