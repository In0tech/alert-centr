from datetime import UTC, datetime
from typing import Literal

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    app_secret_key: str = "change-me"
    cors_origins: str = "http://localhost:5173,http://localhost:8080"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def allowed_origins(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


class Alert(BaseModel):
    alert_uid: str
    target_cidr: str
    level: Literal[1, 2, 3]
    status: Literal["active", "closed"]
    start_time: datetime
    end_time: datetime | None = None
    traffic_gbps: float = Field(ge=0)
    dp_blocks: int = Field(ge=0)
    waf_blocks: int = Field(ge=0)


settings = Settings()
app = FastAPI(
    title="Alert Centre API",
    version="0.1.0",
    description="API boundary extracted from the legacy Flask/Dash application.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_SAMPLE_ALERTS = [
    Alert(
        alert_uid="ALT-2026-0001",
        target_cidr="37.9.244.0/24",
        level=1,
        status="active",
        start_time=datetime.now(UTC),
        traffic_gbps=7.8,
        dp_blocks=128400,
        waf_blocks=4210,
    ),
    Alert(
        alert_uid="ALT-2026-0002",
        target_cidr="217.118.84.0/24",
        level=2,
        status="closed",
        start_time=datetime(2026, 8, 29, 8, 30, tzinfo=UTC),
        end_time=datetime(2026, 8, 29, 9, 12, tzinfo=UTC),
        traffic_gbps=2.4,
        dp_blocks=9100,
        waf_blocks=860,
    ),
]


@app.get("/health", tags=["system"])
async def health() -> dict[str, str]:
    return {"status": "ok", "environment": settings.app_env}


@app.get("/api/v1/alerts", response_model=list[Alert], tags=["alerts"])
async def list_alerts(
    status: Literal["active", "closed"] | None = Query(default=None),
    level: Literal[1, 2, 3] | None = Query(default=None),
) -> list[Alert]:
    alerts = _SAMPLE_ALERTS
    if status is not None:
        alerts = [alert for alert in alerts if alert.status == status]
    if level is not None:
        alerts = [alert for alert in alerts if alert.level == level]
    return alerts


@app.get("/api/v1/alerts/{alert_uid}", response_model=Alert, tags=["alerts"])
async def get_alert(alert_uid: str) -> Alert:
    for alert in _SAMPLE_ALERTS:
        if alert.alert_uid == alert_uid:
            return alert
    from fastapi import HTTPException

    raise HTTPException(status_code=404, detail="Alert not found")
