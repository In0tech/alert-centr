from app.core.config import get_settings
from app.db.sqlite import sqlite_connection


class AlertsRepository:
    def __init__(self) -> None:
        self.settings = get_settings()

    def get_all(self) -> list[dict]:
        query = """
            SELECT
                UID AS alert_uid,
                TARGET_CIDR AS target_cidr,
                START_TIME AS start_time,
                END_TIME AS end_time,
                MAX_BPS AS max_bps,
                CURRENT_MAX_BPS AS current_max_bps,
                LEVEL AS level,
                WAF_BLOCKS AS waf_blocks,
                DP_BLOCKS AS dp_blocks
            FROM alerts
            ORDER BY START_TIME DESC
        """
        with sqlite_connection(self.settings.alerts_db_path) as connection:
            rows = connection.execute(query).fetchall()
        return [dict(row) for row in rows]

    def get_by_id(self, alert_uid: str) -> dict | None:
        query = """
            SELECT
                UID AS alert_uid,
                TARGET_CIDR AS target_cidr,
                START_TIME AS start_time,
                END_TIME AS end_time,
                MAX_BPS AS max_bps,
                CURRENT_MAX_BPS AS current_max_bps,
                LEVEL AS level,
                WAF_BLOCKS AS waf_blocks,
                DP_BLOCKS AS dp_blocks
            FROM alerts
            WHERE CAST(UID AS TEXT) = ?
        """
        with sqlite_connection(self.settings.alerts_db_path) as connection:
            row = connection.execute(query, (alert_uid,)).fetchone()
        return dict(row) if row else None
