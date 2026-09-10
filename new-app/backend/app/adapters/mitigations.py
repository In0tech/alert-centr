from datetime import datetime, timezone

from app.core.config import get_settings
from app.db.clickhouse import get_clickhouse_client
from app.db.sqlite import sqlite_connection


class MitigationsRepository:
    def __init__(self) -> None:
        self.settings = get_settings()

    def get_current(self) -> list[dict]:
        query = """
            SELECT
                TARGET_CIDR AS cidr,
                TARGET_NETWORK_INT AS target_network_int,
                TARGET_BROADCAST_INT AS target_broadcast_int,
                CURRENT_MITIGATION AS mitigation,
                UPDATE_TIME_UNIX AS update_time_unix
            FROM mitigations
            ORDER BY UPDATE_TIME_UNIX DESC
        """
        with sqlite_connection(self.settings.mitigations_db_path) as connection:
            rows = connection.execute(query).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            ts = item.get("update_time_unix")
            item["update_time"] = datetime.fromtimestamp(ts, tz=timezone.utc) if ts else None
            result.append(item)
        return result

    def get_history(self, days: int = 7) -> list[dict]:
        days = max(1, min(int(days), 365))
        client = get_clickhouse_client()
        query = """
            SELECT TARGET_CIDR, CURRENT_MITIGATION, UPDATE_TIME
            FROM mitigations_events
            WHERE UPDATE_TIME >= now() - INTERVAL {days:UInt16} DAY
            ORDER BY UPDATE_TIME DESC
        """
        rows = client.query(query, parameters={"days": days}).result_rows
        return [
            {"cidr": row[0], "mitigation": row[1], "changed_at": row[2]}
            for row in rows
        ]
