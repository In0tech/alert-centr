from datetime import datetime

from app.db.clickhouse import get_clickhouse_client


class MetricsRepository:
    def get_summary(self, start: datetime, end: datetime) -> dict:
        client = get_clickhouse_client()
        query = """
            SELECT
                count() AS attacks,
                avg(MAX_BPS) AS avg_bps,
                max(MAX_BPS) AS max_bps,
                avg(dateDiff('second', START_TIME, coalesce(END_TIME, now()))) AS avg_duration
            FROM genie_events
            WHERE START_TIME >= {start:DateTime}
              AND START_TIME <= {end:DateTime}
        """
        row = client.query(query, parameters={"start": start, "end": end}).result_rows[0]
        return {
            "attacks": int(row[0] or 0),
            "avg_bps": float(row[1] or 0),
            "max_bps": float(row[2] or 0),
            "avg_duration": float(row[3] or 0),
        }
