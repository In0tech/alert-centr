from functools import lru_cache

import clickhouse_connect

from app.core.config import get_settings


@lru_cache
def get_clickhouse_client():
    settings = get_settings()
    return clickhouse_connect.get_client(
        host=settings.clickhouse_host,
        port=settings.clickhouse_port,
        username=settings.clickhouse_user,
        password=settings.clickhouse_password,
        database=settings.clickhouse_database,
    )
