"""Lazy singletons for ClickHouse and OpenSearch clients.

Importing this module performs no network I/O. Clients are constructed on
first call to `get_clickhouse_client()` / `get_opensearch_client()` and
cached via functools.lru_cache.

Call `reset_clients()` to clear the caches (useful in tests).
"""

import functools

import clickhouse_connect
from opensearchpy import OpenSearch

from services import config


@functools.lru_cache(maxsize=1)
def get_clickhouse_client():
    return clickhouse_connect.get_client(
        host=config.clickhouse_host(),
        port=config.clickhouse_port(),
        user=config.clickhouse_user(),
        database=config.clickhouse_database(),
    )


@functools.lru_cache(maxsize=1)
def get_opensearch_client():
    return OpenSearch(
        hosts=[{'host': config.opensearch_host(), 'port': config.opensearch_port()}],
        http_compress=True,
        http_auth=(config.opensearch_username(), config.opensearch_password()),
        use_ssl=True,
        verify_certs=False,
        ssl_assert_hostname=False,
        ssl_show_warn=False,
        timeout=30,
    )


def reset_clients():
    get_clickhouse_client.cache_clear()
    get_opensearch_client.cache_clear()

