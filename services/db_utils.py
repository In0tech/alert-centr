"""Shared helpers for ClickHouse queries used across services, ingests,
exports, and the web layer.

This module consolidates previously copy-pasted snippets:
  - `unique_id_condition` (dedup subquery for ReplacingMergeTree)
  - `q_result_to_df` (query -> pandas DataFrame)
  - `_normalize_net_broadcast` (IPv4 /32-ending-in-.0 fixup)
  - `time_filter_sql`, `time_filter_recent_updates_sql`
  - `_net_intersects_sql`, `_time_intersects_sql`
  - `cidr_to_filter`, `time_to_filter` (OpenSearch helpers)

No clients are constructed at import. `q_result_to_df` resolves the
ClickHouse client lazily through `services.clients`.
"""

import ipaddress

import pandas as pd

from services.clients import get_clickhouse_client


unique_id_condition = '''
(ID, UPDATE_TIME) IN (
    SELECT ID, MAX(UPDATE_TIME) as UPDATE_TIME
    FROM genie_events
    GROUP BY ID
)
'''


def q_result_to_df(query, client=None):
    ch = client if client is not None else get_clickhouse_client()
    result = ch.query(query)
    rows = result.result_rows
    if not rows:
        return pd.DataFrame()
    cols = [c[0] for c in result.columns]
    return pd.DataFrame(rows, columns=cols)


def _normalize_net_broadcast(target_network, target_broadcast):
    """A /32 ending in .0 (network==broadcast) is actually a /24 in disguise."""
    if target_network == target_broadcast and str(target_network).endswith('.0'):
        octets = str(target_network).split('.')
        return target_network, '.'.join(octets[:3] + ['255'])
    return target_network, target_broadcast


def time_filter_sql(start_iso=None, end_iso=None):
    if start_iso and end_iso:
        return f" ( START_TIME >= toDateTime('{start_iso}') AND START_TIME <= toDateTime('{end_iso}') ) \
               OR ( END_TIME >= toDateTime('{start_iso}')   AND END_TIME <= toDateTime('{end_iso}')   ) "
    elif start_iso:
        return f"START_TIME >= toDateTime('{start_iso}') OR END_TIME >= toDateTime('{start_iso}') OR END_TIME IS NULL"
    elif end_iso:
        return f"START_TIME <= toDateTime('{end_iso}') OR  END_TIME <= toDateTime('{end_iso}')"


def time_filter_recent_updates_sql(start_iso=None, end_iso=None):
    if start_iso and end_iso:
        return f"START_TIME >= toDateTime('{start_iso}') AND END_TIME <= toDateTime('{end_iso}')"
    elif start_iso:
        return f"START_TIME >= toDateTime('{start_iso}')"
    elif end_iso:
        return f"END_TIME <= toDateTime('{end_iso}')"


def _net_intersects_sql(target_net_col, target_bcast_col, cidr):
    """ClickHouse predicate: stored network range [target_net_col,
    target_bcast_col] (IPv4-as-uint32 OR dotted-quad strings) intersects the
    input CIDR. Covers exact match, subnet, supernet, and partial overlap.

    Both columns are coerced via toUInt32() so dotted-quad TEXT and integer
    storage both work.
    """
    net = ipaddress.IPv4Network(cidr, strict=False)
    net_str = str(net.network_address)
    bcast_str = str(net.broadcast_address)
    return (f"( toUInt32({target_net_col}) <= toUInt32(toIPv4('{bcast_str}')) "
            f"AND toUInt32({target_bcast_col}) >= toUInt32(toIPv4('{net_str}')) )")


def _time_intersects_sql(start_col, end_col, start_iso, end_iso):
    """ClickHouse predicate: stored [start_col, end_col] interval intersects
    [start_iso, end_iso]. NULL end_col is treated as unbounded (ongoing)."""
    return (f"( {start_col} <= toDateTime('{end_iso}') "
            f"AND (isNull({end_col}) OR {end_col} >= toDateTime('{start_iso}')) )")


def cidr_to_filter(cidr, ip_field_name='ipdst'):
    dst_net = ipaddress.IPv4Network(cidr, strict=False)
    if dst_net.network_address == dst_net.broadcast_address:
        query_filter = {"term": {f"{ip_field_name}.keyword": str(dst_net.network_address)}}
    else:
        query_filter = {"range": {ip_field_name: {"gte": str(dst_net.network_address),
                                                  "lte": str(dst_net.broadcast_address),
                                                  "include_lower": True, "include_upper": True}}}
    return query_filter


def time_to_filter(start, end=None):
    start = pd.to_datetime(start).isoformat()
    end = pd.to_datetime(end).isoformat() if end else 'now'
    return {"gte": start, "lte": end}

