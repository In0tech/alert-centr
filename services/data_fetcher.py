import os
import pathlib
import configparser
import sqlite3
import ipaddress
from datetime import datetime, timedelta

import pandas as pd
import clickhouse_connect
import geoip2.database
from opensearchpy import OpenSearch


##############################################################################
############################   CONFIG / CLIENTS   ############################
##############################################################################

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'alert_center.conf'))

CLICKHOUSE_HOST = config.get('CLICKHOUSE', 'HOST')
CLICKHOUSE_PORT = config.getint('CLICKHOUSE', 'PORT')
CLICKHOUSE_USER = config.get('CLICKHOUSE', 'USER')
CLICKHOUSE_DATABASE = config.get('CLICKHOUSE', 'DATABASE')
clickhouse_client = clickhouse_connect.get_client(
    host=CLICKHOUSE_HOST,
    port=CLICKHOUSE_PORT,
    user=CLICKHOUSE_USER,
    database=CLICKHOUSE_DATABASE,
)

ALERTS_DB_PATH = config.get('DATABASE_PATHS', 'ALERTS_DB_PATH')
MITIGATIONS_DB_PATH = config.get('DATABASE_PATHS', 'MITIGATIONS_DB_PATH')
KUMA_STATUS_DB_PATH = config.get('DATABASE_PATHS', 'KUMA_STATUS_DB_PATH')

OPENSEARCH_HOST = config.get('OPENSEARCH', 'HOST')
OPENSEARCH_PORT = config.getint('OPENSEARCH', 'PORT')
OPENSEARCH_USERNAME = config.get('OPENSEARCH', 'USERNAME')
OPENSEARCH_PASSWORD = config.get('OPENSEARCH', 'PASSWORD')

opensearch_client = OpenSearch(
    hosts=[{'host': OPENSEARCH_HOST, 'port': OPENSEARCH_PORT}],
    http_compress=True,
    http_auth=(OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD),
    use_ssl=True,
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False,
    timeout=30,
)


##############################################################################
##############################   HELPERS   ####################################
##############################################################################

unique_id_condition = '''
(ID, UPDATE_TIME) IN (
    SELECT ID, MAX(UPDATE_TIME) as UPDATE_TIME
    FROM genie_events
    GROUP BY ID
)
'''


def time_filter_sql(start_iso=None, end_iso=None):
    # START_TIME and END_TIME
    if start_iso and end_iso:
        return f" ( START_TIME >= toDateTime('{start_iso}') AND START_TIME <= toDateTime('{end_iso}') ) \
               OR ( END_TIME >= toDateTime('{start_iso}')   AND END_TIME <= toDateTime('{end_iso}')   ) "
    elif start_iso:
        return f"START_TIME >= toDateTime('{start_iso}') OR END_TIME >= toDateTime('{start_iso}') OR END_TIME IS NULL"
    elif end_iso:
        return f"START_TIME <= toDateTime('{end_iso}') OR  END_TIME <= toDateTime('{end_iso}')"


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
    start = f"{str(pd.to_datetime(start).isoformat())}+03:00"
    end = f"{str(pd.to_datetime(end).isoformat())}+03:00" if end else 'now'
    return {"gte": start, "lte": end}


def format_datetime_for_query(dt):
    """Format a datetime (or datetime-like value) for SQLite queries
    that compare against START_TIME / END_TIME TEXT columns
    ('YYYY-MM-DD HH:MM:SS')."""
    if dt is None:
        return None
    return pd.to_datetime(dt).strftime('%Y-%m-%d %H:%M:%S')


# MaxMind's GeoLite2 Russian country names occasionally use unusual or
# Soviet-era abbreviations (e.g. "ФРГ" instead of "Германия", "Британия"
# instead of "Великобритания"). This override table maps ISO codes to the
# conventional Russian names and is consulted before country.names['ru'].
_COUNTRY_RU_OVERRIDE = {
    'DE': 'Германия',
    'GB': 'Великобритания',
    'US': 'США',
    'RU': 'Россия',
    'FR': 'Франция',
    'IT': 'Италия',
    'ES': 'Испания',
    'CN': 'Китай',
    'JP': 'Япония',
    'KR': 'Республика Корея',
    'KP': 'КНДР',
    'IN': 'Индия',
    'BR': 'Бразилия',
    'CA': 'Канада',
    'AU': 'Австралия',
    'NL': 'Нидерланды',
    'BE': 'Бельгия',
    'PL': 'Польша',
    'UA': 'Украина',
    'BY': 'Беларусь',
    'KZ': 'Казахстан',
    'TR': 'Турция',
    'IR': 'Иран',
    'IQ': 'Ирак',
    'SA': 'Саудовская Аравия',
    'AE': 'ОАЭ',
    'EG': 'Египет',
    'ZA': 'ЮАР',
    'MX': 'Мексика',
    'AR': 'Аргентина',
    'VN': 'Вьетнам',
    'TH': 'Таиланд',
    'ID': 'Индонезия',
    'PH': 'Филиппины',
    'SG': 'Сингапур',
    'MY': 'Малайзия',
    'PK': 'Пакистан',
    'BD': 'Бангладеш',
    'IL': 'Израиль',
    'RO': 'Румыния',
    'CZ': 'Чехия',
    'SK': 'Словакия',
    'HU': 'Венгрия',
    'AT': 'Австрия',
    'CH': 'Швейцария',
    'SE': 'Швеция',
    'NO': 'Норвегия',
    'FI': 'Финляндия',
    'DK': 'Дания',
    'PT': 'Португалия',
    'GR': 'Греция',
    'BG': 'Болгария',
    'RS': 'Сербия',
    'HR': 'Хорватия',
    'SI': 'Словения',
    'LT': 'Литва',
    'LV': 'Латвия',
    'EE': 'Эстония',
    'MD': 'Молдова',
    'GE': 'Грузия',
    'AM': 'Армения',
    'AZ': 'Азербайджан',
    'UZ': 'Узбекистан',
    'KG': 'Киргизия',
    'TJ': 'Таджикистан',
    'TM': 'Туркмения',
    'CO': 'Колумбия',
    'CL': 'Чили',
    'PE': 'Перу',
    'VE': 'Венесуэла',
    'NG': 'Нигерия',
    'KE': 'Кения',
    'MA': 'Марокко',
    'DZ': 'Алжир',
    'TN': 'Тунис',
}

_GEOLITE_PATH = pathlib.Path('/export/home/lvelueta/alert_center/dbs/GeoLite2-City.mmdb')
_geoip_reader = None


def _get_geoip_reader():
    """Lazy-load the GeoLite2-City reader once per process. Returns None
    if the .mmdb file is not present (e.g. dev box without the DB)."""
    global _geoip_reader
    if _geoip_reader is None:
        try:
            _geoip_reader = geoip2.database.Reader(_GEOLITE_PATH)
        except Exception:
            _geoip_reader = None
    return _geoip_reader


def ip_to_country_label(ip):
    """Resolve a source IP to a Russian country name via GeoLite2.
    Uses _COUNTRY_RU_OVERRIDE first (MaxMind's Russian names are
    occasionally Soviet-era abbreviations like 'ФРГ' / 'Британия'),
    then country.names['ru'], then the English name. Returns None
    only when the GeoLite2 reader is unavailable."""
    reader = _get_geoip_reader()
    if reader is None:
        return None
    try:
        resp = reader.city(ip)
        iso = resp.country.iso_code
        if iso and iso in _COUNTRY_RU_OVERRIDE:
            return _COUNTRY_RU_OVERRIDE[iso]
        names = resp.country.names or {}
        name = names.get('ru') or names.get('en')
        if not name:
            return None
        return str(name)
    except Exception:
        return None


def _normalize_net_broadcast(target_network, target_broadcast):
    """A /32 ending in .0 (network==broadcast) is actually a /24 in disguise."""
    if target_network == target_broadcast and str(target_network).endswith('.0'):
        octets = str(target_network).split('.')
        return target_network, '.'.join(octets[:3] + ['255'])
    return target_network, target_broadcast


def _net_broad_to_cidr(target_network, target_broadcast):
    try:
        net = ipaddress.IPv4Address(target_network)
        bcast = ipaddress.IPv4Address(target_broadcast)
        if net == bcast:
            if int(net.packed[-1]) == 0:
                return str(ipaddress.IPv4Network(f"{net}/24", strict=False))
            return f"{net}/32"
        for prefix in range(31, -1, -1):
            n = ipaddress.IPv4Network(f"{net}/{prefix}", strict=False)
            if n.network_address == net and n.broadcast_address == bcast:
                return str(n)
        cidrs = list(ipaddress.summarize_address_range(net, bcast))
        return ", ".join(str(c) for c in cidrs)
    except Exception:
        return f"{target_network} - {target_broadcast}"


def _normalize_attack_record(rec):
    if rec is None:
        return None
    rec = dict(rec)
    tn = rec.pop('target_network', None)
    tb = rec.pop('target_broadcast', None)
    rec['target'] = _net_broad_to_cidr(tn, tb)
    res = rec.get('resource')
    if isinstance(res, (list, tuple)):
        rec['resource'] = '\n'.join(str(x) for x in res)
    return rec


##############################################################################
################################   ALERTS   ##################################
##############################################################################

def get_alerts():
    sqlite_connection = sqlite3.connect(ALERTS_DB_PATH)
    sqlite_connection.execute('PRAGMA busy_timeout = 10000')
    df = pd.read_sql_query(
        'SELECT UID, TARGET_CIDR, START_TIME, END_TIME, MAX_BPS, CURRENT_MAX_BPS, '
        'LEVEL, WAF_BLOCKS, DP_BLOCKS FROM alerts',
        sqlite_connection,
    )
    sqlite_connection.close()

    df = df.rename(columns={
        'UID': 'alert_uid',
        'TARGET_CIDR': 'target_cidr',
        'START_TIME': 'start_time',
        'END_TIME': 'end_time',
        'MAX_BPS': 'max_bps',
        'CURRENT_MAX_BPS': 'current_max_bps',
        'LEVEL': 'level',
        'WAF_BLOCKS': 'waf_blocks',
        'DP_BLOCKS': 'dp_blocks',
    })
    return df


def get_alert(alert_id):
    sqlite_connection = sqlite3.connect(ALERTS_DB_PATH)
    sqlite_connection.execute('PRAGMA busy_timeout = 10000')
    df = pd.read_sql_query(f'SELECT UID, TARGET_CIDR, START_TIME, END_TIME, MAX_BPS, CURRENT_MAX_BPS, LEVEL, WAF_BLOCKS, DP_BLOCKS FROM alerts WHERE UID = {alert_id}', sqlite_connection)
    sqlite_connection.close()

    df = df.rename(columns={
        'UID': 'alert_uid',
        'TARGET_CIDR': 'target_cidr',
        'START_TIME': 'start_time',
        'END_TIME': 'end_time',
        'MAX_BPS': 'max_bps',
        'CURRENT_MAX_BPS': 'current_max_bps',
        'LEVEL': 'level',
        'WAF_BLOCKS': 'waf_blocks',
        'DP_BLOCKS': 'dp_blocks',
    })
    return df


def get_alerts_for_search(cidr, start_time, end_time):
    """Alerts whose network range intersects `cidr` AND whose [start_time,
    end_time] interval intersects [start_time, end_time] (NULL end = ongoing,
    treated as unbounded).

    Uses TARGET_NETWORK_INT / TARGET_BROADCAST_INT columns (populated by
    services.alert.migrate_alerts_add_int_cols + fill_alerts) so the net
    intersection is done in SQL. Time intersection is also done in SQL via
    bound parameters (no f-string interpolation) to avoid the SQL-injection
    risk called out in AGENTS.md.
    """
    net = ipaddress.IPv4Network(cidr, strict=False)
    net_int = int(net.network_address)
    bcast_int = int(net.broadcast_address)

    start_str = pd.to_datetime(start_time).strftime('%Y-%m-%d %H:%M:%S') if start_time else None
    end_str = pd.to_datetime(end_time).strftime('%Y-%m-%d %H:%M:%S') if end_time else None

    sqlite_connection = sqlite3.connect(ALERTS_DB_PATH)
    sqlite_connection.execute('PRAGMA busy_timeout = 10000')
    try:
            df = pd.read_sql_query(
                '''SELECT UID, TARGET_CIDR, START_TIME, END_TIME, MAX_BPS, LEVEL, WAF_BLOCKS, DP_BLOCKS
                 FROM alerts
                WHERE TARGET_NETWORK_INT <= ?
                  AND TARGET_BROADCAST_INT >= ?
                  AND START_TIME <= ?
                  AND (END_TIME IS NULL OR END_TIME >= ?)
                ORDER BY START_TIME DESC''',
            sqlite_connection,
            params=(bcast_int, net_int, end_str, start_str)
        )
    finally:
        sqlite_connection.close()

    df = df.rename(columns={
        'UID': 'alert_uid',
        'TARGET_CIDR': 'target_cidr',
        'START_TIME': 'start_time',
        'END_TIME': 'end_time',
        'MAX_BPS': 'max_bps',
        'LEVEL': 'level',
        'WAF_BLOCKS': 'waf_blocks',
        'DP_BLOCKS': 'dp_blocks',
    })
    return df


def get_top_alerts_by_bps(start_time, end_time):
    """Top-3 alerts (by CURRENT_MAX_BPS) whose [START_TIME, END_TIME]
    falls within [start_time, end_time]. Parameterized SQLite query.
    Returns an empty DataFrame on error."""
    try:
        start_str = format_datetime_for_query(start_time)
        end_str = format_datetime_for_query(end_time)

        sqlite_connection = sqlite3.connect(ALERTS_DB_PATH)
        sqlite_connection.execute('PRAGMA busy_timeout = 10000')
        try:
            df = pd.read_sql_query(
                '''SELECT UID, TARGET_CIDR, START_TIME, END_TIME, CURRENT_MAX_BPS
                     FROM alerts
                    WHERE START_TIME >= ? AND END_TIME <= ?
                    ORDER BY CURRENT_MAX_BPS DESC
                    LIMIT 3''',
                sqlite_connection,
                params=[start_str, end_str]
            )
        finally:
            sqlite_connection.close()
        return df
    except Exception as e:
        print(f"Error in get_top_alerts_by_bps: {e}")
        return pd.DataFrame()


def get_top_alerts_by_duration(start_time, end_time):
    """Top-3 alerts (by duration in seconds) whose [START_TIME, END_TIME]
    falls within [start_time, end_time]. Parameterized SQLite query.
    Returns an empty DataFrame on error."""
    try:
        start_str = format_datetime_for_query(start_time)
        end_str = format_datetime_for_query(end_time)

        sqlite_connection = sqlite3.connect(ALERTS_DB_PATH)
        sqlite_connection.execute('PRAGMA busy_timeout = 10000')
        try:
            df = pd.read_sql_query(
                '''SELECT UID, TARGET_CIDR, START_TIME, END_TIME, CURRENT_MAX_BPS,
                          (julianday(END_TIME) - julianday(START_TIME)) * 24 * 60 * 60 AS duration_seconds
                     FROM alerts
                    WHERE START_TIME >= ? AND END_TIME <= ?
                    ORDER BY duration_seconds DESC
                    LIMIT 3''',
                sqlite_connection,
                params=[start_str, end_str]
            )
        finally:
            sqlite_connection.close()
        return df
    except Exception as e:
        print(f"Error in get_top_alerts_by_duration: {e}")
        return pd.DataFrame()


##############################################################################
##############################   KUMA EVENTS   ###############################
##############################################################################

def get_kuma_status(target_cidr):
    network = ipaddress.IPv4Network(target_cidr, strict=False)
    target_network = str(network.network_address)
    target_broadcast = str(network.broadcast_address)

    unique_ip_condition = '''
    (TARGET_IP, UPDATE_TIME) IN (
        SELECT TARGET_IP, MAX(UPDATE_TIME) as UPDATE_TIME
        FROM kuma_events
        GROUP BY TARGET_IP
    )
    '''

    query = f"""
    SELECT TARGET_IP, STATUS, UPDATE_TIME
    FROM kuma_events
    WHERE toUInt32(TARGET_IP) >= toUInt32(toIPv4('{target_network}'))
        AND toUInt32(TARGET_IP) <= toUInt32(toIPv4('{target_broadcast}'))
        AND {unique_ip_condition}
    """
    result = clickhouse_client.query(query)
    rows = result.result_rows
    return pd.DataFrame(rows, columns=['target_ip', 'status', 'last_update'])


def get_kuma_events_by_time(start_time, end_time):
    """Return all kuma_events whose UPDATE_TIME falls within
    [start_time - 5 minutes, end_time]. If end_time is None/NaT/empty
    (ongoing alert) no upper bound is applied (i.e. up to now).

    Unlike get_kuma_status (which dedups to the latest status per IP for a
    given CIDR), this returns every status-change event within the time
    window regardless of target IP.
    """
    start_ts = pd.to_datetime(start_time, errors='coerce')
    if pd.isna(start_ts):
        return pd.DataFrame(columns=['target_ip', 'status', 'last_update'])

    lower_bound = (start_ts - timedelta(minutes=5)).strftime('%Y-%m-%d %H:%M:%S')

    end_ts = pd.to_datetime(end_time, errors='coerce')

    if pd.isna(end_ts):
        time_clause = f"UPDATE_TIME >= toDateTime('{lower_bound}')"
    else:
        upper_bound = end_ts.strftime('%Y-%m-%d %H:%M:%S')
        time_clause = (
            f"UPDATE_TIME >= toDateTime('{lower_bound}') "
            f"AND UPDATE_TIME <= toDateTime('{upper_bound}')"
        )

    query = f"""
    SELECT TARGET_IP, STATUS, UPDATE_TIME
    FROM kuma_events
    WHERE {time_clause}
    ORDER BY UPDATE_TIME
    """
    
    result = clickhouse_client.query(query)
    rows = result.result_rows
    return pd.DataFrame(rows, columns=['target_ip', 'status', 'last_update'])


##############################################################################
##############################   MITIGATIONS   ################################
##############################################################################

def get_mitigations():
    """All rows from the SQLite mitigations table (current SBH state).
    Returns a DataFrame with friendly column names; empty DataFrame if
    no rows."""
    sqlite_connection = sqlite3.connect(MITIGATIONS_DB_PATH)
    sqlite_connection.execute('PRAGMA busy_timeout = 10000')
    try:
        cursor = sqlite_connection.cursor()
        cursor.execute('SELECT * FROM mitigations')
        rows = cursor.fetchall()
    finally:
        sqlite_connection.close()

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows, columns=[
        'CIDR', 'TARGET_NETWORK_INT', 'TARGET_BROADCAST_INT',
        'Mitigation', 'Update time',
    ])
    df['Update time'] = pd.to_datetime(df['Update time'], unit='s')
    return df


def get_mitigations_for_cidr(net_int, bcast_int):
    """Rows from the SQLite mitigations table whose stored network range
    intersects the input [net_int, bcast_int] range. Parameterized query
    (closes the SQL-injection surface of the original f-string version in
    alert_interactive.test_stuff).

    Note: the predicate preserves the historical behaviour of the original
    view code (TARGET_NETWORK_INT <= net_int AND TARGET_BROADCAST_INT >=
    bcast_int).
    """
    sqlite_connection = sqlite3.connect(MITIGATIONS_DB_PATH)
    sqlite_connection.execute('PRAGMA busy_timeout = 10000')
    try:
        df = pd.read_sql_query(
            '''SELECT TARGET_CIDR, TARGET_NETWORK_INT, TARGET_BROADCAST_INT,
                      CURRENT_MITIGATION, UPDATE_TIME_UNIX
                 FROM mitigations
                WHERE TARGET_NETWORK_INT <= ?
                  AND TARGET_BROADCAST_INT >= ?''',
            sqlite_connection,
            params=[int(net_int), int(bcast_int)]
        )
    finally:
        sqlite_connection.close()
    return df


def get_mitigation_events(days: int = 7):
    """Recent ClickHouse mitigations_events rows (default last 7 days).
    Uses the shared clickhouse_client singleton (replaces the per-call
    client constructed in alert_interactive.get_mitigation_events)."""
    days = int(days)
    rows = clickhouse_client.query(f"""
        SELECT TARGET_CIDR, CURRENT_MITIGATION, UPDATE_TIME
        FROM alert_center.mitigations_events
        WHERE UPDATE_TIME >= now() - INTERVAL {days} DAY
        ORDER BY UPDATE_TIME DESC
    """).result_rows

    if not rows:
        return pd.DataFrame(columns=['Changed at', 'CIDR', 'Mitigation'])

    df = pd.DataFrame(rows, columns=['CIDR', 'Mitigation', 'Changed at'])
    df['Mitigation'] = df['Mitigation'].apply(
        lambda x: 'removed' if x is None or (isinstance(x, float) and pd.isna(x)) else x
    )
    df['Changed at'] = pd.to_datetime(df['Changed at']).dt.strftime('%Y-%m-%d %H:%M:%S')
    return df


##############################################################################
############################   WELCOME COUNTS   ###############################
# Lightweight read-only COUNT helpers used by the welcome / landing page.
# Each opens its own short-lived connection (consistent with the rest of
# this module) and returns an int, or None on any error so the caller can
# render a dash instead of 500-ing the whole page.
##############################################################################

def count_open_alerts():
    """Number of alerts with END_TIME IS NULL (ongoing)."""
    sqlite_connection = sqlite3.connect(ALERTS_DB_PATH)
    sqlite_connection.execute('PRAGMA busy_timeout = 10000')
    try:
        cursor = sqlite_connection.cursor()
        cursor.execute('SELECT COUNT(*) FROM alerts WHERE END_TIME IS NULL')
        return int(cursor.fetchone()[0])
    finally:
        sqlite_connection.close()


def count_active_mitigations():
    """Number of mitigations rows whose CURRENT_MITIGATION is non-empty
    (e.g. SBH or 'Переведён на ЦОТ'). NULL / '' means mitigation removed."""
    sqlite_connection = sqlite3.connect(MITIGATIONS_DB_PATH)
    sqlite_connection.execute('PRAGMA busy_timeout = 10000')
    try:
        cursor = sqlite_connection.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM mitigations "
            "WHERE CURRENT_MITIGATION IS NOT NULL AND CURRENT_MITIGATION != ''"
        )
        return int(cursor.fetchone()[0])
    finally:
        sqlite_connection.close()


def count_genie_events_24h():
    """Distinct Genie events started in the last 24h.

    MUST apply the unique_id_condition predicate because genie_events uses
    ReplacingMergeTree and would otherwise over-count until OPTIMIZE FINAL
    runs (see AGENTS.md).
    """
    since = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    query = f"""
        SELECT COUNT(*) FROM genie_events
        WHERE START_TIME >= toDateTime('{since}')
          AND {unique_id_condition}
    """
    return int(clickhouse_client.query(query).result_rows[0][0])


def count_kuma_probes():
    """Total number of monitored probes tracked in the SQLite kuma_status
    table (one row per TARGET_IP)."""
    sqlite_connection = sqlite3.connect(KUMA_STATUS_DB_PATH)
    sqlite_connection.execute('PRAGMA busy_timeout = 10000')
    try:
        cursor = sqlite_connection.cursor()
        cursor.execute('SELECT COUNT(*) FROM kuma_status')
        return int(cursor.fetchone()[0])
    finally:
        sqlite_connection.close()


##############################################################################
##############################   GENIE EVENTS   ###############################
##############################################################################

def get_related_genie(target_cidr, start_time, end_time):
    network = ipaddress.IPv4Network(target_cidr, strict=False)
    target_network = str(network.network_address)
    target_broadcast = str(network.broadcast_address)

    end_condition = ''
    if end_time:
        end_condition = f"AND END_TIME <= toDateTime('{end_time}')"

    query = f"""
    SELECT ID, STATUS, UPDATE_TIME, START_TIME, END_TIME, MAX_BPS, MAX_PPS, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST
    FROM genie_events
    WHERE toUInt32(TARGET_NETWORK) >= toUInt32(toIPv4('{target_network}'))
        AND toUInt32(TARGET_BROADCAST) <= toUInt32(toIPv4('{target_broadcast}'))
        AND START_TIME >= toDateTime('{start_time}')     {end_condition}
        AND {unique_id_condition}
    """

    result = clickhouse_client.query(query)
    rows = result.result_rows
    df = pd.DataFrame(rows, columns=['id', 'status', 'last_update', 'start', 'end', 'max_bps', 'max_pps', 'resource', 'target_network', 'target_broadcast'])
    df['target_network'], df['target_broadcast'] = zip(*df.apply(lambda r: _normalize_net_broadcast(r['target_network'], r['target_broadcast']), axis=1))
    return df


def get_genie_events_for_search(cidr, start_time, end_time):
    """Genie events whose TARGET_NETWORK..TARGET_BROADCAST range intersects
    `cidr` AND whose [START_TIME, END_TIME] interval intersects
    [start_time, end_time] (NULL END_TIME = ongoing, treated as unbounded).

    Net intersection covers exact match, subnet, supernet, and partial
    overlap (see _net_intersects_sql). Time intersection uses the
    "ends after start of period OR starts before end of period" semantics.

    Separate from get_related_genie (used by the alert detail page) which
    only looks for subnets of the alert CIDR — that behaviour is preserved.
    """
    net_predicate = _net_intersects_sql('TARGET_NETWORK', 'TARGET_BROADCAST', cidr)
    time_predicate = _time_intersects_sql('START_TIME', 'END_TIME', start_time, end_time)

    query = f"""
    SELECT ID, STATUS, UPDATE_TIME, START_TIME, END_TIME, MAX_BPS, MAX_PPS, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST
    FROM genie_events
    WHERE {net_predicate}
        AND {time_predicate}
        AND {unique_id_condition}
    """

    result = clickhouse_client.query(query)
    rows = result.result_rows
    df = pd.DataFrame(rows, columns=['id', 'status', 'last_update', 'start', 'end', 'max_bps', 'max_pps', 'resource', 'target_network', 'target_broadcast'])
    df['target_network'], df['target_broadcast'] = zip(*df.apply(lambda r: _normalize_net_broadcast(r['target_network'], r['target_broadcast']), axis=1))
    return df


def get_genie_traffic(start, end):
    tf = time_filter_sql(start, end)

    rows = clickhouse_client.query(f"""
    SELECT ID, START_TIME, END_TIME, MAX_BPS 
    FROM genie_events
    WHERE {tf} AND {unique_id_condition}
    """).result_rows

    return rows


def get_genie_events(start, end):
    tf = time_filter_sql(start, end)

    genie_rows = clickhouse_client.query(f"""
    SELECT ID, STATUS, UPDATE_TIME, START_TIME, END_TIME, MAX_BPS, MAX_PPS, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST
    FROM genie_events
    WHERE {tf} AND {unique_id_condition}
    """).result_rows

    df = pd.DataFrame(genie_rows, columns=['id', 'status', 'last_update', 'start', 'end', 'max_bps', 'max_pps', 'resource', 'target_network', 'target_broadcast'])
    df['target_network'], df['target_broadcast'] = zip(*df.apply(lambda r: _normalize_net_broadcast(r['target_network'], r['target_broadcast']), axis=1))

    return df


##############################################################################
#######################   REPORTS — VC-IT / IT_PE   ###########################
##############################################################################

def get_vc_it_elk_summary(start, end=None):
    time_filter = {"range": {"@timestamp": time_to_filter(start, end)}}
    action_filter = {"bool": {"must_not": {"term": {"action.keyword": "forward"}}}}
    volume_filter = {"range": {"packet_count": {"gte": 1000000}}}

    indices = {
        "ELK DP20": "logstash-beats-crq280529-radwarevision",
        "ELK DP6": "logstash-beats-crq440253-ru.antiddos.antiddos-prod",
        "ELK DP VA": "logstash-beats-crq465196-antiddos"
    }

    summary = {}
    for name, index in indices.items():
        try:
            res = opensearch_client.search(
                index=index,
                body={
                    "size": 0,
                    "query": {
                        "bool": {
                            "filter": [time_filter, action_filter, volume_filter]
                        }
                    }
                }
            )
            summary[name] = f"{res['hits']['total']['relation']}: {res['hits']['total']['value']}"
            print(res)
        except Exception as e:
            summary[name] = f"Error: {str(e)}"

    return summary


def get_vc_it_genie_summary(start_iso, end_iso=None):
    time_filter = time_filter_sql(start_iso, end_iso)

    resource_filter = """
        arrayExists(x -> position(x, 'vc-it') > 0, RESOURCE) OR 
        arrayExists(x -> position(x, 'IT_pe') > 0, RESOURCE)
    """
    conditions = f"({time_filter}) AND ({resource_filter})"

    max_bps_query = f"""
        SELECT ID, MAX_BPS, MAX_PPS, START_TIME, END_TIME, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST
        FROM genie_events
        WHERE {conditions}
          AND {unique_id_condition}
        ORDER BY MAX_BPS DESC
        LIMIT 1
    """

    max_duration_query = f"""
        SELECT ID, MAX_BPS, MAX_PPS, START_TIME, END_TIME, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST,
               if(isNull(END_TIME), dateDiff('second', START_TIME, now()), dateDiff('second', START_TIME, END_TIME)) AS duration
        FROM genie_events
        WHERE {conditions}
          AND {unique_id_condition}
        ORDER BY duration DESC
        LIMIT 1
    """

    result_max_bps = clickhouse_client.query(max_bps_query).result_rows
    result_max_duration = clickhouse_client.query(max_duration_query).result_rows

    df_max_bps = pd.DataFrame(result_max_bps, columns=['id', 'max_bps', 'max_pps', 'start_time', 'end_time', 'resource', 'target_network', 'target_broadcast'])
    df_max_duration = pd.DataFrame(result_max_duration, columns=['id', 'max_bps', 'max_pps', 'start_time', 'end_time', 'resource', 'target_broadcast', 'target_network', 'duration'])
    for df in (df_max_bps, df_max_duration):
        if not df.empty:
            df['target_network'], df['target_broadcast'] = zip(*df.apply(lambda r: _normalize_net_broadcast(r['target_network'], r['target_broadcast']), axis=1))

    return {
        'biggest_attack_by_bps': _normalize_attack_record(df_max_bps.to_dict(orient='records')[0]) if len(df_max_bps) > 0 else None,
        'longest_attack_by_duration': _normalize_attack_record(df_max_duration.to_dict(orient='records')[0]) if len(df_max_duration) > 0 else None
    }


def _build_extra_stats(conditions):
    duration_formula = "if(isNull(END_TIME), dateDiff('second', START_TIME, now()), dateDiff('second', START_TIME, END_TIME))"

    stats_query = f"""
        SELECT
            avg(MAX_BPS), median(MAX_BPS), varSamp(MAX_BPS), stddevSamp(MAX_BPS),
            avg(duration), median(duration), varSamp(duration), stddevSamp(duration)
        FROM (
            SELECT MAX_BPS, {duration_formula} AS duration
            FROM genie_events
            WHERE {conditions} AND {unique_id_condition}
        )
    """

    bps_bins_labels = [
        '<1 Mbps', '1-10 Mbps', '10-100 Mbps', '100-500 Mbps',
        '500M-1 Gbps', '1-2 Gbps', '2-3 Gbps', '3-4 Gbps',
        '4-5 Gbps', '5-10 Gbps', '>10 Gbps',
    ]
    bps_hist_query = f"""
        SELECT
            count() AS total,
            countIf(MAX_BPS < 1e6) AS c0,
            countIf(MAX_BPS >= 1e6 AND MAX_BPS < 1e7) AS c1,
            countIf(MAX_BPS >= 1e7 AND MAX_BPS < 1e8) AS c2,
            countIf(MAX_BPS >= 1e8 AND MAX_BPS < 5e8) AS c3,
            countIf(MAX_BPS >= 5e8 AND MAX_BPS < 1e9) AS c4,
            countIf(MAX_BPS >= 1e9 AND MAX_BPS < 2e9) AS c5,
            countIf(MAX_BPS >= 2e9 AND MAX_BPS < 3e9) AS c6,
            countIf(MAX_BPS >= 3e9 AND MAX_BPS < 4e9) AS c7,
            countIf(MAX_BPS >= 4e9 AND MAX_BPS < 5e9) AS c8,
            countIf(MAX_BPS >= 5e9 AND MAX_BPS < 1e10) AS c9,
            countIf(MAX_BPS >= 1e10) AS c10
        FROM genie_events
        WHERE {conditions} AND {unique_id_condition}
    """

    dur_bins_labels = [
        '\u22641 min', '1-5 min', '5-10 min', '10-20 min',
        '20-30 min', '30-60 min', '1-10 h', '>10 h',
    ]
    dur_hist_query = f"""
        SELECT
            count() AS total,
            countIf(duration <= 60) AS c0,
            countIf(duration > 60 AND duration < 300) AS c1,
            countIf(duration >= 300 AND duration < 600) AS c2,
            countIf(duration >= 600 AND duration < 1200) AS c3,
            countIf(duration >= 1200 AND duration < 1800) AS c4,
            countIf(duration >= 1800 AND duration < 3600) AS c5,
            countIf(duration >= 3600 AND duration < 36000) AS c6,
            countIf(duration >= 36000) AS c7
        FROM (
            SELECT {duration_formula} AS duration
            FROM genie_events
            WHERE {conditions} AND {unique_id_condition}
        )
    """

    stats_result = clickhouse_client.query(stats_query).result_rows
    bps_hist_result = clickhouse_client.query(bps_hist_query).result_rows
    dur_hist_result = clickhouse_client.query(dur_hist_query).result_rows

    if not stats_result or stats_result[0][0] is None:
        return {
            'avg_bps': None, 'median_bps': None, 'variance_bps': None, 'stddev_bps': None,
            'avg_duration': None, 'median_duration': None, 'variance_duration': None, 'stddev_duration': None,
            'bps_histogram': None,
            'duration_histogram': None,
        }

    sr = stats_result[0]

    bh = None
    if bps_hist_result:
        row = bps_hist_result[0]
        total = row[0] or 1
        bh = []
        for i, label in enumerate(bps_bins_labels):
            cnt = row[i + 1]
            bh.append({'label': label, 'count': cnt, 'pkt': round(cnt / total * 100, 1)})

    dh = None
    if dur_hist_result:
        row = dur_hist_result[0]
        total = row[0] or 1
        dh = []
        for i, label in enumerate(dur_bins_labels):
            cnt = row[i + 1]
            dh.append({'label': label, 'count': cnt, 'pkt': round(cnt / total * 100, 1)})

    return {
        'avg_bps': sr[0], 'median_bps': sr[1], 'variance_bps': sr[2], 'stddev_bps': sr[3],
        'avg_duration': sr[4], 'median_duration': sr[5], 'variance_duration': sr[6], 'stddev_duration': sr[7],
        'bps_histogram': bh,
        'duration_histogram': dh,
    }


def get_vc_it_extra_stats(start_iso, end_iso=None):
    time_filter = time_filter_sql(start_iso, end_iso)
    resource_filter = """
        arrayExists(x -> position(x, 'vc-it') > 0, RESOURCE) OR
        arrayExists(x -> position(x, 'IT_pe') > 0, RESOURCE)
    """
    conditions = f"({time_filter}) AND ({resource_filter})"
    return _build_extra_stats(conditions)


##############################################################################
##########################   REPORTS — B2B   ##################################
##############################################################################

def get_b2b_summary(start_iso, end_iso=None):
    time_filter = time_filter_sql(start_iso, end_iso)
    base_conditions = f"({time_filter}) AND {unique_id_condition}"

    e = datetime.strptime(end_iso, '%Y-%m-%dT%H:%M:%S') + timedelta(hours=2)
    end_iso = e.isoformat()
    tf = f"""
( START_TIME >= toDateTime('{start_iso}') AND START_TIME <= toDateTime('{end_iso}') ) \
    AND ( END_TIME >= toDateTime('{start_iso}')   AND END_TIME <= toDateTime('{end_iso}')   ) """

    # duration > 4 minutes
    extra_cond = """
         (dateDiff('second', START_TIME, END_TIME) > 239  AND 
         arrayExists(x -> NOT position(x, 'Home') > 0, RESOURCE)
         )
    """
    total_query = f"""
SELECT COUNT(DISTINCT ID) FROM genie_events WHERE ({tf}) AND ({extra_cond})
    """

    total_result = clickhouse_client.query(total_query).result_rows[0][0]

    vc_it_condition = """
        arrayExists(x -> position(x, 'vc-it') > 0 OR position(x, 'IT_pe') > 0, RESOURCE)
    """
    vc_it_query = f"""
        SELECT COUNT(*) FROM genie_events WHERE {base_conditions} AND ({vc_it_condition})
    """
    vc_it_result = clickhouse_client.query(vc_it_query).result_rows[0][0]

    test_condition = """
        arrayExists(x -> position(lowerUTF8(x), 'test') > 0, RESOURCE)
    """
    test_query = f"""
        SELECT COUNT(*) FROM genie_events WHERE {base_conditions} AND ({test_condition})
    """
    test_result = clickhouse_client.query(test_query).result_rows[0][0]

    fttb_condition = """
        arrayExists(x -> position(x, 'FTTB') > 0 OR position(x, 'PSCORE') > 0, RESOURCE)
    """
    fttb_query = f"""
        SELECT COUNT(*) FROM genie_events WHERE {base_conditions} AND ({fttb_condition})
    """
    fttb_result = clickhouse_client.query(fttb_query).result_rows[0][0]

    exclusion_condition = """
        NOT arrayExists(x -> x = 'Home' OR x = 'Non-Home' OR  position(x, 'vc-it') > 0 OR position(x, 'IT_pe') > 0 OR position(x, 'FTTB') > 0 OR position(x, 'PSCORE') > 0 OR position(lowerUTF8(x), 'test') > 0, RESOURCE)
    """
    duration_condition = """
        if(isNull(END_TIME), 
           dateDiff('second', START_TIME, now()) > 300,
           dateDiff('second', START_TIME, END_TIME) > 300)
    """

    impact_filter = f"""
        ({exclusion_condition})
    """

    max_bps_query = f"""
        SELECT ID, MAX_BPS, MAX_PPS, START_TIME, END_TIME, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST
        FROM genie_events
        WHERE {base_conditions} AND {impact_filter}
        ORDER BY MAX_BPS DESC
        LIMIT 1
    """

    max_bps_result = clickhouse_client.query(max_bps_query).result_rows
    max_duration_query = f"""
        SELECT ID, MAX_BPS, MAX_PPS, START_TIME, END_TIME, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST,
               if(isNull(END_TIME), dateDiff('second', START_TIME, now()), dateDiff('second', START_TIME, END_TIME)) AS duration
        FROM genie_events
        WHERE {base_conditions} AND {impact_filter}
        ORDER BY duration DESC
        LIMIT 1
    """
    max_duration_result = clickhouse_client.query(max_duration_query).result_rows

    df_max_bps = pd.DataFrame(max_bps_result,
                              columns=['id', 'max_bps', 'max_pps', 'start_time', 'end_time', 'resource', 'target_network',
                                       'target_broadcast']) if max_bps_result else pd.DataFrame(
        columns=['id', 'max_bps', 'max_pps', 'start_time', 'end_time', 'resource', 'target_network', 'target_broadcast'])

    df_max_duration = pd.DataFrame(max_duration_result,
                                   columns=['id', 'max_bps', 'max_pps', 'start_time', 'end_time', 'resource', 'target_network',
                                            'target_broadcast', 'duration']) if max_duration_result else pd.DataFrame(
        columns=['id', 'max_bps', 'max_pps', 'start_time', 'end_time', 'resource', 'target_network', 'target_broadcast', 'duration'])

    for df in (df_max_bps, df_max_duration):
        if not df.empty:
            df['target_network'], df['target_broadcast'] = zip(*df.apply(lambda r: _normalize_net_broadcast(r['target_network'], r['target_broadcast']), axis=1))

    return {
        'total_genie_events': total_result,
        'vc_it_it_pe_events': vc_it_result,
        'test_events': test_result,
        'fttb_events': fttb_result,
        'total_b2b_events': int(total_result) - int(vc_it_result) - int(test_result) - int(fttb_result),
        'biggest_attack_by_bps': _normalize_attack_record(df_max_bps.to_dict(orient='records')[0]) if not df_max_bps.empty else None,
        'longest_attack_by_duration': _normalize_attack_record(df_max_duration.to_dict(orient='records')[0]) if not df_max_duration.empty else None
    }


def get_b2b_extra_stats(start_iso, end_iso=None):
    e = datetime.strptime(end_iso, '%Y-%m-%dT%H:%M:%S') + timedelta(hours=2)
    end_shifted = e.isoformat()
    tf = f"""
( START_TIME >= toDateTime('{start_iso}') AND START_TIME <= toDateTime('{end_shifted}') ) \
    AND ( END_TIME >= toDateTime('{start_iso}')   AND END_TIME <= toDateTime('{end_shifted}')   )"""
    exclusion_condition = """
        NOT arrayExists(x -> x = 'Home' OR x = 'Non-Home' OR position(x, 'vc-it') > 0 OR position(x, 'IT_pe') > 0 OR position(x, 'FTTB') > 0 OR position(x, 'PSCORE') > 0 OR position(lowerUTF8(x), 'test') > 0, RESOURCE)
    """
    conditions = f"({tf}) AND ({exclusion_condition})"
    return _build_extra_stats(conditions)


##############################################################################
########################   REPORTS — SHPD / FTTB   ###########################
##############################################################################

def get_shpd_genie_summary(start_iso, end_iso=None):
    time_filter = time_filter_sql(start_iso, end_iso)

    resource_filter = "arrayExists(x -> position(x, 'FTTB') > 0 OR position(x, 'PSCORE') > 0, RESOURCE)"
    conditions = f"({time_filter}) AND ({resource_filter}) AND {unique_id_condition}"

    max_bps_query = f"""
        SELECT ID, MAX_BPS, MAX_PPS, START_TIME, END_TIME, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST
        FROM genie_events
        WHERE {conditions}
        ORDER BY MAX_BPS DESC
        LIMIT 1
    """

    max_duration_query = f"""
        SELECT ID, MAX_BPS, MAX_PPS, START_TIME, END_TIME, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST,
               if(isNull(END_TIME), dateDiff('second', START_TIME, now()), dateDiff('second', START_TIME, END_TIME)) AS duration
        FROM genie_events
        WHERE {conditions}
          AND {unique_id_condition}
        ORDER BY duration DESC
        LIMIT 1
    """

    result_max_bps = clickhouse_client.query(max_bps_query).result_rows
    result_max_duration = clickhouse_client.query(max_duration_query).result_rows

    df_max_bps = pd.DataFrame(result_max_bps, columns=['id', 'max_bps', 'max_pps', 'start_time', 'end_time', 'resource', 'target_network', 'target_broadcast'])
    df_max_duration = pd.DataFrame(result_max_duration, columns=['id', 'max_bps', 'max_pps', 'start_time', 'end_time', 'resource', 'target_network', 'target_broadcast', 'duration'])
    for df in (df_max_bps, df_max_duration):
        if not df.empty:
            df['target_network'], df['target_broadcast'] = zip(*df.apply(lambda r: _normalize_net_broadcast(r['target_network'], r['target_broadcast']), axis=1))

    return {
        'biggest_attack_by_bps': _normalize_attack_record(df_max_bps.to_dict(orient='records')[0]) if len(df_max_bps) > 0 else None,
        'longest_attack_by_duration': _normalize_attack_record(df_max_duration.to_dict(orient='records')[0]) if len(df_max_duration) > 0 else None
    }


def get_shpd_extra_stats(start_iso, end_iso=None):
    time_filter = time_filter_sql(start_iso, end_iso)
    resource_filter = "arrayExists(x -> position(x, 'FTTB') > 0 OR position(x, 'PSCORE') > 0, RESOURCE)"
    conditions = f"({time_filter}) AND ({resource_filter}) AND {unique_id_condition}"
    return _build_extra_stats(conditions)


##############################################################################
###################   REPORTS — ALL-EVENTS HISTOGRAMS   ######################
##############################################################################

_DURATION_BINS = [
    '\u22641 min', '1-5 min', '5-10 min', '10-20 min',
    '20-30 min', '30-60 min', '1-10 h', '>10 h',
]
_BPS_BINS = [
    '<1 Mbps', '1-10 Mbps', '10-100 Mbps', '100-500 Mbps',
    '500M-1 Gbps', '1-2 Gbps', '2-3 Gbps', '3-4 Gbps',
    '4-5 Gbps', '5-10 Gbps', '>10 Gbps',
]


def get_all_duration_histogram(start_iso, end_iso=None):
    """Duration histogram (8 bins) over ALL genie_events in the window
    (no resource filter). Mirrors the duration_histogram section of
    _build_extra_stats but with the bare time_filter as the only
    condition. Returns a list of {'label','count','pkt'} dicts, or
    None if no data."""
    time_filter = time_filter_sql(start_iso, end_iso)
    conditions = f"({time_filter})"

    duration_formula = ("if(isNull(END_TIME), "
                        "dateDiff('second', START_TIME, now()), "
                        "dateDiff('second', START_TIME, END_TIME))")

    dur_hist_query = f"""
        SELECT
            count() AS total,
            countIf(duration <= 60) AS c0,
            countIf(duration > 60 AND duration < 300) AS c1,
            countIf(duration >= 300 AND duration < 600) AS c2,
            countIf(duration >= 600 AND duration < 1200) AS c3,
            countIf(duration >= 1200 AND duration < 1800) AS c4,
            countIf(duration >= 1800 AND duration < 3600) AS c5,
            countIf(duration >= 3600 AND duration < 36000) AS c6,
            countIf(duration >= 36000) AS c7
        FROM (
            SELECT {duration_formula} AS duration
            FROM genie_events
            WHERE {conditions} AND {unique_id_condition}
        )
    """
    dur_hist_result = clickhouse_client.query(dur_hist_query).result_rows
    if not dur_hist_result:
        return None
    row = dur_hist_result[0]
    total = row[0] or 0
    if not total:
        return None
    dh = []
    for i, label in enumerate(_DURATION_BINS):
        cnt = row[i + 1] or 0
        dh.append({'label': label, 'count': cnt,
                   'pkt': round(cnt / total * 100, 1)})
    return dh


def get_all_bps_histogram(start_iso, end_iso=None):
    """BPS histogram (11 bins) over ALL genie_events in the window (no
    resource filter). Mirrors the bps_histogram section of
    _build_extra_stats but with the bare time_filter as the only
    condition. Returns a list of {'label','count','pkt'} dicts, or
    None if no data."""
    time_filter = time_filter_sql(start_iso, end_iso)
    conditions = f"({time_filter})"

    bps_hist_query = f"""
        SELECT
            count() AS total,
            countIf(MAX_BPS < 1e6) AS c0,
            countIf(MAX_BPS >= 1e6 AND MAX_BPS < 1e7) AS c1,
            countIf(MAX_BPS >= 1e7 AND MAX_BPS < 1e8) AS c2,
            countIf(MAX_BPS >= 1e8 AND MAX_BPS < 5e8) AS c3,
            countIf(MAX_BPS >= 5e8 AND MAX_BPS < 1e9) AS c4,
            countIf(MAX_BPS >= 1e9 AND MAX_BPS < 2e9) AS c5,
            countIf(MAX_BPS >= 2e9 AND MAX_BPS < 3e9) AS c6,
            countIf(MAX_BPS >= 3e9 AND MAX_BPS < 4e9) AS c7,
            countIf(MAX_BPS >= 4e9 AND MAX_BPS < 5e9) AS c8,
            countIf(MAX_BPS >= 5e9 AND MAX_BPS < 1e10) AS c9,
            countIf(MAX_BPS >= 1e10) AS c10
        FROM genie_events
        WHERE {conditions} AND {unique_id_condition}
    """
    bps_hist_result = clickhouse_client.query(bps_hist_query).result_rows
    if not bps_hist_result:
        return None
    row = bps_hist_result[0]
    total = row[0] or 0
    if not total:
        return None
    bh = []
    for i, label in enumerate(_BPS_BINS):
        cnt = row[i + 1] or 0
        bh.append({'label': label, 'count': cnt,
                   'pkt': round(cnt / total * 100, 1)})
    return bh


##############################################################################
######################   RADWARE  /  ANTIDDOS   ##############################
##############################################################################

def get_top_radware_summary(start, end=None):
    time_filter = {"range": {"@timestamp": time_to_filter(start, end)}}

    res = opensearch_client.search(index="*radwarevision*,*antiddos*", body={
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    time_filter,
                    {"bool": {"must_not": {"term": {"action.keyword": "forward"}}}}
                ]
            }
        },
        "aggs": {
            "top_ipdst": {
                "terms": {
                    "field": "ipdst.keyword",
                    "size": 11,
                    "order": {"_count": "desc"}
                }
            }
        }
    })

    top_ipdst = res['aggregations']['top_ipdst']['buckets']
    return top_ipdst


def get_top_policies_summary(start, end=None, size=10):
    """Top 'policy' values by document count over the DP index patterns
    (*radwarevision*, *antiddos*). Counts ALL actions (no drop filter).
    Returns a list of {'key','doc_count'} buckets, excluding empty/null keys.
    """
    time_filter = {"range": {"@timestamp": time_to_filter(start, end)}}

    res = opensearch_client.search(index="*radwarevision*,*antiddos*", body={
        "size": 0,
        "query": {
            "bool": {
                "filter": [time_filter]
            }
        },
        "aggs": {
            "top_policies": {
                "terms": {
                    "field": "policy.keyword",
                    "size": size,
                    "order": {"_count": "desc"}
                }
            }
        }
    })

    buckets = res['aggregations']['top_policies']['buckets']
    return [b for b in buckets if b.get('key')]


def get_dp_data(dst_cidr, start_time, end_time, top_descriptions_num=10):
    dst_net_query_filter = cidr_to_filter(dst_cidr)
    time_filter = time_to_filter(start_time, end_time)

    res = opensearch_client.search(index="*radwarevision*,*antiddos*", body={
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": time_filter}},
                    dst_net_query_filter
                ]
            }
        },
        "aggs": {
            "drops": {
                "filter": {"term": {"action.keyword": "drop"}},
                "aggs": {
                    "drop_packets": {"sum": {"field": "packet_count"}}
                }
            },
            "challenges": {
                "filter": {"term": {"action.keyword": "challenge"}},
                "aggs": {
                    "challenge_packets": {"sum": {"field": "packet_count"}}
                }
            },
            "top_drop_descriptions": {
                "filter": {"term": {"action.keyword": "drop"}},
                "aggs": {
                    "by_desc": {
                        "terms": {
                            "field": "description.keyword",
                            "size": top_descriptions_num,
                            "order": {"total_packets": "desc"}
                        },
                        "aggs": {
                            "total_packets": {"sum": {"field": "packet_count"}}
                        }
                    }
                }
            },
            "top_challenge_descriptions": {
                "filter": {"term": {"action.keyword": "challenge"}},
                "aggs": {
                    "by_desc": {
                        "terms": {
                            "field": "description.keyword",
                            "size": top_descriptions_num,
                            "order": {"total_packets": "desc"}
                        },
                        "aggs": {
                            "total_packets": {"sum": {"field": "packet_count"}}
                        }
                    }
                }
            },
            "top_policies": {
                "terms": {
                    "field": "policy.keyword",
                    "size": 20,
                    "order": {"_count": "desc"}
                }
            }
        }
    })

    
    return res


def top_ipdst_drop(start_time, end_time):
    time_filter = time_to_filter(start_time, end_time)

    res = opensearch_client.search(index="*radwarevision*,*antiddos*", body={
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": time_filter}},
                    {"bool": {"must_not": {"term": {"action.keyword": "forward"}}}}
                ]
            }
        },
        "aggs": {
            "top_ipdst": {
                "terms": {
                    "field": "ipdst.keyword",
                    "size": 10,
                    "order": {"_count": "desc"}
                }
            }
        }
    })

    top_ipdst = res['aggregations']['top_ipdst']['buckets']
    return top_ipdst


def get_top_attack_sources(start, end, cidr=None, size=11):
    """Top attack source IPs (ipsrc.keyword) by document count over the
    DP index patterns (*radwarevision*, *antiddos*), filtered to drop
    actions only. Optionally filtered to a destination CIDR
    (ipdst within `cidr`) when `cidr` is provided.

    Replaces reports_pdf_alt._fetch_top_sources (cidr=None) and
    search_interactive._fetch_top_sources_for_cidr (cidr set). Returns a
    list of {'key','doc_count'} buckets."""
    time_filter = {"range": {"@timestamp": time_to_filter(start, end)}}

    query_filter = [
        time_filter,
        {"bool": {"must_not": {"term": {"action.keyword": "forward"}}}},
    ]
    if cidr is not None:
        query_filter.append(cidr_to_filter(cidr, 'ipdst'))

    res = opensearch_client.search(index="*radwarevision*,*antiddos*", body={
        "size": 0,
        "query": {
            "bool": {
                "filter": query_filter
            }
        },
        "aggs": {
            "top_ipsrc": {
                "terms": {
                    "field": "ipsrc.keyword",
                    "size": size,
                    "order": {"_count": "desc"}
                }
            }
        }
    })

    return res['aggregations']['top_ipsrc']['buckets']


def has_dp_drops(dst_cidr, start_time, end_time):
    """Lightweight existence check (Option A): returns True if ANY drop-action
    document exists for the CIDR in [start_time, end_time].

    Uses size:0 + a filter aggregation (no hit collection, no terms agg, no
    sum sub-agg). Intended for update_alerts_levels where only a Yes/No is
    needed. NOTE: unlike get_dp_data, this does NOT sum packet_count — a doc
    with packet_count=0 or null still counts as a drop existing.
    """
    dst_net_query_filter = cidr_to_filter(dst_cidr)
    time_filter = time_to_filter(start_time, end_time)

    res = opensearch_client.search(index="*radwarevision*,*antiddos*", body={
        "size": 0,
        "track_total_hits": False,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": time_filter}},
                    dst_net_query_filter
                ]
            }
        },
        "aggs": {
            "drops": {
                "filter": {"bool": {"must_not": {"term": {"action.keyword": "forward"}}}}
            }
        }
    })
    return res['aggregations']['drops']['doc_count'] > 0


def get_dp_drop_packets(dst_cidr, start_time, end_time):
    """Sum of dropped packet_count over the window (DP index).

    Like has_dp_drops but returns the actual packet total instead of a
    boolean, so update_alerts_levels can compute a drop/anomaly-pps ratio for
    the level (LEVEL). Returns 0 when there are no drop docs.
    """
    dst_net_query_filter = cidr_to_filter(dst_cidr)
    time_filter = time_to_filter(start_time, end_time)

    res = opensearch_client.search(index="*radwarevision*,*antiddos*", body={
        "size": 0,
        "track_total_hits": False,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": time_filter}},
                    dst_net_query_filter
                ]
            }
        },
        "aggs": {
            "drops": {
                "filter": {"bool": {"must_not": {"term": {"action.keyword": "forward"}}}},
                "aggs": {
                    "drop_packets": {"sum": {"field": "packet_count"}}
                }
            }
        }
    })
    val = res['aggregations']['drops']['drop_packets']['value']
    return int(val) if val else 0


##############################################################################
################################   WAF   ######################################
##############################################################################

def get_waf_data(dst_cidr, start_time, end_time, timeout=30):
    dst_net_query_filter = cidr_to_filter(dst_cidr)
    time_filter = time_to_filter(start_time, end_time)

    res1 = opensearch_client.search(index="*ru.solidwaf*", timeout=timeout, body=
        {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                {"range": {"@timestamp": time_filter}},
                    dst_net_query_filter
                ]
            }
        },
        "_source": ["method", "path", "decision", "geoip.country_name", "os", "app"]
    }
    )

    res2 = opensearch_client.search(index="*ingress-waf*", timeout=timeout, body=
        {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                {"range": {"@timestamp": time_filter}},
                    dst_net_query_filter
                ]
            }
        },
        "aggs": {
            "by_source_ip": {
                "terms": {"field": "message.keyword", "size": 10}
            }
        }
    }
    )

    return [res1, res2]


def waf_top_ips_by_fail():
    res = opensearch_client.search(index="*crq453121-ru.solidwaf*,*ingress_waf*", body=
        {
        "size": 0,
        "query": {
            "bool": {
            "filter": [
                {"range": {"@timestamp": {"gte": "now-1h", "lte": "now"}}},
                {"term": {"decision.keyword": "Block"}}
            ]
            }
        },
        "aggs": {
            "top_client_ips": {
            "terms": {
                "field": "client_ip.keyword",
                "size": 10,
                "order": {"_count": "desc"}
            }
            }
        }
        }
    )
    ret = res['aggregations']['top_client_ips']['buckets']

    return ret


def waf_blocks_by_net(dst_cidr, start_time, end_time, timeout=30):
    dst_net_query_filter = cidr_to_filter(dst_cidr, "client_ip")
    time_filter = time_to_filter(start_time, end_time)

    res = opensearch_client.search(index="*ru.solidwaf*", timeout=timeout, body=
        {
            "size": 0,
            "query": {
                "bool": {
                "filter": [
                    {"range": {"@timestamp": time_filter}},
                    dst_net_query_filter
                ]
                }
            },
            "aggs": {
                "pass_block": {
                "terms": {
                    "field": "decision.keyword",
                }
                }
            }
        }
    )
    return res


def has_waf_blocks(dst_cidr, start_time, end_time, timeout=60):
    """Lightweight existence check (Option A): returns True if ANY
    decision=Block document exists for the CIDR in [start_time, end_time].

    Uses size:0 + a filter aggregation (no hit collection, no terms agg).
    Intended for update_alerts_levels where only a Yes/No is needed.
    """
    dst_net_query_filter = cidr_to_filter(dst_cidr, "client_ip")
    time_filter = time_to_filter(start_time, end_time)

    res = opensearch_client.search(index="*ru.solidwaf*", timeout=timeout, body={
        "size": 0,
        "track_total_hits": False,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": time_filter}},
                    dst_net_query_filter
                ]
            }
        },
        "aggs": {
            "blocks": {
                "filter": {"term": {"decision.keyword": "Block"}}
            }
        }
    })
    return res['aggregations']['blocks']['doc_count'] > 0


def get_waf_blocks_count(dst_cidr, start_time, end_time, timeout=60):
    """doc_count of decision=Block documents over the window (WAF index).

    Like has_waf_blocks but returns the actual count, used by
    update_alerts_levels to build the WAF informational note (block count +
    approx rps) that accompanies LEVEL without affecting prioritization.
    """
    dst_net_query_filter = cidr_to_filter(dst_cidr, "client_ip")
    time_filter = time_to_filter(start_time, end_time)

    res = opensearch_client.search(index="*ru.solidwaf*", timeout=timeout, body={
        "size": 0,
        "track_total_hits": False,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": time_filter}},
                    dst_net_query_filter
                ]
            }
        },
        "aggs": {
            "blocks": {
                "filter": {"term": {"decision.keyword": "Block"}}
            }
        }
    })
    return int(res['aggregations']['blocks']['doc_count'] or 0)


##############################################################################
#                      DP / WAF time-series helpers                          #
# Used by alert_center/views/alert_interactive.py to render the              #
# before/during/after histograms on the alert-detail page.                  #
##############################################################################

# OpenSearch date_histogram bucket keys are epoch-ms in UTC (they come from
# the @timestamp field, which is stored in UTC). The UI plots them with
# pd.to_datetime(key, unit='ms') which yields a naive UTC datetime, while
# _alert_phase_shapes uses naive Moscow-local datetimes from SQLite. Shifting
# the bucket key by +03:00 aligns the bars with the alert-phase band and
# makes the x-axis tick labels read Moscow local time.
_MOSCOW_OFFSET_MS = 3 * 3600 * 1000


def _epoch_ms(time_str):
    """Parse a 'YYYY-MM-DD HH:MM:SS' (or ISO) string to epoch milliseconds."""
    return int(pd.to_datetime(time_str).timestamp() * 1000)


def get_dp_drops_timeseries(dst_cidr, start_time, end_time, interval="1m", reason_size=5):
    """DP (Radware/AntiDDoS) non-forward packet counts bucketed over time,
    with a per-action (drop / challenge) → per-reason (description.keyword)
    breakdown so the histogram can be stacked by action+reason like the WAF
    decisions graph.

    Returns a list of dicts, one per bucket:
        {
            "key": <epoch_ms>,
            "doc_count": <int>,
            "packets": <int>,                  # total non-forward packets
            "actions": [                        # per-action breakdown
                {
                    "key": "<action>",          # e.g. "drop", "challenge"
                    "packets": <int>,           # total packets for this action
                    "buckets": [                # top-N reasons for this action
                        {"key": "<desc>", "packets": <int>, "doc_count": <int>},
                        ...
                    ],
                }, ...
            ],
        }

    Buckets with no documents are still returned (min_doc_count=0) so the
    x-axis on the histogram stays continuous. `extended_bounds` forces the
    full queried [start_time, end_time] window to be materialized — without
    it OpenSearch clamps the outer buckets to the first/last actual document,
    which yields only as many buckets as there is data (e.g. 2-3 for a 3h
    alert).

    `reason_size` caps the per-action terms aggregation on description.keyword
    (default 5 — top 5 reasons per action, remainder folded into "Other" by
    the caller).
    """
    dst_net_query_filter = cidr_to_filter(dst_cidr)
    time_filter = time_to_filter(start_time, end_time)

    res = opensearch_client.search(index="*radwarevision*,*antiddos*", body={
        "size": 0,
        "track_total_hits": False,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": time_filter}},
                    dst_net_query_filter,
                    {"bool": {"must_not": {"term": {"action.keyword": "forward"}}}},
                ]
            }
        },
        "aggs": {
            "drops_ts": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {
                        "min": _epoch_ms(start_time),
                        "max": _epoch_ms(end_time),
                    },
                },
                "aggs": {
                    "pkt_sum": {
                        "sum": {"field": "packet_count"}
                    },
                    "by_action": {
                        "terms": {
                            "field": "action.keyword",
                            "order": {"pkt_sum": "desc"},
                        },
                        "aggs": {
                            "pkt_sum": {
                                "sum": {"field": "packet_count"}
                            },
                            "by_reason": {
                                "terms": {
                                    "field": "description.keyword",
                                    "size": reason_size,
                                    "order": {"pkt_sum": "desc"},
                                },
                                "aggs": {
                                    "pkt_sum": {
                                        "sum": {"field": "packet_count"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    })

    out = []
    for b in res['aggregations']['drops_ts']['buckets']:
        actions = []
        for ab in b.get('by_action', {}).get('buckets', []):
            reasons = []
            for sb in ab.get('by_reason', {}).get('buckets', []):
                pkt = sb.get('pkt_sum', {}).get('value')
                reasons.append({
                    "key": sb['key'],
                    "packets": int(pkt) if pkt else 0,
                    "doc_count": sb.get('doc_count', 0),
                })
            apkt = ab.get('pkt_sum', {}).get('value')
            actions.append({
                "key": ab['key'],
                "packets": int(apkt) if apkt else 0,
                "buckets": reasons,
            })
        out.append({
            "key": b['key'] + _MOSCOW_OFFSET_MS,
            "doc_count": b.get('doc_count', 0),
            "packets": int(b['pkt_sum']['value']) if b['pkt_sum'].get('value') else 0,
            "actions": actions,
        })
    return out


def get_waf_decisions_timeseries(dst_cidr, start_time, end_time, interval="1m"):
    """WAF (ru.solidwaf) decision counts bucketed over time.

    Returns a list of dicts, one per bucket:
        {"key": <epoch_ms>, "buckets": [{"key": "Pass", "doc_count": N}, ...]}

    Each bucket carries a per-decision breakdown so the histogram can be
    stacked (Pass / Block). Buckets with no documents are still returned.
    `extended_bounds` is set so the full queried window is materialized even
    when matching docs only span a subset of it — otherwise OpenSearch clamps
    the histogram to the first/last actual document and the chart shows fewer
    buckets than expected.
    """
    dst_net_query_filter = cidr_to_filter(dst_cidr, "client_ip")
    time_filter = time_to_filter(start_time, end_time)

    res = opensearch_client.search(index="*ru.solidwaf*", timeout=60, body={
        "size": 0,
        "track_total_hits": False,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"@timestamp": time_filter}},
                    dst_net_query_filter,
                ]
            }
        },
        "aggs": {
            "decisions_ts": {
                "date_histogram": {
                    "field": "@timestamp",
                    "fixed_interval": interval,
                    "min_doc_count": 0,
                    "extended_bounds": {
                        "min": _epoch_ms(start_time),
                        "max": _epoch_ms(end_time),
                    },
                },
                "aggs": {
                    "by_decision": {
                        "terms": {"field": "decision.keyword"}
                    }
                }
            }
        }
    })

    out = []
    for b in res['aggregations']['decisions_ts']['buckets']:
        out.append({
            "key": b['key'] + _MOSCOW_OFFSET_MS,
            "buckets": [
                {"key": sb['key'], "doc_count": sb['doc_count']}
                for sb in b['by_decision']['buckets']
            ],
        })
    return out

