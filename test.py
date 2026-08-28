import os
import configparser
from datetime import datetime, timedelta

import clickhouse_connect
import pandas as pd


def get_last_thursday_at_9am():
    """Most recent Thursday 09:00 (local). If today is Thursday and the
    clock has passed 09:00, returns today 09:00; otherwise the previous
    Thursday. Matches services/utils.py::get_last_thursday_at_9am."""
    now = datetime.now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    days_since_thursday = (today.weekday() - 3) % 7
    if days_since_thursday == 0 and now.hour >= 9:
        delta_days = 0
    else:
        delta_days = days_since_thursday
    last_thursday = today - timedelta(days=delta_days)
    return last_thursday.replace(hour=9, minute=0, second=0, microsecond=0)


config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'alert_center.conf'))

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


unique_id_condition = '''
(ID, UPDATE_TIME) IN (
    SELECT ID, MAX(UPDATE_TIME) as UPDATE_TIME
    FROM genie_events
    GROUP BY ID
)
'''


def time_filter_sql(start_iso=None, end_iso=None):
    if start_iso and end_iso:
        return f" ( START_TIME >= toDateTime('{start_iso}') AND START_TIME <= toDateTime('{end_iso}') ) \
               OR ( END_TIME >= toDateTime('{start_iso}')   AND END_TIME <= toDateTime('{end_iso}')   ) "
    elif start_iso:
        return f"START_TIME >= toDateTime('{start_iso}') OR END_TIME >= toDateTime('{start_iso}') OR END_TIME IS NULL"
    elif end_iso:
        return f"START_TIME <= toDateTime('{end_iso}') OR  END_TIME <= toDateTime('{end_iso}')"


def get_fttb_events(start_iso, end_iso=None):
    """Count genie_events whose RESOURCE array contains 'FTTB' or 'PSCORE'.

    Mirrors the fttb_query block inside services/data_fetcher.py::get_b2b_summary.
    Returns the integer count.
    """
    time_filter = time_filter_sql(start_iso, end_iso)
    base_conditions = f"({time_filter}) AND {unique_id_condition}"

    fttb_condition = """
        arrayExists(x -> position(x, 'FTTB') > 0 OR position(x, 'PSCORE') > 0, RESOURCE)
    """
    fttb_query = f"""
        SELECT COUNT(*) FROM genie_events WHERE {base_conditions} AND ({fttb_condition})
    """
    return clickhouse_client.query(fttb_query).result_rows[0][0]


def get_fttb_event_ids(start_iso, end_iso=None):
    """Return a DataFrame of (ID, START_TIME, END_TIME, RESOURCE) for all
    FTTB/PSCORE events in the window. Mirrors the fttb_query filter but
    selects rows instead of counting them."""
    time_filter = time_filter_sql(start_iso, end_iso)
    base_conditions = f"({time_filter}) AND {unique_id_condition}"

    fttb_condition = """
        arrayExists(x -> position(x, 'FTTB') > 0 OR position(x, 'PSCORE') > 0, RESOURCE)
    """
    query = f"""
        SELECT ID, START_TIME, END_TIME, RESOURCE
        FROM genie_events
        WHERE {base_conditions} AND ({fttb_condition})
        ORDER BY START_TIME DESC
    """
    rows = clickhouse_client.query(query).result_rows
    return pd.DataFrame(rows, columns=['id', 'start_time', 'end_time', 'resource'])


def verify_fttb_count(start_iso, end_iso=None):
    """Cross-check the original COUNT(*) query against a COUNT(DISTINCT ID).

    The original get_fttb_events relies on unique_id_condition to dedupe
    ReplacingMergeTree rows (one row per ID, latest UPDATE_TIME). If the
    dedup works, COUNT(*) == COUNT(DISTINCT ID). We also compute a raw
    COUNT(*) WITHOUT unique_id_condition to show the pre-dedup row count.

    Returns a dict with keys: 'count_star_dedup', 'count_distinct_id',
    'count_star_raw', 'matches'.
    """
    time_filter = time_filter_sql(start_iso, end_iso)
    fttb_condition = """
        arrayExists(x -> position(x, 'FTTB') > 0 OR position(x, 'PSCORE') > 0, RESOURCE)
    """

    star_dedup_q = f"""
        SELECT COUNT(*) FROM genie_events
        WHERE ({time_filter}) AND {unique_id_condition} AND ({fttb_condition})
    """
    distinct_q = f"""
        SELECT COUNT(DISTINCT ID) FROM genie_events
        WHERE ({time_filter}) AND {unique_id_condition} AND ({fttb_condition})
    """
    raw_q = f"""
        SELECT COUNT(*) FROM genie_events
        WHERE ({time_filter}) AND ({fttb_condition})
    """

    star_dedup = clickhouse_client.query(star_dedup_q).result_rows[0][0]
    distinct = clickhouse_client.query(distinct_q).result_rows[0][0]
    raw = clickhouse_client.query(raw_q).result_rows[0][0]

    return {
        'count_star_dedup': star_dedup,
        'count_distinct_id': distinct,
        'count_star_raw': raw,
        'matches': star_dedup == distinct,
    }


if __name__ == '__main__':
    # Default window: last Thursday 09:00 -> this Thursday 09:00
    end = get_last_thursday_at_9am()
    start = end - timedelta(days=7)
    count = get_fttb_events(start.isoformat(), end.isoformat())
    print(f"FTTB events {start.isoformat()} -> {end.isoformat()}: {count}")

    prev_w_start = start - timedelta(days=7)
    prev_w_count = get_fttb_events(prev_w_start.isoformat(), start.isoformat())
    print(f"lw FTTB events {prev_w_start.isoformat()} -> {start.isoformat()}: {prev_w_count}")

    # Verify the original count actually reflects unique IDs
    v = verify_fttb_count(start.isoformat(), end.isoformat())
    print("\n--- uniqueness verification ---")
    print(f"  COUNT(*)          (dedup): {v['count_star_dedup']}")
    print(f"  COUNT(DISTINCT ID) (dedup): {v['count_distinct_id']}")
    print(f"  COUNT(*)          (raw)  : {v['count_star_raw']}")
    print(f"  unique_ids == original count? {v['matches']}")

    df = get_fttb_event_ids(start.isoformat(), end.isoformat())
    if not df.empty:
        df['resource'] = df['resource'].apply(lambda arr: ', '.join(arr) if arr else '')
        print(f"\nFTTB event IDs (showing first 5 of {len(df)}):")
        with pd.option_context('display.max_colwidth', None, 'display.width', None):
            print(df.head(5).to_string(index=False))

        out_path = os.path.join(os.path.dirname(__file__), 'fttb_event_ids.txt')
        with open(out_path, 'w') as f:
            f.write(f"FTTB events {start.isoformat()} -> {end.isoformat()}\n")
            f.write(f"Total: {len(df)}\n\n")
            with pd.option_context('display.max_rows', None, 'display.max_colwidth', None, 'display.width', None):
                f.write(df.to_string(index=False))
        print(f"\nFull table written to: {out_path}")
    else:
        print("\nNo FTTB events found.")

