'''
==== services/alert.py — rough outline ====

PURPOSE
  Merge raw Genie DDoS events (ClickHouse `genie_events`) with the existing
  de-duplicated alert table (SQLite `dbs/alerts.db`) so the UI sees one
  coherent alert per network/time window instead of many raw events.

DATA SOURCES
  - ClickHouse genie_events            : raw attack events (dedup via
    unique_id_condition = (ID, MAX(UPDATE_TIME)) per ID)
  - SQLite alerts table                : this module's own de-duplicated output
  - OpenSearch (services/data_fetcher) : DP drops + WAF blocks for levels

CORE FUNCTIONS
  get_genie_recent_update(start, end)
      Pull latest-only Genie rows in a time window from ClickHouse.

  merge_nets_times(dataset, merge_into=None)
      Heart of the dedup. Two passes:
        1) Merge overlapping/adjacent IPv4 ranges into parent nets.
        2) Sort by start time; collapse overlapping time intervals per net
           into single alert records. UID conflicts -> keep smaller UID,
           remove larger. Returns (collapsed_df, uids_to_remove).

  fill_alerts(start, end)
      Pull fresh Genie rows, merge with existing still-relevant alerts
      (END_TIME >= start OR END_TIME IS NULL), persist back to SQLite
      (INSERT new UID=-1 rows, UPDATE existing UIDs, DELETE superseded UIDs).
      Timing: called once per ~60s pipeline pass (1-day window; 3-day window at startup).

  update_alerts()
      For every ongoing alert (END_TIME IS NULL): re-query ClickHouse for
      matching Genie events, refresh CURRENT_MAX_BPS / CURRENT_MAX_PPS /
      MAX_BPS / MAX_PPS / CURRENT_RESOURCES / CURRENT_GENIE_EVENTS.
      If no Genie event is still ongoing -> set END_TIME, zero current
      counters (alert closed).
      Timing: called once per ~60s pipeline pass, right after fill_alerts().

  LEVEL — single severity tier computed from OpenSearch DP-drops +
  bps-volume (>= 1 Gbps threshold). WAF blocks are recorded separately as
  WAF_BLOCKS and do NOT feed into LEVEL:
        LEVEL : 1 (highest: DP>=10k AND bps>=1G) / 2 (either) / 3 (neither).
                0 = unassigned on first compute; then monotonic toward
                severity via min(old,new). Locked via LEVEL_LOCKED when alert ends.

  update_alerts_levels(batch_size=10)
      Ongoing alerts only. Recomputes LEVEL over [START_TIME, now] every pass,
      merging monotonically. Also stores WAF_BLOCKS / DP_BLOCKS.
      Timing: called once per ~60s pipeline pass, right after update_alerts().

  update_old_alerts_levels(ended_limit, batch_size)
      Ended alerts only whose LEVEL_LOCKED = 0. One-shot compute over the
      fixed [START,END] window, then sets LEVEL_LOCKED = 1.
      Timing: called every ~5s by the daemon process (run_level_update),
              up to ended_limit=20 alerts per pass.

  update_old_alerts_bps(ended_limit)
      Ended alerts only whose BPS_LOCKED = 0. One-shot MAX_BPS refresh over
      the fixed [START,END] window using ALL matching Genie events
      (ongoing + ended), then sets BPS_LOCKED = 1. Closes the gap left by
      update_alerts() which only folds ongoing Genie events into MAX_BPS.
      Timing: called every ~5s by the daemon process (run_level_update),
              right after update_old_alerts_levels.

  recreate_alerts_db() / migrate_alerts_add_*()
      Schema bootstrap + idempotent column migrations.

LIVE LOOP  (when run as __main__ — `python -m services.alert`)
  - Spawns a daemon process running run_level_update():
        update_old_alerts_levels() every LOOP_INTERVAL_SECONDS = 5s
        (ENDED_LIMIT=20 ended alerts per pass).
  - Main process _run_pipeline():
        startup : fill_alerts(3d) -> update_alerts -> update_alerts_levels
        loop    : fill_alerts(1d) -> update_alerts -> update_alerts_levels
                  then sleep 60s, repeat forever.
'''




import pandas as pd
import clickhouse_connect
import json
import configparser
import os
import ipaddress
import sqlite3

import time
import traceback
import multiprocessing


config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'alert_center.conf'))

ALERTS_DB_PATH = config.get('DATABASE_PATHS', 'ALERTS_DB_PATH')

CLICKHOUSE_HOST = config.get('CLICKHOUSE', 'HOST')
CLICKHOUSE_PORT = config.getint('CLICKHOUSE', 'PORT')
CLICKHOUSE_USER = config.get('CLICKHOUSE', 'USER')
CLICKHOUSE_DATABASE = config.get('CLICKHOUSE', 'DATABASE')

ALERT_CENTER_BOT_TOKEN = config.get('BUZZ_API', 'ALERT_CENTER_BOT_TOKEN')
TEST_CHAT_ID = config.get('BUZZ_API', 'TEST_CHAT_ID')

clickhouse_client = clickhouse_connect.get_client(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, user=CLICKHOUSE_USER, database=CLICKHOUSE_DATABASE)

def _normalize_net_broadcast(target_network, target_broadcast):
    """A /32 ending in .0 (network==broadcast) is actually a /24 in disguise."""
    if target_network == target_broadcast and str(target_network).endswith('.0'):
        octets = str(target_network).split('.')
        return target_network, '.'.join(octets[:3] + ['255'])
    return target_network, target_broadcast

def time_filter_recent_updates_sql(start_iso=None, end_iso=None):
    '''if start_iso and end_iso:
        return f"UPDATE_TIME >= toDateTime('{start_iso}') AND UPDATE_TIME <= toDateTime('{end_iso}')"
    elif start_iso:
        return f"UPDATE_TIME >= toDateTime('{start_iso}')"
    elif end_iso:
        return f"UPDATE_TIME <= toDateTime('{end_iso}')" 
    '''
    # START_TIME, END_TIME instead 
    if start_iso and end_iso:
        return f"START_TIME >= toDateTime('{start_iso}') AND END_TIME <= toDateTime('{end_iso}')"
    elif start_iso:
        return f"START_TIME >= toDateTime('{start_iso}')"
    elif end_iso:
        return f"END_TIME <= toDateTime('{end_iso}')"#'''
    
    
def q_result_to_df(q):
    rows = clickhouse_client.query(q).result_rows
    if not rows:
        return pd.DataFrame()
    cols = [c[0] for c in clickhouse_client.query(q).columns] 
    return pd.DataFrame(rows, columns=cols)

unique_id_condition = '''
(ID, UPDATE_TIME) IN (
    SELECT ID, MAX(UPDATE_TIME) as UPDATE_TIME
    FROM genie_events
    GROUP BY ID
)
'''
def get_genie_recent_update(start_update_time, end_update_time):
    tf = time_filter_recent_updates_sql(start_update_time, end_update_time)

    genie_rows = clickhouse_client.query(f"""
    SELECT ID, STATUS, UPDATE_TIME, START_TIME, END_TIME, MAX_BPS, MAX_PPS, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST
    FROM genie_events
    WHERE {tf} AND {unique_id_condition}      AND STATUS != 'Obsolete'
    """).result_rows                 #  AND (STATUS = 'Ongoing' OR STATUS = 'Open' OR STATUS = 'New')

    df = pd.DataFrame(genie_rows, columns=['id', 'status', 'last_update', 'start', 'end', 'max_bps', 'max_pps', 'resource', 'target_network', 'target_broadcast'])
    df['target_network'], df['target_broadcast'] = zip(*df.apply(lambda r: _normalize_net_broadcast(r['target_network'], r['target_broadcast']), axis=1))
    return df


#####################

def make_naive(ts):
    if not ts or pd.isna(ts):
        return None
    dt = pd.to_datetime(ts).tz_localize(None)
    return dt

def normalize(dataset):
    normalized = []
    for curr in dataset:
        nr = curr.copy()
        nr.setdefault("end", None)
        normalized.append(nr)
    return normalized
def sort(dataset, net_first = True):
    if net_first:
        sorted_data = sorted(dataset, key=lambda curr: (
            curr["target_network"],
            curr["target_broadcast"],
            curr["start"],
            curr.get("end") or pd.Timestamp.max
        ))
    else:
        sorted_data = sorted(dataset, key=lambda curr: (
            curr["start"],
            curr.get("end") or pd.Timestamp.max,
            curr["target_network"],
            curr["target_broadcast"]
        ))
    return sorted_data 

def overlaps(start_end1, start_end2):
    start1, end1 = start_end1
    start2, end2 = start_end2
    return not (end1 < start2 or end2 < start1)

def find_parent_net(net, merged_nets):
    for curr in merged_nets:
        if overlaps((curr["target_network"], curr["target_broadcast"]), (net["target_network"], net["target_broadcast"])):
            return (curr["target_network"], curr["target_broadcast"]) 
            # same as min-max, since merged_nets merged net ranges
            #return (min(curr["target_network"], net["target_network"]),
            #        max(curr["target_broadcast"], net["target_broadcast"]))
    return (net["target_network"], net["target_broadcast"])


def merge_nets_times(dataset, merge_into=None):
    normalized_data = []

    if merge_into:
        for curr in merge_into:
            nr = curr.copy()
            nr.setdefault("end", None)
            nr['start'] = make_naive(nr['start'])
            nr['end'] = make_naive(nr['end'])# if pd.notna(nr['end']) else make_naive(pd.Timestamp.max)
            nr["_source"] = "db"
            normalized_data.append(nr)

    for curr in dataset:
        nr = curr.copy()
        nr.setdefault("end", None)
        nr['start'] = make_naive(nr['start'])
        nr['end'] = make_naive(nr['end'])# if pd.notna(nr['end']) else make_naive(pd.Timestamp.max)
        nr["_source"] = "genie"
        normalized_data.append(nr)

    sorted_data_by_net = sorted(normalized_data, key=lambda x: (
        x["target_network"]#, x["target_broadcast"] 
        #x["start"], (x.get("end") if pd.notna(x.get("end")) else pd.Timestamp.max)# or pd.Timestamp.max
    ))

    merged_nets = [{
        "target_network": sorted_data_by_net[0]["target_network"],
        "target_broadcast": sorted_data_by_net[0]["target_broadcast"]
    }]
    merging_nets_counter = 0
    for curr in sorted_data_by_net[1:]:
        last = merged_nets[-1]
        if curr["target_network"] <= last["target_broadcast"]:
            merging_nets_counter += 1
            last["target_broadcast"] = max(last["target_broadcast"], curr["target_broadcast"])
        else:
            merged_nets.append({
                "target_network": curr["target_network"],
                "target_broadcast": curr["target_broadcast"]
            })
    print(f"merging_nets_counter {merging_nets_counter} times. Final merged_nets: {len(merged_nets)}")


    merge_counter = 0

    sorted_data_by_time = sorted(normalized_data, key=lambda x: (
        x["start"], 
        (-x.get("end").value if pd.notna(x.get("end")) else -pd.Timestamp.max.value),
        #(x.get("end") if pd.notna(x.get("end")) else pd.Timestamp.max),
        #x["target_network"], x["target_broadcast"]
    ))
    # TODO: maybe sort end None first
    
    
    #################################################
    #################################################    DEBUG
    #################################################
    '''for i in range(len(sorted_data_by_time) - 1):
        curr, next_item = sorted_data_by_time[i], sorted_data_by_time[i + 1]
        assert curr["start"] <= next_item["start"], f"Start time out of order: {curr['start']} > {next_item['start']}"
        if curr["start"] == next_item["start"]:
            curr_end = pd.Timestamp.max if curr["end"] is None else curr["end"]
            next_end = pd.Timestamp.max if next_item["end"] is None else next_item["end"]
            assert curr_end >= next_end, f"End time out of order: {curr['end']} < {next_item['end']}"
    print("Sort validation passed: Data is correctly sorted by start and end times.")#'''
    #################################################
    #################################################    DEBUG
    #################################################
    
    
    merged_dict = {}  # { (net,bro):[{'start':s,'end':e,'uid':uid}, {}...]  ... }
    uids_to_remove = []
    # TODO: is Ending when was current managed?
    for curr in sorted_data_by_time:
        net_obj = find_parent_net(curr, merged_nets)
        #curr["target_network"],  curr["target_broadcast"] = net_obj
        
        # if end before start, end=start
        if curr['end'] and pd.notna(curr['end']) and curr['start']>curr['end']:
            curr['end'] = curr['start']
        
            
        if net_obj in merged_dict:
            merge_counter += 1

            # if last[end] is None     and      curr[start] >= last[start]  (assumed bc sorted)
            if merged_dict[net_obj][-1]['end'] is None or pd.isna(merged_dict[net_obj][-1]['end']):
                ### UID conflict
                if int(merged_dict[net_obj][-1]['uid']) != -1 and int(curr['uid']) != -1 and \
                    int(merged_dict[net_obj][-1]['uid']) != int(curr['uid']):
                    print(f"UID conflict: {merged_dict[net_obj][-1]['uid']} != {curr['uid']}\n {merged_dict[net_obj][-1]}\n {curr}\n---------")    
                    uids_to_remove.append(max(merged_dict[net_obj][-1]['uid'], curr['uid']))
                    merged_dict[net_obj][-1]['uid'] = min(merged_dict[net_obj][-1]['uid'], curr['uid'])
                else:
                    merged_dict[net_obj][-1]['uid'] = max(merged_dict[net_obj][-1]['uid'], curr['uid'])
                ###
                merged_dict[net_obj][-1]['level'] = max(merged_dict[net_obj][-1].get('level', 0), curr.get('level', 0))
                
                continue # later start for current alert; can ignore
        
            # if last[end] is not None  and   current intersects with last
            elif curr['start'] <= merged_dict[net_obj][-1]['end']:
                
                ### UID conflict
                if int(merged_dict[net_obj][-1]['uid']) != -1 and int(curr['uid']) != -1 and \
                    int(merged_dict[net_obj][-1]['uid']) != int(curr['uid']):
                    print(f"UID conflict2: {merged_dict[net_obj][-1]['uid']} != {curr['uid']}\n {merged_dict[net_obj][-1]}\n {curr}\n---------")    
                    uids_to_remove.append(max(merged_dict[net_obj][-1]['uid'], curr['uid']))
                    merged_dict[net_obj][-1]['uid'] = min(merged_dict[net_obj][-1]['uid'], curr['uid'])
                else:
                    merged_dict[net_obj][-1]['uid'] = max(merged_dict[net_obj][-1]['uid'], curr['uid'])
                ###
                
                if curr['end'] is None or pd.isna(curr['end']):
                    merged_dict[net_obj][-1]['end'] = None
                else:    
                    merged_dict[net_obj][-1]['end'] = max(merged_dict[net_obj][-1]['end'], curr['end'])
                merged_dict[net_obj][-1]['level'] = max(merged_dict[net_obj][-1].get('level', 0), curr.get('level', 0))
                    
            else:
                merged_dict[net_obj].append({"start":curr["start"], "end":curr["end"], 'uid':curr['uid'], 'level':curr.get('level', 0)})
        else:
            merged_dict[net_obj] = [{"start":curr["start"], "end":curr["end"], 'uid':curr['uid'], 'level':curr.get('level', 0)}]


    #################################################
    #################################################    DEBUG
    #################################################
    '''def verify_no_overlap_for_net(merged_dict):
        for net_obj, intervals in merged_dict.items():
            for i in range(1, len(intervals)):
                prev = intervals[i - 1]
                curr = intervals[i]
                
                # Handle unbounded end times (None or NaT)
                prev_end = pd.Timestamp.max if prev['end'] is None or pd.isna(prev['end']) else prev['end']
                curr_start = curr['start']
                
                if curr_start < prev_end:
                    return False, f"Overlap detected for net {net_obj}: " \
                                f"interval {i-1} ends at {prev['end']} but interval {i} starts at {curr_start}"
        return True, "No overlaps found for any net_obj."
    print(verify_no_overlap_for_net(merged_dict))
    
    for (net, bro), intervals in merged_dict.items():
        if str(ipaddress.IPv4Address(net)) == '66.90.90.0':
            print(f"Net: {ipaddress.IPv4Address(net)}; Bro: {ipaddress.IPv4Address(bro)}")
            for interval in intervals:
                print(f"Start: {interval['start']}; End: {interval['end']}; UID: {interval['uid']}")
            print("-------------------------------------------------------")#'''
    #################################################
    #################################################    DEBUG
    #################################################
    
    
    print(f"Merged: {len(merged_dict)} nets; \
Total: {sum(len(i) for i in merged_dict.values())} ranges/alerts; \
{merge_counter} merge_counter")
        
    # merged_dict: { (net,bro):[{'start':s,'end':e,'uid':uid}, {}...]  ... }
    # collapsed_df should be:  
    # { 'start': [s,s,s...], 'end': [e,e,e...], 'uid': [uid,uid,uid...], 
    #   'target_network': [n,n,n...], 'target_broadcast': [b,b,b...] }
    collapsed_list = []
    for (net, bro), intervals in merged_dict.items():
        for interval in intervals:
            # ## # TODO : Wrong ???? [{'start':1...}, {'start':2...}, ...]
            collapsed_list.append({
                'start': interval['start'],
                'end': interval['end'],
                'uid': interval.get('uid', -1),
                'level': interval.get('level', 0),
                'target_network': net,
                'target_broadcast': bro
            })
    collapsed_df = pd.DataFrame(collapsed_list)
    return collapsed_df, uids_to_remove




#####################

def _open_sqlite_conn(path):
    """Open a SQLite connection with WAL + sane busy_timeout so concurrent
    writers (main loop vs old_alerts_leveler process) wait instead of raising
    'database is locked'. WAL persists in the DB file header after first set."""
    conn = sqlite3.connect(path)
    conn.execute('PRAGMA journal_mode = WAL')
    conn.execute('PRAGMA synchronous = NORMAL')
    conn.execute('PRAGMA busy_timeout = 30000')
    return conn

sqlite_connection = _open_sqlite_conn(ALERTS_DB_PATH)

def reopen_sqlite_conn():
    global sqlite_connection
    try:
        sqlite_connection.commit()
        sqlite_connection.close()
    except: pass
    sqlite_connection = _open_sqlite_conn(ALERTS_DB_PATH)


def determine_prefix(row):
    start = row['target_network'].split('.')
    end = row['target_broadcast'].split('.')

    if start[0] == end[0]:
        if start[1] == end[1]:
            if start[2] == end[2]:
                if start[3] == end[3]:
                    return 32
                return 24
            return 16
        return 8
    return 1


'''def get_current_alerts(start=None, end=None):
    global sqlite_connection

    sqlite_cursor = sqlite_connection.cursor()
    def to_ts(time):
        return pd.to_datetime(time).strftime('%Y-%m-%d %H:%M:%S')

    if start and end:
        start = to_ts(start)
        end = to_ts(end)
        sqlite_cursor.execute('SELECT TARGET_NETWORK, TARGET_BROADCAST, START_TIME, END_TIME, UID FROM alerts WHERE ((START_TIME >= ? AND END_TIME <= ?) OR (END_TIME IS NULL)) ORDER BY START_TIME ASC', (start, end))
    elif start:
        start = to_ts(start)
        sqlite_cursor.execute('SELECT TARGET_NETWORK, TARGET_BROADCAST, START_TIME, END_TIME, UID FROM alerts WHERE ((START_TIME >= ?) OR (END_TIME IS NULL))  ORDER BY START_TIME ASC', (start,))
    elif end:
        end = to_ts(end)
        sqlite_cursor.execute('SELECT TARGET_NETWORK, TARGET_BROADCAST, START_TIME, END_TIME, UID FROM alerts WHERE ((END_TIME <= ?) OR (END_TIME IS NULL)) ORDER BY START_TIME ASC', (end,))
    else:
        sqlite_cursor.execute('SELECT TARGET_NETWORK, TARGET_BROADCAST, START_TIME, END_TIME, UID FROM alerts ORDER BY START_TIME ASC')
    
    return sqlite_cursor.fetchall()'''

def get_relevant_alerts(relevant_from):
    global sqlite_connection

    sqlite_cursor = sqlite_connection.cursor()
    def to_ts(time):
        return pd.to_datetime(time).strftime('%Y-%m-%d %H:%M:%S')

    start = to_ts(relevant_from)
    sqlite_cursor.execute('SELECT TARGET_NETWORK, TARGET_BROADCAST, START_TIME, END_TIME, UID, LEVEL FROM alerts WHERE ((END_TIME >= ?) OR (END_TIME IS NULL)) ORDER BY START_TIME ASC', (start,))

    return sqlite_cursor.fetchall()



def fill_alerts(start, end):
    global sqlite_connection
    reopen_sqlite_conn()    
    
    genie_df = get_genie_recent_update(start, end)
    if genie_df.empty:
        return    
    genie_df = genie_df[['target_network', 'target_broadcast', 'start', 'end']]
        
    genie_df = genie_df.sort_values('target_network')
    genie_df['target_network'] = genie_df['target_network'].apply(lambda x: int(ipaddress.IPv4Address(x)))
    genie_df['target_broadcast'] = genie_df['target_broadcast'].apply(lambda x: int(ipaddress.IPv4Address(x)))
    genie_df['uid'] = -1
    genie_df['level'] = 0
    genie_records = genie_df.to_dict('records')

    genie_df['start'] = genie_df['start'].apply(lambda x: make_naive(x))
    #genie_df['end'] = genie_df['end'].apply(lambda x: make_naive(x))
    genie_df['end'] = genie_df['end'].apply(lambda x: make_naive(x) if pd.notna(x) else None)


    print("--------------------\nStarting...")


    current_alerts = get_relevant_alerts(start)#get_current_alerts(start=start, end=end)
    if current_alerts and len(current_alerts) > 0:

        print(f"Found {len(current_alerts)} recent alerts. (From {start} to {end})")
        sqlite_cursor = sqlite_connection.cursor()
        sqlite_cursor.execute('SELECT COUNT(*) FROM alerts')
        total_alerts = sqlite_cursor.fetchone()[0]
        print(f"alerts table row count: {total_alerts}")
        
        current_alerts = pd.DataFrame(current_alerts, columns=['target_network', 'target_broadcast', 'start', 'end', 'uid', 'level'])
        current_alerts['target_network'], current_alerts['target_broadcast'] = zip(*current_alerts.apply(lambda r: _normalize_net_broadcast(r['target_network'], r['target_broadcast']), axis=1))
        current_alerts['target_network'] = current_alerts['target_network'].apply(lambda x: int(ipaddress.IPv4Address(x)))
        current_alerts['target_broadcast'] = current_alerts['target_broadcast'].apply(lambda x: int(ipaddress.IPv4Address(x)))
        current_alerts = current_alerts.to_dict('records')
    else:
        current_alerts = None
    
    print(f" Inserting {len(genie_records)} genie records ")
    if current_alerts and len(current_alerts) > 0:
        print(f"                                 into {len(current_alerts)} recent alerts ")
    
    alerts_df, uids_to_remove = merge_nets_times(genie_records, current_alerts)

    # capture integer representations before converting back to dotted-quad strings
    alerts_df['target_network_int'] = alerts_df['target_network']
    alerts_df['target_broadcast_int'] = alerts_df['target_broadcast']

    alerts_df['target_network'] = alerts_df['target_network'].apply(lambda x: str(ipaddress.IPv4Address(x)))
    alerts_df['target_broadcast'] = alerts_df['target_broadcast'].apply(lambda x: str(ipaddress.IPv4Address(x)))
    
    alerts_df['target_prefix'] = alerts_df.apply(determine_prefix, axis=1)
    alerts_df['target_cidr'] = alerts_df.apply(
        lambda row: str(ipaddress.IPv4Network(f"{ipaddress.IPv4Address(row['target_network'])}/{row['target_prefix']}", strict=False)),
        axis=1
    )

    alerts_df = alerts_df[['target_cidr', 'target_network', 'target_broadcast',
                           'target_network_int', 'target_broadcast_int',
                           'start', 'end', 'uid', 'level']]

    alerts_df = alerts_df.rename(columns={
        'target_cidr': 'TARGET_CIDR',
        'target_network': 'TARGET_NETWORK',
        'target_broadcast': 'TARGET_BROADCAST',
        'target_network_int': 'TARGET_NETWORK_INT',
        'target_broadcast_int': 'TARGET_BROADCAST_INT',
        'start': 'START_TIME',
        'end': 'END_TIME',
        'uid': 'UID',
        'level': 'LEVEL'
    })
    alerts_df['UPDATE_TIME'] = pd.to_datetime('now')#.strftime('%Y-%m-%d %H:%M:%S')
    alerts_df['UPDATE_TIME'] = alerts_df['UPDATE_TIME'].apply(lambda x: str(make_naive(x).strftime('%Y-%m-%d %H:%M:%S')))
    alerts_df['START_TIME'] = alerts_df['START_TIME'].astype(str)
    alerts_df['END_TIME'] = alerts_df['END_TIME'].apply(
        lambda x: x.strftime('%Y-%m-%d %H:%M:%S') if pd.notna(x) and x is not None and x != 'NaT' else None
    )
    
    

    #################################################
    #################################################    DEBUG
    #################################################
    '''duplicates = alerts_df[['TARGET_NETWORK', 'TARGET_BROADCAST', 'START_TIME', 'END_TIME', 'UID']]
    dup_start = duplicates[duplicates.duplicated(subset=['TARGET_NETWORK', 'TARGET_BROADCAST', 'START_TIME'], keep=False)]
    print(f"NET-BRO-START Duplicates found: {len(dup_start)} after merge:\n {dup_start.head(10)}")

    dup_end = duplicates[duplicates.duplicated(subset=['TARGET_NETWORK', 'TARGET_BROADCAST', 'END_TIME'], keep=False)]
    print(f"NET-BRO-END Duplicates found: {len(dup_end)} after merge:\n {dup_end.head(10)}")'''
    #################################################
    #################################################    DEBUG
    #################################################
    
    
    sqlite_cursor = sqlite_connection.cursor()

    for uid in uids_to_remove:
        sqlite_cursor.execute('DELETE FROM alerts WHERE UID = ?', (uid,))
    sqlite_connection.commit()


    for _, row in alerts_df.iterrows():
        if row['UID'] == -1:        
            sqlite_cursor.execute('''
                INSERT INTO alerts 
                (TARGET_CIDR, TARGET_NETWORK, TARGET_BROADCAST,
                 TARGET_NETWORK_INT, TARGET_BROADCAST_INT,
                 START_TIME, END_TIME, UPDATE_TIME)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                row['TARGET_CIDR'],
                row['TARGET_NETWORK'],
                row['TARGET_BROADCAST'],
                int(row['TARGET_NETWORK_INT']) if pd.notna(row['TARGET_NETWORK_INT']) else None,
                int(row['TARGET_BROADCAST_INT']) if pd.notna(row['TARGET_BROADCAST_INT']) else None,
                row['START_TIME'],
                row['END_TIME'],
                row['UPDATE_TIME']))
        else:
            sqlite_cursor.execute('''
                UPDATE alerts
                SET
                    TARGET_CIDR = ?,
                    TARGET_NETWORK = ?,
                    TARGET_BROADCAST = ?,
                    TARGET_NETWORK_INT = ?,
                    TARGET_BROADCAST_INT = ?,
                    START_TIME = ?,
                    END_TIME = ?,
                    UPDATE_TIME = ?
                WHERE UID = ?
            ''', (
                row['TARGET_CIDR'],
                row['TARGET_NETWORK'],
                row['TARGET_BROADCAST'],
                int(row['TARGET_NETWORK_INT']) if pd.notna(row['TARGET_NETWORK_INT']) else None,
                int(row['TARGET_BROADCAST_INT']) if pd.notna(row['TARGET_BROADCAST_INT']) else None,
                row['START_TIME'],
                row['END_TIME'],
                row['UPDATE_TIME'],
                row['UID']
            ))

    sqlite_connection.commit()

    sqlite_cursor.execute('SELECT COUNT(*) FROM alerts')
    total = sqlite_cursor.fetchone()[0]
    sqlite_cursor.execute('SELECT COUNT(*), COUNT(DISTINCT UID) FROM alerts')
    distinct = sqlite_cursor.fetchone()
    print(f"alerts table row count: {total}, alert table distinct UIDs: {distinct}")
    
    sqlite_connection.close()
    #clickhouse_client.insert_df('alert_center.alerts', alerts_df)



def update_alerts():
    '''
    End alerts and update data.

    Single batched ClickHouse query (was: one query per ongoing alert) —
    the unique_id_condition subquery is now evaluated once per pass instead
    of N times, and all Genie events since the earliest ongoing alert's
    START_TIME are fetched in one round-trip. Network-range containment and
    per-alert start-time filtering are then done in Python. SQLite UPDATEs
    are flushed in a single BEGIN IMMEDIATE transaction.
    '''
    global sqlite_connection
    reopen_sqlite_conn()
    sqlite_cursor = sqlite_connection.cursor()

    sqlite_cursor.execute('''
        SELECT UID, TARGET_CIDR, TARGET_NETWORK, TARGET_BROADCAST, START_TIME,
               CURRENT_MAX_BPS, CURRENT_MAX_PPS
        FROM alerts
        WHERE END_TIME IS NULL
        ORDER BY START_TIME ASC
    ''')
    rows = sqlite_cursor.fetchall()
    col_names = [d[0] for d in sqlite_cursor.description]

    if not rows:
        sqlite_cursor.close()
        sqlite_connection.close()
        return

    alerts = []
    for row in rows:
        alert = dict(zip(col_names, row))
        target_network, target_broadcast = _normalize_net_broadcast(
            alert['TARGET_NETWORK'], alert['TARGET_BROADCAST'])
        alert['TARGET_NETWORK'] = target_network
        alert['TARGET_BROADCAST'] = target_broadcast
        alert['TARGET_NETWORK_INT'] = int(ipaddress.IPv4Address(target_network))
        alert['TARGET_BROADCAST_INT'] = int(ipaddress.IPv4Address(target_broadcast))
        alert['START_TS'] = pd.to_datetime(alert['START_TIME']).strftime("%Y-%m-%d %H:%M:%S")
        alert['START_PD'] = pd.to_datetime(alert['START_TIME'])
        alerts.append(alert)

    earliest_start = min(a['START_TS'] for a in alerts)

    ###########################
    ###############  ADD GENIE DATA — single batched query
    ###########################
    genie_rows = clickhouse_client.query(f"""
    SELECT ID, toUInt32(TARGET_NETWORK), toUInt32(TARGET_BROADCAST),
           MAX_BPS, MAX_PPS, RESOURCE, END_TIME, START_TIME
    FROM genie_events
    WHERE START_TIME >= toDateTime('{earliest_start}')
      AND {unique_id_condition}
    """).result_rows

    # Close the SELECT connection before the write block below.
    sqlite_cursor.close()
    sqlite_connection.close()

    pending_updates = []      # (uid, max_bps, max_pps, resources_json, raw_json, recovered_num)
    pending_end_times = []     # (uid, end_time)

    for alert in alerts:
        uid = alert['UID']
        target_network = alert['TARGET_NETWORK']
        target_broadcast = alert['TARGET_BROADCAST']
        target_net_int = alert['TARGET_NETWORK_INT']
        target_bro_int = alert['TARGET_BROADCAST_INT']
        alert_start_pd = alert['START_PD']
        current_max_bps = alert['CURRENT_MAX_BPS'] or 0
        current_max_pps = alert['CURRENT_MAX_PPS'] or 0

        ongoing = False
        genie_data = {
            'end_times': [],
            'resources': [],
            'non-perfect-overlap': {
                'max_bps': 0,
                'max_pps': 0
            },
            'raw': []
        }

        for genie_row in genie_rows:
            genie_id, genie_net_int, genie_bro_int, genie_max_bps, genie_max_pps, \
                genie_resources, genie_end_time, genie_start_time = genie_row

            # Network-range containment (was ClickHouse WHERE clause).
            if genie_net_int < target_net_int or genie_bro_int > target_bro_int:
                continue
            # Per-alert start-time filter (was ClickHouse WHERE clause).
            # ClickHouse returns tz-aware datetimes; SQLite START_TIME is tz-naive.
            if genie_start_time is not None and make_naive(genie_start_time) < alert_start_pd:
                continue

            genie_net = str(ipaddress.IPv4Address(genie_net_int))
            genie_broadcast = str(ipaddress.IPv4Address(genie_bro_int))
            genie_net, genie_broadcast = _normalize_net_broadcast(genie_net, genie_broadcast)

            ### End alerts
            if genie_end_time is not None:
                genie_data['end_times'].append(genie_end_time)
            else:
                ongoing = True
                raw_row = [genie_id, genie_net, genie_broadcast,
                           genie_max_bps, genie_max_pps, genie_resources, genie_end_time]
                genie_data['raw'].append(raw_row)
                ### Update current resources, max BPS and max PPS
                genie_data['resources'].extend(genie_resources)
                if str(genie_net) == str(target_network) and str(genie_broadcast) == str(target_broadcast):
                    if 'perfect-overlap' in genie_data:
                        genie_data['perfect-overlap']['max_bps'] += genie_max_bps
                        genie_data['perfect-overlap']['max_pps'] += genie_max_pps
                    else:
                        genie_data['perfect-overlap'] = {
                            'max_bps': genie_max_bps,
                            'max_pps': genie_max_pps
                        }
                else:
                    genie_data['non-perfect-overlap']['max_bps'] += genie_max_bps
                    genie_data['non-perfect-overlap']['max_pps'] += genie_max_pps
        ###########################

        max_bps = genie_data['perfect-overlap']['max_bps'] if 'perfect-overlap' in genie_data else genie_data['non-perfect-overlap']['max_bps']
        max_bps = max(max_bps, current_max_bps)
        max_pps = genie_data['perfect-overlap']['max_pps'] if 'perfect-overlap' in genie_data else genie_data['non-perfect-overlap']['max_pps']
        max_pps = max(max_pps, current_max_pps)

        pending_updates.append((
            uid, max_bps, max_pps,
            json.dumps(genie_data['resources']),
            json.dumps(genie_data['raw']),
            len(genie_data['end_times'])
        ))

        if not ongoing:  ### End alerts
            end_time = make_naive(max(genie_data['end_times'])).strftime('%Y-%m-%d %H:%M:%S')
            pending_end_times.append((uid, end_time))

    # Tight write block: single transaction for all UPDATEs.
    reopen_sqlite_conn()
    sqlite_cursor = sqlite_connection.cursor()
    try:
        sqlite_cursor.execute('BEGIN IMMEDIATE')
        for uid, max_bps, max_pps, resources_json, raw_json, recovered_num in pending_updates:
            sqlite_cursor.execute('''UPDATE alerts SET
            CURRENT_MAX_BPS = ?, MAX_BPS = MAX(MAX_BPS, ?), CURRENT_MAX_PPS = ?,
            CURRENT_RESOURCES = ?, CURRENT_GENIE_EVENTS = ?,
            RECOVERED_GENIE_EVENTS_NUM = ?
                WHERE UID = ?''',
                (max_bps, max_bps, max_pps, resources_json, raw_json, recovered_num, uid))
        for uid, end_time in pending_end_times:
            sqlite_cursor.execute('UPDATE alerts SET END_TIME = ? WHERE UID = ?', (end_time, uid))
            sqlite_cursor.execute('UPDATE alerts SET CURRENT_MAX_BPS = 0, CURRENT_MAX_PPS = 0 WHERE UID = ?', (uid,))
        sqlite_connection.commit()
    except Exception:
        sqlite_connection.rollback()
        raise
    finally:
        sqlite_cursor.close()
        sqlite_connection.close()
    sqlite_connection.close()








from data_fetcher import has_dp_drops
from data_fetcher import has_waf_blocks
from data_fetcher import get_dp_drop_packets
from data_fetcher import get_waf_blocks_count
from utils import send_notification
from concurrent.futures import ThreadPoolExecutor, as_completed

def bps_ge_1gbps(max_bps):
    return (max_bps or 0) >= 1_000_000_000
    #return (max_bps or 0) >= 200_000_000


# Level scheme. LEVEL is a 2-condition severity tier, with lower numbers
# meaning higher priority:
#   1 = highest:  DP drops >= LEVEL_DP_DROP_THRESHOLD AND max_bps >= 1 Gbps
#   2 = lower:    either condition alone (XOR)
#   3 = lowest:   neither condition
#   0 = unassigned (not yet computed). Once a non-zero value is assigned it
#       is monotonic toward severity: ongoing alerts keep min(old, new) so
#       the level can only get *more* severe as the attack evolves.
LEVEL_DP_DROP_THRESHOLD = 10_000


def _compute_level(dp_packets, max_bps):
    """Compute the level (1/2/3) from DP drops and traffic volume.

      dp_cond  = DP dropped packets over the alert window >= LEVEL_DP_DROP_THRESHOLD
      bps_cond = max_bps >= 1 Gbps

      both true  -> 1 (highest)
      either true -> 2
      neither    -> 3 (lowest)

    `dp_packets` is the total dropped packet_count summed over
    [START_TIME, END_TIME-or-now] from get_dp_drop_packets().
    `max_bps`   is CURRENT_MAX_BPS (ongoing) or MAX_BPS (ended).
    Returns 1, 2 or 3. The 0 sentinel (unassigned) is handled by callers.
    """
    dp_cond  = (dp_packets or 0) >= LEVEL_DP_DROP_THRESHOLD
    bps_cond = bps_ge_1gbps(max_bps)
    if dp_cond and bps_cond:
        return 1
    if dp_cond or bps_cond:
        return 2
    return 3

def update_alerts_levels(batch_size=10):
    '''
    LEVEL is the 2-condition severity tier:
        1 = highest: DP drops >= 10k AND max_bps >= 1 Gbps
        2 = lower:   either condition alone
        3 = lowest:  neither condition
        0 = unassigned (default; assigned on first compute)
    WAF blocks are NOT part of LEVEL (recorded separately as WAF_BLOCKS).
    LEVEL is monotonic toward severity: ongoing alerts keep min(old, new)
    so the level can only get more severe as the attack evolves. The 0
    sentinel is replaced on the first compute (not merged via min).

    Blocking. Internally batches rows (up to batch_size at a time) and runs
    the DP/WAF magnitude fetches concurrently per batch (threads, since the
    OpenSearch calls are I/O-bound and release the GIL).

    Lock discipline: the SELECT connection is closed before any OpenSearch
    call is made, and a fresh connection is opened only for the final UPDATE
    block. No SQLite transaction is held open while waiting on OpenSearch,
    which is what previously caused 'database is locked' collisions with the
    long-running old_alerts_leveler process.
    '''
    global sqlite_connection

    reopen_sqlite_conn()
    sqlite_cursor = sqlite_connection.cursor()

    sqlite_cursor.execute('''
        SELECT UID, TARGET_CIDR, START_TIME, END_TIME, LEVEL, CURRENT_MAX_BPS
        FROM alerts
        WHERE END_TIME IS NULL
        ORDER BY START_TIME ASC
    ''')

    rows = sqlite_cursor.fetchall()
    col_names = [d[0] for d in sqlite_cursor.description]

    sqlite_cursor.close()
    sqlite_connection.close()

    if not rows:
        return

    max_workers = batch_size * 2  # 2 OpenSearch checks per row concurrently

    pending_updates = []  # (uid, new_level, waf_blocks, dp_blocks) w/o txn

    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        alerts = [dict(zip(col_names, r)) for r in batch]

        dp_pkt_results  = {a['UID']: 0 for a in alerts}
        waf_cnt_results = {a['UID']: 0 for a in alerts}

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            fut_to_kind = {}
            for a in alerts:
                cidr  = a['TARGET_CIDR']
                start = pd.to_datetime(a['START_TIME']).strftime("%Y-%m-%d %H:%M:%S")
                window_end = a['END_TIME']  # ongoing -> None -> OpenSearch 'now'
                fut_to_kind[ex.submit(get_dp_drop_packets, cidr, start, window_end)] = ('dp',  a['UID'])
                fut_to_kind[ex.submit(get_waf_blocks_count, cidr, start, window_end)] = ('waf', a['UID'])

            for fut in as_completed(fut_to_kind):
                kind, uid = fut_to_kind[fut]
                if kind == 'dp':
                    dp_pkt_results[uid]  = fut.result()
                else:
                    waf_cnt_results[uid] = fut.result()

        for a in alerts:
            uid       = a['UID']
            old_level = a['LEVEL'] or 0
            max_bps   = a['CURRENT_MAX_BPS'] or 0

            # --- LEVEL (2-condition tier, monotonic toward severity) ---
            computed = _compute_level(dp_pkt_results[uid], max_bps)
            if old_level == 0:
                # First compute: just assign (don't min against 0).
                new_level = computed
            else:
                new_level = min(old_level, computed)
            waf_blocks = waf_cnt_results[uid]

            # DP blocks = total dropped packets over the alert's elapsed
            # window. Recomputed every leveler pass for ongoing alerts so the
            # value tracks the live attack (mirrors WAF_BLOCKS behavior).
            dp_blocks = int(dp_pkt_results[uid])

            # --- Buzz opening notification on first LEVEL=1 transition ---
            # LEVEL is monotonic toward severity, so the transition into 1
            # happens at most once per alert. OPENING_NOTIFICATION stores the
            # Buzz sync_id (matching the deprecated services/buzz.py convention)
            # so a future closing notification can reply in the same thread.
            opening_sync_id = None
            if new_level == 1 and old_level != 1:
                try:
                    text = (
                        f"🚨 Level-1 attack detected on {a['TARGET_CIDR']}\n"
                        f"Alert #{uid}: "
                        f"https://ddos-info.antiddos.cloud.vimpelcom.ru:8000/alert/{uid}"
                    )
                    res = send_notification(ALERT_CENTER_BOT_TOKEN, TEST_CHAT_ID, text)
                    opening_sync_id = (res or {}).get("result", {}).get("sync_id")
                    if not opening_sync_id:
                        opening_sync_id = "1"
                except Exception:
                    traceback.print_exc()
                    opening_sync_id = "0"

            pending_updates.append((uid, new_level, waf_blocks, dp_blocks, opening_sync_id))

    if not pending_updates:
        return

    # Tight write block: open a fresh connection, acquire the write lock
    # upfront via BEGIN IMMEDIATE, flush all UPDATEs, commit, close.
    # busy_timeout (30s) covers any transient collision with the leveler.
    reopen_sqlite_conn()
    sqlite_cursor = sqlite_connection.cursor()
    try:
        sqlite_cursor.execute('BEGIN IMMEDIATE')
        for uid, new_level, waf_blocks, dp_blocks, opening_sync_id in pending_updates:
            if opening_sync_id is not None:
                sqlite_cursor.execute(
                    'UPDATE alerts SET LEVEL = ?, WAF_BLOCKS = ?, DP_BLOCKS = ?, '
                    '  OPENING_NOTIFICATION = ?  WHERE UID = ?',
                    (new_level, waf_blocks, dp_blocks,  opening_sync_id, uid)
                )      
            else:
                sqlite_cursor.execute(
                    'UPDATE alerts SET LEVEL = ?, WAF_BLOCKS = ?, DP_BLOCKS = ? WHERE UID = ?',
                    (new_level, waf_blocks, dp_blocks, uid)
                )
        sqlite_connection.commit()
    except Exception:
        sqlite_connection.rollback()
        raise
    finally:
        sqlite_cursor.close()
        sqlite_connection.close()


def update_old_alerts_levels(ended_limit=20, batch_size=5):
    '''
    Recompute LEVEL for ended alerts whose LEVEL_LOCKED = 0, processing the
    most recent ended alerts first (ORDER BY END_TIME DESC). After computing
    the final level, sets LEVEL_LOCKED = 1 so the alert is never reprocessed.

    LEVEL is the 2-condition severity tier:
        1 = highest (DP drops >= 10k AND max_bps >= 1 Gbps),
        2 = either condition,
        3 = neither)

    Counterpart to update_alerts_levels (which only touches ongoing alerts).
    Differences vs update_alerts_levels:
      - reads MAX_BPS / MAX_PPS (permanent high-watermarks) instead of
        CURRENT_MAX_BPS / CURRENT_MAX_PPS (zeroed by update_alerts() when an
        alert ends)
      - locks LEVEL via LEVEL_LOCKED
      - LEVEL is a one-shot compute here (no monotonic merge), since the
        alert has ended and the final window is fixed.
      - does NOT touch ongoing alerts (END_TIME IS NULL) — those stay with
        update_alerts_levels

    Intended to run in its own long-running process (see services/old_alerts_leveler.py)
    so a large historical backlog can be worked through without blocking the
    main alert pipeline. ended_limit caps how many ended alerts are processed
    per call; the loop calls this repeatedly until none remain (LEVEL_LOCKED=0).

    Blocking. Internally batches rows (up to batch_size at a time) and runs
    the DP/WAF magnitude fetches concurrently per batch (threads, since the
    OpenSearch calls are I/O-bound and release the GIL).

    Lock discipline: same as update_alerts_levels — the SELECT connection is
    closed before any OpenSearch call, and a fresh connection is opened only
    for the final UPDATE block so no SQLite transaction is held during the
    slow I/O waits. This avoids 'database is locked' collisions with the
    main pipeline's update_alerts_levels call.
    '''
    global sqlite_connection
    reopen_sqlite_conn()
    sqlite_cursor = sqlite_connection.cursor()
    # busy_timeout is already set by _open_sqlite_conn() / reopen_sqlite_conn()

    sqlite_cursor.execute('''
        SELECT UID, TARGET_CIDR, START_TIME, END_TIME, LEVEL, MAX_BPS, LEVEL_LOCKED
        FROM alerts
        WHERE END_TIME IS NOT NULL
          AND LEVEL_LOCKED = 0
        ORDER BY END_TIME DESC
        LIMIT ?
    ''', (ended_limit,))

    rows = sqlite_cursor.fetchall()
    col_names = [d[0] for d in sqlite_cursor.description]

    sqlite_cursor.close()
    sqlite_connection.close()

    if not rows:
        return 0

    max_workers = batch_size * 2  # 2 OpenSearch checks per row concurrently

    pending_updates = []  # (uid, new_level, lock_level, waf_blocks, dp_blocks) w/o txn

    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        alerts = [dict(zip(col_names, r)) for r in batch]

        dp_pkt_results  = {a['UID']: 0 for a in alerts}
        waf_cnt_results = {a['UID']: 0 for a in alerts}

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            fut_to_kind = {}
            for a in alerts:
                cidr  = a['TARGET_CIDR']
                start = pd.to_datetime(a['START_TIME']).strftime("%Y-%m-%d %H:%M:%S")
                window_end = a['END_TIME']  # always set here (ended alerts only)
                fut_to_kind[ex.submit(get_dp_drop_packets, cidr, start, window_end)] = ('dp',  a['UID'])
                fut_to_kind[ex.submit(get_waf_blocks_count, cidr, start, window_end)] = ('waf', a['UID'])

            for fut in as_completed(fut_to_kind):
                kind, uid = fut_to_kind[fut]
                if kind == 'dp':
                    dp_pkt_results[uid]  = fut.result()
                else:
                    waf_cnt_results[uid] = fut.result()

        for a in alerts:
            uid       = a['UID']
            max_bps   = a['MAX_BPS'] or 0
            level_locked = a.get('LEVEL_LOCKED') or 0

            # --- LEVEL (only if not already locked) ---
            new_level = a.get('LEVEL') or 0
            waf_blocks = 0
            dp_blocks = 0
            lock_level = 0
            if not level_locked:
                new_level = _compute_level(dp_pkt_results[uid], max_bps)
                waf_blocks = waf_cnt_results[uid]
                # DP blocks = total dropped packets over the alert's fixed
                # window. Frozen once LEVEL_LOCKED is set (mirrors
                # WAF_BLOCKS treatment for ended alerts).
                dp_blocks = int(dp_pkt_results[uid])
                lock_level = 1

            pending_updates.append((uid, new_level, lock_level, waf_blocks, dp_blocks))

    if not pending_updates:
        return 0

    # Tight write block: open a fresh connection, acquire the write lock
    # upfront via BEGIN IMMEDIATE, flush all UPDATEs, commit, close.
    # busy_timeout (30s) covers any transient collision with the main pipeline.
    reopen_sqlite_conn()
    sqlite_cursor = sqlite_connection.cursor()
    try:
        sqlite_cursor.execute('BEGIN IMMEDIATE')
        for uid, new_level, lock_level, waf_blocks, dp_blocks in pending_updates:
            sqlite_cursor.execute(
                'UPDATE alerts SET LEVEL = ?, LEVEL_LOCKED = MAX(LEVEL_LOCKED, ?), '
                'WAF_BLOCKS = ?, DP_BLOCKS = ? '
                'WHERE UID = ?',
                (new_level, lock_level, waf_blocks, dp_blocks, uid)
            )
        sqlite_connection.commit()
    except Exception:
        sqlite_connection.rollback()
        raise
    finally:
        sqlite_cursor.close()
        sqlite_connection.close()

    return len(pending_updates)


def update_old_alerts_bps(ended_limit=20):
    '''
    One-shot final MAX_BPS refresh for ended alerts whose BPS_LOCKED = 0,
    processing the most recent ended alerts first (ORDER BY END_TIME DESC).
    After recomputing MAX_BPS over the full fixed [START_TIME, END_TIME]
    window, sets BPS_LOCKED = 1 so the alert is never reprocessed.

    Counterpart to update_old_alerts_levels (which locks LEVEL) but for the
    traffic-volume watermark. The reason it exists: update_alerts() only
    folds *ongoing* Genie events (END_TIME IS NULL) into the alert's
    MAX_BPS — the Genie row(s) that mark an alert's end carry the final
    peak value but are skipped (only their END_TIME is harvested to close
    the alert). Any straggler Genie events ingested after the alert was
    closed are also missed, since update_alerts() only selects
    WHERE END_TIME IS NULL. This pass closes that gap by recomputing
    MAX_BPS over ALL matching Genie events in the alert's window.

    Reuses update_alerts()'s perfect-overlap / non-perfect-overlap rule:
      - perfect-overlap    = genie net == alert net (exact match)        -> sum
      - non-perfect-overlap= genie net contained within alert net range -> sum
      - perfect-overlap wins if any exists, else non-perfect-overlap.
    Final value is max(recomputed, existing MAX_BPS) so the watermark
    can only go up.
    '''
    global sqlite_connection
    reopen_sqlite_conn()
    sqlite_cursor = sqlite_connection.cursor()

    sqlite_cursor.execute('''
        SELECT UID, TARGET_NETWORK, TARGET_BROADCAST, START_TIME, END_TIME, MAX_BPS
        FROM alerts
        WHERE END_TIME IS NOT NULL
          AND BPS_LOCKED = 0
        ORDER BY END_TIME DESC
        LIMIT ?
    ''', (ended_limit,))

    rows = sqlite_cursor.fetchall()
    col_names = [d[0] for d in sqlite_cursor.description]

    sqlite_cursor.close()
    sqlite_connection.close()

    if not rows:
        return 0

    alerts = []
    for row in rows:
        a = dict(zip(col_names, row))
        target_network, target_broadcast = _normalize_net_broadcast(
            a['TARGET_NETWORK'], a['TARGET_BROADCAST'])
        a['TARGET_NETWORK'] = target_network
        a['TARGET_BROADCAST'] = target_broadcast
        a['TARGET_NETWORK_INT'] = int(ipaddress.IPv4Address(target_network))
        a['TARGET_BROADCAST_INT'] = int(ipaddress.IPv4Address(target_broadcast))
        a['START_TS'] = pd.to_datetime(a['START_TIME']).strftime("%Y-%m-%d %H:%M:%S")
        a['START_PD'] = pd.to_datetime(a['START_TIME'])
        a['END_PD']   = pd.to_datetime(a['END_TIME'])  # always set for ended alerts
        alerts.append(a)

    earliest_start = min(a['START_TS'] for a in alerts)

    # Single batched ClickHouse query — same shape as update_alerts().
    # unique_id_condition gives us the latest (final) MAX_BPS per Genie ID,
    # which for ended events carries the peak value we previously skipped.
    genie_rows = clickhouse_client.query(f"""
    SELECT ID, toUInt32(TARGET_NETWORK), toUInt32(TARGET_BROADCAST),
           MAX_BPS, MAX_PPS, RESOURCE, END_TIME, START_TIME
    FROM genie_events
    WHERE START_TIME >= toDateTime('{earliest_start}')
      AND {unique_id_condition}
    """).result_rows

    pending_updates = []

    for alert in alerts:
        uid = alert['UID']
        target_net_int = alert['TARGET_NETWORK_INT']
        target_bro_int = alert['TARGET_BROADCAST_INT']
        target_network = alert['TARGET_NETWORK']
        target_broadcast = alert['TARGET_BROADCAST']
        alert_start_pd = alert['START_PD']

        perfect_overlap = {'max_bps': 0, 'max_pps': 0}
        non_perfect_overlap = {'max_bps': 0, 'max_pps': 0}
        has_perfect = False

        for genie_row in genie_rows:
            (genie_id, genie_net_int, genie_bro_int, genie_max_bps,
             genie_max_pps, genie_resources, genie_end_time,
             genie_start_time) = genie_row

            # Network-range containment (was ClickHouse WHERE clause).
            if genie_net_int < target_net_int or genie_bro_int > target_bro_int:
                continue
            # Per-alert start-time filter (was ClickHouse WHERE clause).
            if genie_start_time is not None and make_naive(genie_start_time) < alert_start_pd:
                continue
            # Strict upper bound: a genie event that started after the alert
            # ended belongs to a *different* alert and must NOT be folded into
            # this one. Without this guard, every subsequent attack on the same
            # (or contained) range was summed into the closed alert's MAX_BPS,
            # producing inflated values (e.g. 3100 Gbps vs ~37 Gbps peak).
            # Mirrors get_related_genie()'s END_TIME <= alert.END_TIME clause
            # so the displayed "related events" table matches the computed value.
            alert_end_pd = alert['END_PD']
            if genie_start_time is not None and make_naive(genie_start_time) > alert_end_pd:
                continue

            genie_net = str(ipaddress.IPv4Address(genie_net_int))
            genie_broadcast = str(ipaddress.IPv4Address(genie_bro_int))
            genie_net, genie_broadcast = _normalize_net_broadcast(genie_net, genie_broadcast)

            if str(genie_net) == str(target_network) and str(genie_broadcast) == str(target_broadcast):
                has_perfect = True
                perfect_overlap['max_bps'] += genie_max_bps or 0
                perfect_overlap['max_pps'] += genie_max_pps or 0
            else:
                non_perfect_overlap['max_bps'] += genie_max_bps or 0
                non_perfect_overlap['max_pps'] += genie_max_pps or 0

        max_bps = perfect_overlap['max_bps'] if has_perfect else non_perfect_overlap['max_bps']
        final_max_bps = max(max_bps, alert['MAX_BPS'] or 0)

        pending_updates.append((final_max_bps, uid))

    if not pending_updates:
        return 0

    reopen_sqlite_conn()
    sqlite_cursor = sqlite_connection.cursor()
    try:
        sqlite_cursor.execute('BEGIN IMMEDIATE')
        for final_max_bps, uid in pending_updates:
            sqlite_cursor.execute(
                'UPDATE alerts SET MAX_BPS = ?, BPS_LOCKED = 1 WHERE UID = ?',
                (final_max_bps, uid)
            )
        sqlite_connection.commit()
    except Exception:
        sqlite_connection.rollback()
        raise
    finally:
        sqlite_cursor.close()
        sqlite_connection.close()

    return len(pending_updates)


def recreate_alerts_db():
    sqlite_cursor = sqlite_connection.cursor()

    sqlite_cursor.execute('DROP TABLE IF EXISTS alerts')

    sqlite_cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            UID INTEGER PRIMARY KEY AUTOINCREMENT,
            TARGET_CIDR TEXT NOT NULL,
            TARGET_NETWORK TEXT,
            TARGET_BROADCAST TEXT,
            TARGET_NETWORK_INT INTEGER,
            TARGET_BROADCAST_INT INTEGER,
            START_TIME TEXT NOT NULL,
            END_TIME TEXT,
            UPDATE_TIME TEXT,
            
            LEVEL INTEGER DEFAULT 0,
            LEVEL_LOCKED INTEGER DEFAULT 0,
            WAF_BLOCKS INTEGER DEFAULT 0,
            DP_BLOCKS INTEGER DEFAULT 0,
            OPENING_NOTIFICATION TEXT DEFAULT "0",
            CLOSING_NOTIFICATION TEXT DEFAULT "0",
            
            
            CURRENT_MAX_BPS INTEGER DEFAULT 0,
            MAX_BPS INTEGER DEFAULT 0,
            BPS_LOCKED INTEGER DEFAULT 0,
            CURRENT_MAX_PPS INTEGER DEFAULT 0,
            CURRENT_RESOURCES BLOB,
            CURRENT_GENIE_EVENTS BLOB,
            RECOVERED_GENIE_EVENTS_NUM INTEGER DEFAULT 0
        )
    ''')

    sqlite_connection.commit()


def migrate_alerts_add_int_cols():
    """Idempotent migration: adds TARGET_NETWORK_INT / TARGET_BROADCAST_INT
    columns to the alerts table if missing and backfills them from the
    existing TARGET_NETWORK / TARGET_BROADCAST TEXT columns.

    Safe to run on a fresh table (no-op) or an existing populated table.
    """
    global sqlite_connection
    reopen_sqlite_conn()
    sqlite_cursor = sqlite_connection.cursor()

    sqlite_cursor.execute('PRAGMA table_info(alerts)')
    existing_cols = {row[1] for row in sqlite_cursor.fetchall()}

    if 'TARGET_NETWORK_INT' not in existing_cols:
        sqlite_cursor.execute('ALTER TABLE alerts ADD COLUMN TARGET_NETWORK_INT INTEGER')
    if 'TARGET_BROADCAST_INT' not in existing_cols:
        sqlite_cursor.execute('ALTER TABLE alerts ADD COLUMN TARGET_BROADCAST_INT INTEGER')
    sqlite_connection.commit()

    sqlite_cursor.execute('SELECT UID, TARGET_NETWORK, TARGET_BROADCAST FROM alerts')
    rows = sqlite_cursor.fetchall()
    for uid, net_str, bcast_str in rows:
        net_int = None
        bcast_int = None
        try:
            if net_str is not None:
                net_str, bcast_str2 = _normalize_net_broadcast(net_str, bcast_str)
                net_int = int(ipaddress.IPv4Address(net_str))
                bcast_int = int(ipaddress.IPv4Address(bcast_str2))
        except Exception:
            pass
        sqlite_cursor.execute(
            'UPDATE alerts SET TARGET_NETWORK_INT = ?, TARGET_BROADCAST_INT = ? WHERE UID = ?',
            (net_int, bcast_int, uid)
        )
    sqlite_connection.commit()
    sqlite_cursor.close()


# =============================================================================
# =============================================================================
# ============        ONE-TIME MIGRATION — TO BE REMOVED              =========
# ============        After running once in production, DELETE        =========
# ============        migrate_alerts_recompute_bps() below AND        =========
# ============        the call to it at the bottom of __main__.       =========
# =============================================================================
# =============================================================================

def migrate_alerts_recompute_bps():
    """ONE-TIME MIGRATION — TO BE REMOVED after use.

    Background: update_old_alerts_bps() had no upper bound on genie.START_TIME,
    so for every closed alert it summed in every subsequent genie event on the
    same (or contained) network range, no matter how far in the future. The
    resulting MAX_BPS values are inflated and were frozen by BPS_LOCKED = 1.

    This migration:
      1. Resets MAX_BPS = 0 AND BPS_LOCKED = 0 on ALL ended alerts.
      2. Returns immediately — the existing run_level_update() daemon
         (services/alert.py:__main__) will then recompute every unlocked
         alert via update_old_alerts_bps() with the now-fixed strict
         [START_TIME, END_TIME] window filter, at 20 alerts per ~5s.

    IMPORTANT: this zeroes MAX_BPS for every closed alert, including ones
    that were correctly computed. That is intentional — recomputing them
    with the fixed filter yields the same (correct) value. The trade-off
    is a brief window where MAX_BPS shows 0 for closed alerts until the
    leveler catches up (~1 alert per 5s; ~700 alerts per hour).

    Usage:
        python -c "from services.alert import migrate_alerts_recompute_bps; migrate_alerts_recompute_bps()"

    After running, the leveler process must be running (or services.alert
    started as __main__) so update_old_alerts_bps() actually re-processes
    the reset rows. Verify progress with:
        SELECT COUNT(*) FROM alerts WHERE BPS_LOCKED = 0 AND END_TIME IS NOT NULL;

    Once COUNT(*) returns 0, all alerts have been recomputed and this
    function can be removed.
    """
    global sqlite_connection
    reopen_sqlite_conn()
    sqlite_cursor = sqlite_connection.cursor()
    try:
        sqlite_cursor.execute(
            'SELECT COUNT(*) FROM alerts WHERE END_TIME IS NOT NULL AND BPS_LOCKED = 1'
        )
        affected = sqlite_cursor.fetchone()[0]
        print(f"[migrate_alerts_recompute_bps] resetting MAX_BPS / BPS_LOCKED "
              f"on {affected} ended alerts...")

        sqlite_cursor.execute('BEGIN IMMEDIATE')
        sqlite_cursor.execute(
            'UPDATE alerts SET MAX_BPS = 0, BPS_LOCKED = 0 '
            'WHERE END_TIME IS NOT NULL'
        )
        sqlite_connection.commit()
        print(f"[migrate_alerts_recompute_bps] done. "
              f"The run_level_update() daemon will now recompute them.")
        print(f"[migrate_alerts_recompute_bps] monitor progress with:")
        print(f"  SELECT COUNT(*) FROM alerts WHERE BPS_LOCKED = 0 "
              f"AND END_TIME IS NOT NULL;")
    except Exception:
        sqlite_connection.rollback()
        raise
    finally:
        sqlite_cursor.close()
        sqlite_connection.close()
        




LOOP_INTERVAL_SECONDS = 5
ENDED_LIMIT = 20

def run_level_update(interval=LOOP_INTERVAL_SECONDS, ended_limit=ENDED_LIMIT):
    print("[old_alerts_leveler] waiting to start (120s)...")
    time.sleep(120)
    print("[old_alerts_leveler] starting...")
    
    while True:
        try:
            processed = update_old_alerts_levels(ended_limit=ended_limit, batch_size=5)
            bps_processed = update_old_alerts_bps(ended_limit=ended_limit)
            if processed or bps_processed:
                print(f"[old_alerts_leveler] processed {processed} ended alerts (levels), "
                      f"{bps_processed} (final MAX_BPS); "
                      f"sleeping {interval}s")
            else:
                bruh = interval + 15
                print(f"[old_alerts_leveler] no ended alerts to level; "
                      f"sleeping {bruh}s")
                time.sleep(15)
        except Exception:
            print("[old_alerts_leveler] error:")
            traceback.print_exc()

        time.sleep(interval)


def _run_pipeline(window_days, label=""):
    today = pd.Timestamp.today().date()
    end_ts = pd.Timestamp(f"{today} 11:00:00")
    start = (end_ts - pd.Timedelta(days=window_days)).strftime("%Y-%m-%d %H:%M:%S")

    fill_alerts(start, None)
    print(f"[{label}] filled alerts")
    update_alerts()
    print(f"[{label}] updated alerts")
    update_alerts_levels()
    print(f"[{label}] updated alert levels")


if __name__ == "__main__":
    #recreate_alerts_db()
    #migrate_alerts_recompute_bps()


    leveler = multiprocessing.Process(target=run_level_update, daemon=True)
    leveler.start()

    _run_pipeline(window_days=3, label="startup")
    while True:
        _run_pipeline(window_days=1, label="loop")
        print("sleeping 60s")
        time.sleep(60)


