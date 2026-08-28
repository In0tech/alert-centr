from flask import Flask, request, Response
import asyncio
import requests
import json
from datetime import timedelta
import time 
from datetime import datetime
import sqlite3
import clickhouse_connect
import configparser
import os

import ipaddress

import pandas as pd 

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'alert_center.conf'))

DB_PATH = config.get('DATABASE_PATHS', 'MITIGATIONS_DB_PATH')

CLICKHOUSE_HOST = config.get('CLICKHOUSE', 'HOST')
CLICKHOUSE_PORT = config.getint('CLICKHOUSE', 'PORT')
CLICKHOUSE_USER = config.get('CLICKHOUSE', 'USER')
CLICKHOUSE_DATABASE = config.get('CLICKHOUSE', 'DATABASE')
clickhouse_client = clickhouse_connect.get_client(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, user=CLICKHOUSE_USER, database=CLICKHOUSE_DATABASE)

mitigations_bot_token = config.get('BUZZ_API', 'MITIGATIONS_BOT_TOKEN')
buzz_mitigations_chat_id = config.get('BUZZ_API', 'MITIGATIONS_CHAT_ID')
BUZZ_URL = config.get('BUZZ_API', 'BUZZ_URL')
BUZZ_REPLY_URL = config.get('BUZZ_API', 'BUZZ_REPLY_URL')


def target_range_to_cidr(start_ip: str, end_ip: str) -> str:
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    total = int(end) - int(start) + 1
    prefix = 32 - (total.bit_length() - 1)
    net = ipaddress.IPv4Network(f"{start}/{prefix}", strict=False)
    return str(net)



def send_notification(token, chat_id, text, respond_to = None, rep_statistics = True):
    global BUZZ_URL
    headers = {
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
    }
    
    if respond_to:
        payload = {
            "source_sync_id": respond_to,
            "reply": {
                "status": "ok",
                "body": text,
            },
            "opts": {},
        }
        try:
            resp = requests.post(BUZZ_REPLY_URL, headers=headers, data=json.dumps(payload), timeout=10)
            resp.raise_for_status()
            return resp.json()
        except: pass # fallback to simple notification
    
    payload = {
        "group_chat_id": chat_id,
        "notification": {
            "status": "ok",
            "body": text,
        },
        "opts": {},
    }

    resp = requests.post(BUZZ_URL, headers=headers, data=json.dumps(payload), timeout=10)
    resp.raise_for_status()
    return resp.json()

def check_db_for_sbh(sqlite3_cursor: sqlite3.Cursor):
    sqlite3_cursor.execute('SELECT * FROM mitigations WHERE CURRENT_MITIGATION = "SBH"')
    sbh_rows = sqlite3_cursor.fetchall()
    if len(sbh_rows) > 0:
        sbh_df = pd.DataFrame(sbh_rows, columns=['TARGET_CIDR', 'TARGET_NETWORK_INT', 'TARGET_BROADCAST_INT', 'CURRENT_MITIGATION', 'UPDATE_TIME_UNIX'])
        return sbh_df
    return pd.DataFrame() 

        
# add a test row
#ip_int = int(ipaddress.IPv4Address('95.31.244.125'))
#cot_df.loc[len(cot_df)] = {'TARGET_CIDR': '95.31.244.125/32', 'TARGET_NETWORK_INT': ip_int, 'TARGET_BROADCAST_INT': ip_int, 
#                        'CURRENT_MITIGATION': 'cot', 'UPDATE_TIME_UNIX': 0}


def check_db_for_cot(sqlite3_cursor: sqlite3.Cursor, cot_nets: list[ipaddress.IPv4Network]):
    sqlite3_cursor.execute('SELECT * FROM mitigations WHERE CURRENT_MITIGATION = "Переведён на ЦОТ"')
    cot_rows = sqlite3_cursor.fetchall()
    if len(cot_rows) > 0:
        cot_df = pd.DataFrame(cot_rows, columns=['TARGET_CIDR', 'TARGET_NETWORK_INT', 'TARGET_BROADCAST_INT', 'CURRENT_MITIGATION', 'UPDATE_TIME_UNIX'])
        cot_df = cot_df[cot_df['TARGET_CIDR'].apply(
            lambda x: any(ipaddress.IPv4Network(x, strict=False).overlaps(target_net) 
                        for target_net in cot_nets)
        )]
        return cot_df
    return pd.DataFrame()


def c_rounding(value, unit):
    value = float(value)
    if   value >= 1000000000:
        return f"{(value/1000000000):.2f} G{unit}"
    elif value >= 1000000:
        return f"{(value/1000000):.2f} M{unit}"
    #elif value > 1000:
    return f"{(value/1000):.2f} K{unit}"

def dedup_names(list):
    #eturn str(lst)
    
    unique = set()
    string = ""
    for i in list:
        unique.add(i)
        
    for name in unique:
        string += f'{name}\n'
    return string



unique_id_condition = ''' (ID, UPDATE_TIME) IN (
    SELECT ID, MAX(UPDATE_TIME) as UPDATE_TIME
    FROM genie_events
    GROUP BY ID
) '''
base_condition = f"{unique_id_condition} AND STATUS != 'Obsolete'"
def get_last_related_genie_event_by_net(search_network, search_broadcast):
    ''' returns last genie_events dataframe from genie db'''
    
    q = f"""
SELECT ID, MAX_BPS, MAX_PPS, START_TIME, END_TIME, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST FROM alert_center.genie_events 
WHERE (( TARGET_NETWORK  <= '{search_network}'
    AND TARGET_BROADCAST >= '{search_broadcast}'  AND END_TIME IS NULL  ) AND {base_condition} )
ORDER BY START_TIME DESC LIMIT 1"""
    db_res = clickhouse_client.query(q).result_rows
    if len(db_res) == 0:
        return pd.DataFrame()
    df = pd.DataFrame(db_res, columns=['id', 'max_bps', 'max_pps','start_time', 'end_time', 'resource', 'target_network', 'target_broadcast'])
    return df 


def get_genie_event_by_net(search_network, search_broadcast):    
    conditions = [
        # exact match and is current
f""" (( TARGET_BROADCAST = '{search_broadcast}' AND TARGET_NETWORK = '{search_network}' AND END_TIME IS NULL ) AND {base_condition}) """,

        # fully contains net and is current
f""" (( TARGET_BROADCAST >= '{search_broadcast}' AND TARGET_NETWORK <= '{search_network}' AND END_TIME IS NULL ) AND {base_condition}) """,

        # intersects and is current
f""" (( TARGET_BROADCAST >= '{search_network}' AND TARGET_NETWORK <= '{search_broadcast}' AND END_TIME IS NULL ) AND {base_condition}) """,

        # intersects and recent
f""" (( TARGET_BROADCAST >= '{search_network}' AND TARGET_NETWORK <= '{search_broadcast}' AND END_TIME >= toDateTime('{(datetime.now()-timedelta(days=1)).strftime('%Y-%m-%d %H:%M:%S')}') ) AND {base_condition}) """,


        # fully contains net but is not current
#f""" (( TARGET_BROADCAST >= '{search_broadcast}' AND TARGET_NETWORK <= '{search_network}' ) AND {base_condition}) """,

        # intersects but is not current
#f""" (( TARGET_BROADCAST >= '{search_network}' AND TARGET_NETWORK <= '{search_broadcast}' ) AND {base_condition}) """
    ]

    for condition in conditions:
        query = f"""SELECT ID, MAX_BPS, MAX_PPS, START_TIME, END_TIME, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST FROM alert_center.genie_events
        WHERE {condition}
        ORDER BY START_TIME DESC LIMIT 1
        """ # better order by END_TIME. NULL behavior ??

        db_res = clickhouse_client.query(query).result_rows
        if len(db_res) > 0:
            df = pd.DataFrame(db_res, columns=['id', 'max_bps', 'max_pps','start_time', 'end_time', 'resource', 'target_network', 'target_broadcast'])
            return df
    
    return pd.DataFrame()



def get_genie_event_by_id(genie_event_id):
    q = f"""
SELECT ID, MAX_BPS, MAX_PPS, START_TIME, END_TIME, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST FROM alert_center.genie_events 
WHERE ID = '{genie_event_id}' AND {base_condition}
ORDER BY START_TIME DESC LIMIT 1"""
    db_res = clickhouse_client.query(q).result_rows
    if len(db_res) == 0:
        return pd.DataFrame()
    df = pd.DataFrame(db_res, columns=['id', 'max_bps', 'max_pps','start_time', 'end_time', 'resource', 'target_network', 'target_broadcast'])
    return df



def collapse_networks(df: pd.DataFrame) -> list:
    records = []
    for _, row in df.iterrows():
        #start_ip_int = int(ipaddress.ip_address(row['TARGET_NETWORK_INT']))
        #end_ip_int = int(ipaddress.ip_address(row['TARGET_BROADCAST_INT']))
        records.append({
            'start_ip_int': row['TARGET_NETWORK_INT'],
            'end_ip_int': row['TARGET_BROADCAST_INT'],
            'subnets': []
        })

    if not records:
        return []

    records.sort(key=lambda x: x['start_ip_int'])


    merged_records = []
    current = records[0]
    current['subnets'].extend((current['start_ip_int'], current['end_ip_int']))

    for record in records[1:]:
        if record['start_ip_int'] <= current['end_ip_int']+1:  # +1 to extend adjacent networks
            current['subnets'].extend((record['start_ip_int'], record['end_ip_int']))
            current['end_ip_int'] = max(current['end_ip_int'], record['end_ip_int'])
        else:
            merged_records.append(current)
            current = record

    merged_records.append(current)


    res = []
    for record in merged_records:
        start_ip = ipaddress.ip_address(record['start_ip_int'])
        end_ip = ipaddress.ip_address(record['end_ip_int'])
        res.append((str(start_ip), str(end_ip)))

    return res

CURRENT_OPEN_NOTIFICATIONS = {} # (mitigation_cidr, mitigation_type) : {genie_event_id , sync_id, start_time, mitigation_type}

def close_notifications(current_active):
    global CURRENT_OPEN_NOTIFICATIONS
    remove_ranges = []    

    for key in CURRENT_OPEN_NOTIFICATIONS.keys():
        if key not in current_active:
            duration = time.time() - CURRENT_OPEN_NOTIFICATIONS[key]['start_time']
            mitigation_type = CURRENT_OPEN_NOTIFICATIONS[key]['mitigation_type']
            mitigation_label = 'Селективный BH' if mitigation_type == 'sbh' else 'Перевод на ЦОТ'
            
            print(f'Sending close <<<<<<< for {key[0]} ({mitigation_type})')
            genie_event_text = f"""✅ Митигация окончена ({mitigation_label})

🎯 Target:
{target_range_to_cidr(*key[0])} 

🕐 Продолжительность митигации:
{time.strftime('%H:%M:%S', time.gmtime(duration))}
"""

            send_notification(mitigations_bot_token, buzz_mitigations_chat_id, genie_event_text, CURRENT_OPEN_NOTIFICATIONS[key]['sync_id'])
            remove_ranges.append(key)
            
    for key in remove_ranges:
        del CURRENT_OPEN_NOTIFICATIONS[key]
                
                

def main():
    global CURRENT_OPEN_NOTIFICATIONS
    
    cot_nets_str = '''37.9.244.0/24
37.9.245.0/24
62.231.7.208/28
85.115.249.0/24
217.118.84.0/24
217.118.85.0/24
217.118.86.0/24
217.118.87.0/24
80.243.79.0/24
80.243.78.0/24'''
    cot_nets = []
    for net in cot_nets_str.split('\n'):
        if net:
            cot_nets.append(ipaddress.IPv4Network(net, strict=False))

    TIMEOUT = 10
    
    while True:
        sqlite3_connection = sqlite3.connect(DB_PATH)
        sqlite3_cursor  = sqlite3_connection.cursor()
        
        sbh_df: pd.DataFrame = check_db_for_sbh(sqlite3_cursor)
        cot_df: pd.DataFrame = check_db_for_cot(sqlite3_cursor, cot_nets)
        
        print(f"sbh_df size: {sbh_df}")
        
        if sbh_df.empty and cot_df.empty:
            time.sleep(TIMEOUT)
            sqlite3_connection.close()
            continue
               

        ########## collapse and collect all active ranges with their mitigation type
        all_active_ranges = [] # list of ((start_ip, end_ip), mitigation_type)

        if not sbh_df.empty:
            sbh_ranges = collapse_networks(sbh_df)
            for r in sbh_ranges:
                all_active_ranges.append((r, 'sbh'))

        if not cot_df.empty:
            cot_ranges = collapse_networks(cot_df)
            for r in cot_ranges:
                all_active_ranges.append((r, 'cot'))

        active_keys = [((start_ip, end_ip), mtype) for ((start_ip, end_ip), mtype) in all_active_ranges]
        
        close_notifications(active_keys)
        
        for (start_ip, end_ip), mitigation_type in all_active_ranges:
            target_range = (start_ip, end_ip)
            key = (target_range, mitigation_type)

            if mitigation_type == 'sbh':
                mitigation_label = 'Селективный BH'
            else:
                mitigation_label = 'Перевод на ЦОТ'
                            
            ################## New notification
            if key not in CURRENT_OPEN_NOTIFICATIONS.keys():
                
                # get genie event with exact overlap or larger, current or latest
                event_df = get_genie_event_by_net(target_range[0], target_range[1])  #  *target_range
                #print(event_df)
                if event_df.empty: 
                    genie_event_text = f""" 🚨 Зафиксирована DDOS атака

🎯 Target:
{target_range_to_cidr(*target_range)}

❗ Отсутствует релевантное событие в Genie

🛡️ Принимаемые меры защиты:
{mitigation_label}
"""
                else: 
                    event = event_df.iloc[0]   
                    genie_event_text = f""" 🚨 Зафиксирована DDOS атака

🎯 Target:
{target_range_to_cidr(*target_range)}

📍 Sub-network:
{dedup_names(event['resource'])}

🎫 ID События:
{event['id']}

📈 Параметры атаки:
{c_rounding(event['max_bps'], 'bps')} / {c_rounding(event['max_pps'], 'pps')}

🛡️ Принимаемые меры защиты:
{mitigation_label}
"""
                
                
                res = send_notification(mitigations_bot_token, buzz_mitigations_chat_id, genie_event_text)
                
                print(f'Sending open    >>>>>> ({mitigation_type})')
                
                CURRENT_OPEN_NOTIFICATIONS[key] = \
                    {'genie_event_id': 1,#genie_event.iloc[0]['id'],
                        'sync_id': res['result']['sync_id'],
                        'start_time': time.time(),
                        'mitigation_type': mitigation_type}
                
            
        sqlite3_connection.commit()
        sqlite3_connection.close()
            
        time.sleep(TIMEOUT)
        

    
if __name__ == "__main__":
    main()
