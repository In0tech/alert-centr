from flask import Flask, request, jsonify
import configparser
import os

app = Flask(__name__)
import pickle

import re
import ipaddress
import sqlite3
from datetime import datetime
from pandas import DataFrame as df

import clickhouse_connect

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'alert_center.conf'))

DB_PATH = config.get('DATABASE_PATHS', 'MITIGATIONS_DB_PATH')

CLICKHOUSE_HOST = config.get('CLICKHOUSE', 'HOST')
CLICKHOUSE_PORT = config.getint('CLICKHOUSE', 'PORT')
CLICKHOUSE_USER = config.get('CLICKHOUSE', 'USER')
CLICKHOUSE_DATABASE = config.get('CLICKHOUSE', 'DATABASE')
clickhouse_client = clickhouse_connect.get_client(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, user=CLICKHOUSE_USER, database=CLICKHOUSE_DATABASE)

##############################
def recreate_mitigations_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('DROP TABLE IF EXISTS mitigations')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS mitigations (
        TARGET_CIDR TEXT PRIMARY KEY,
        TARGET_NETWORK_INT INTEGER NOT NULL,
        TARGET_BROADCAST_INT INTEGER NOT NULL,
        CURRENT_MITIGATION TEXT,
        UPDATE_TIME_UNIX INTEGER NOT NULL
    )
    ''')
    conn.commit()
    conn.close()
# 1 time use: 
#recreate_mitigations_db()
##############################

def recreate_mitigations_events():
    try:
        clickhouse_client.command('DROP TABLE alert_center.mitigations_events')
    except:
        pass
    clickhouse_client.command('''
        CREATE TABLE IF NOT EXISTS alert_center.mitigations_events (
            TARGET_CIDR String,
            TARGET_NETWORK_INT UInt32,
            TARGET_BROADCAST_INT UInt32,
            CURRENT_MITIGATION Nullable(String),
            UPDATE_TIME DateTime('Europe/Moscow')
        )
        ENGINE = MergeTree
    ''')
# 1 time use:
#recreate_mitigations_events()
##############################

def insert_mitigation_event(cidr, network_int, broadcast_int, mitigation, update_time_unix):
    try:
        mitig_str = "NULL" if mitigation is None else "'" + str(mitigation).replace("'", "\\'") + "'"
        
        clickhouse_client.command(f"""INSERT INTO alert_center.mitigations_events VALUES
        (
            '{cidr}',
            {network_int},
            {broadcast_int},
            {mitig_str},
            toDateTime({update_time_unix})
        )  """)
    except Exception as e:
        print('Insert to ClickHouse error')
        print(e)

##############################

def stage_update_mitigation(sqlite_cursor: sqlite3.Cursor, cidr, mitigation=None):
    dst_net = ipaddress.IPv4Network(cidr, strict=False)
    update_time = int(datetime.now().timestamp())

    sqlite_cursor.execute('SELECT CURRENT_MITIGATION FROM mitigations WHERE TARGET_CIDR = ?', (cidr,))
    existing = sqlite_cursor.fetchone()
    if existing:
        existing_mitigation = existing[0]
        sqlite_cursor.execute('''
            UPDATE mitigations
            SET CURRENT_MITIGATION = ?, UPDATE_TIME_UNIX = ?
            WHERE TARGET_CIDR = ?
        ''', (mitigation, update_time, cidr))
        if existing_mitigation != mitigation:
            insert_mitigation_event(cidr, int(dst_net.network_address), int(dst_net.broadcast_address), mitigation, update_time)
    else:
        sqlite_cursor.execute('''
            INSERT INTO mitigations (
                TARGET_CIDR,
                TARGET_NETWORK_INT,
                TARGET_BROADCAST_INT,
                CURRENT_MITIGATION,
                UPDATE_TIME_UNIX
            ) VALUES (?, ?, ?, ?, ?)
        ''', (
            cidr,
            int(dst_net.network_address),
            int(dst_net.broadcast_address),
            mitigation,
            update_time
        ))
        insert_mitigation_event(cidr, int(dst_net.network_address), int(dst_net.broadcast_address), mitigation, update_time)

def get_current_mitigations(sqlite_cursor: sqlite3.Cursor = None):
    if not sqlite_cursor:
        sqlite_connection = sqlite3.connect(DB_PATH)
        sqlite_cursor = sqlite_connection.cursor()
        
    sqlite_cursor.execute('SELECT * FROM mitigations WHERE CURRENT_MITIGATION IS NOT NULL')
    mitigations = df(sqlite_cursor.fetchall(), columns=['TARGET_CIDR', 'TARGET_NETWORK_INT', 'TARGET_BROADCAST_INT', 'CURRENT_MITIGATION', 'UPDATE_TIME_UNIX'])
    return mitigations

##############################

@app.route('/routing_data', methods=['POST'])
def catch_post():
    CURRENT_ROUTING = {}
    
    data = request.get_json()
    
    content = data.get('routing_results', '')

    for line in content:
        network_match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d+)", line)
        comm_match = re.search(r"Communities: (\d+):(\d+)", line)
        if network_match and comm_match:
            route = '?'
            asn = comm_match.group(2)
            match asn[:2]:
                case '60':
                    route = 'SBH'
                case '61':
                    route = 'Переведён на ЦОТ'
                case _:
                    route = str(asn)

            CURRENT_ROUTING[f"{network_match.group(1)}/{network_match.group(2)}"] = route


    print(CURRENT_ROUTING)


    sqlite_connection = sqlite3.connect(DB_PATH)
    sqlite_cursor = sqlite_connection.cursor()

    curr_mitigs_df = get_current_mitigations(sqlite_cursor)
    
    print(f"\n{curr_mitigs_df.head()}\n...\n{curr_mitigs_df.tail()}\n--------------------------------\n")
    
    for index, row in curr_mitigs_df.iterrows():
        if row['TARGET_CIDR'] not in CURRENT_ROUTING:
            stage_update_mitigation(sqlite_cursor, row['TARGET_CIDR'], None)
    sqlite_connection.commit()

    for cidr, route in CURRENT_ROUTING.items():
        stage_update_mitigation(sqlite_cursor, cidr, route)
            
    sqlite_connection.commit()
    sqlite_connection.close()
            

    lame_routes = {}
    for cidr, route in CURRENT_ROUTING.items():
        if cidr.split('/')[1] == '32':
            new_cidr = cidr.split('/')[0]
            lame_routes[new_cidr] = route
        else:
            lame_routes[cidr] = route

    with open('current_mitigations.pkl', 'wb') as f:
        pickle.dump(lame_routes, f)
    
    with open('current_mitigations.pkl', 'rb') as f:
        loaded_data = pickle.load(f)
    
    return jsonify({"status": "success"}), 200



if __name__ == '__main__':
    #recreate_mitigations_db()
    app.run(debug=True, host='0.0.0.0', port=6006)
    
    
    
    
    
    

