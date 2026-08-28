
from flask import Flask, request, Response
import configparser
import os

app = Flask(__name__)

import requests, json

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'alert_center.conf'))

BUZZ_URL = config.get('BUZZ_API', 'BUZZ_URL')
KUMA_BOT_CHAT_ID = config.get('BUZZ_API', 'KUMA_BOT_CHAT_ID')
KUMA_BOT_TOKEN = config.get('BUZZ_API', 'KUMA_BOT_TOKEN')

def send_notification(text):
    headers = {
        "authorization": f"Bearer {KUMA_BOT_TOKEN}",
        "content-type": "application/json",
    }
    payload = {
        "group_chat_id": KUMA_BOT_CHAT_ID,
        "notification": {
            "status": "ok",
            "body": text,
        },
        "opts": {}
    }
    resp = requests.post(url=BUZZ_URL, headers=headers, data=json.dumps(payload), timeout=10)
    resp.raise_for_status()
    return resp.json()



import sqlite3

import clickhouse_connect
from datetime import datetime

CLICKHOUSE_HOST = config.get('CLICKHOUSE', 'HOST')
CLICKHOUSE_PORT = config.getint('CLICKHOUSE', 'PORT')
CLICKHOUSE_USER = config.get('CLICKHOUSE', 'USER')
CLICKHOUSE_DATABASE = config.get('CLICKHOUSE', 'DATABASE')
clickhouse_client = clickhouse_connect.get_client(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, user=CLICKHOUSE_USER, database=CLICKHOUSE_DATABASE)

import ipaddress
from datetime import datetime

def update_kuma_status(kuma_event):
    # kuma_event['msg'] with ip:    [stsload.beeline.ru |217.118.87.7] [ Up] 200 - OK
    # kuma_event['msg'] with no ip: [moskva.beeline.ru] [ Down] timeout of 4000ms exceeded
    KUMA_STATUS_DB_PATH = config.get('DATABASE_PATHS', 'KUMA_STATUS_DB_PATH')
    sqlite_connection = sqlite3.connect(KUMA_STATUS_DB_PATH)


    try:
        header = kuma_event['msg'].split('] [')
        ip = ipaddress.IPv4Address(header[0].split('|')[1])
        status = header[1].split(']')[0] 
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    except:
        print("Bad format: ", kuma_event['msg'])
        return

    try:
        clickhouse_client.command(f"""INSERT INTO kuma_events VALUES 
        (
            '{ip}', 
            '{status}',
            toDateTime('{now}')
        )
        """)
        
        ip = str(ip)
        sqlite_cursor = sqlite_connection.cursor()
        sqlite_cursor.execute(f"SELECT * FROM kuma_status WHERE TARGET_IP = '{ip}'")
        if sqlite_cursor.fetchall():
            sqlite_cursor.execute(f"UPDATE kuma_status SET STATUS = '{status}', UPDATE_TIME = '{now}' WHERE TARGET_IP = '{ip}'")
        else:
            sqlite_cursor.execute(f"INSERT INTO kuma_status VALUES ('{ip}', '{status}', '{now}')")
        sqlite_connection.commit()
        sqlite_connection.close()
    except Exception as e:
        print('Insert to db error')
        print(e)

last_status = {}

@app.route('/kuma', methods=['POST'])
@app.route('/kuma/', methods=['POST'])
def kuma_test():
    a = request.get_json()
    update_kuma_status(a)
        
    id = a['heartbeat']['monitorID']
    status = a['heartbeat']['status']

    if id not in last_status or last_status[id] != status:
        send_notification(f"{a['msg']} \nLast heartbeat: {a['heartbeat']['localDateTime']}")
        last_status[id] = status
    return Response(status=200)
    
app.run(host="0.0.0.0", port=5001, debug=False)



def recreate_kuma_status_db():
    KUMA_STATUS_DB_PATH = config.get('DATABASE_PATHS', 'KUMA_STATUS_DB_PATH')
    sqlite_connection = sqlite3.connect(KUMA_STATUS_DB_PATH)
    sqlite_cursor = sqlite_connection.cursor()
    sqlite_cursor.execute('DROP TABLE IF EXISTS alerts')
    sqlite_cursor.execute('''
        CREATE TABLE IF NOT EXISTS kuma_status (
            TARGET_IP TEXT,            
            STATUS TEXT,

            UPDATE_TIME BLOB
        )
    ''')
    sqlite_connection.commit()
    sqlite_connection.close()


    try:
        clickhouse_client.command('DROP TABLE alert_center.kuma_events')
    except:
        pass
    clickhouse_client.command('''
        CREATE TABLE IF NOT EXISTS alert_center.kuma_events (
            TARGET_IP IPv4,
            STATUS String,

            UPDATE_TIME DateTime('Europe/Moscow'),
        )  
        ENGINE =  MergeTree
    ''')

#recreate_kuma_status_db()

