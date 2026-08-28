import logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.DEBUG,
    datefmt='%Y-%m-%d %H:%M:%S',
    filename='alert_center_webhooks.log',
    filemode='a'
)
logger = logging.getLogger(__name__)
logger.info("Started")


from flask import Flask
app = Flask(__name__)



from flask import Flask, request, Response
import asyncio
import requests
import json

import time 
from datetime import datetime, timedelta, time as dt_time


#from apis import buzz_url, genie_info_bot_token, genie_info_chat_id, buzz_chat_id, buzz_b2b_chat_id
buzz_url = 'asdsadsad'
buzz_token = 'asdsadsa'#genie_info_bot_token
buzz_chat_id = 'asdasd'#genie_info_chat_id
buzz_b2b_chat_id = 'agfadfs'

send_to_buzz = False

    

###################### UTILS ######################
###################################################

def send_notification(url, token, chat_id, text, respond_to = None, rep_statistics = True):
    print(text.split('\n')[2])
    return {'result':{'sync_id':0}}
    
    headers = {
        "authorization": f"Bearer {token}",
        "content-type": "application/json",
    }
    
    if rep_statistics:
        if respond_to:
            reply_url = "https://cts1.buzz.beeline.ru:4443/api/v3/botx/events/reply_event"
            payload = {
                "source_sync_id": respond_to,
                "reply": {
                    "status": "ok",
                    "body": text,
                    "bubble": [
                        [
                            {
                            "command": "/report_statistics",
                            "label": "Текущая статистика",
                            "silent": True,
                            }
                        ]
                    ]
                },
                "opts": {},
            }
            resp = requests.post(reply_url, headers=headers, data=json.dumps(payload), timeout=10)
            resp.raise_for_status()
            return resp.json()
        
        payload = {
            "group_chat_id": chat_id,
            "notification": {
                "status": "ok",
                "body": text,
                "bubble": [
                    [
                        {
                        "command": "/report_statistics",
                        "label": "Текущая статистика",
                        "silent": True,
                        }
                    ]
                ]
            },
            "opts": {},
        }
    else: # not rep_statistics
        if respond_to:
            reply_url = "https://cts1.buzz.beeline.ru:4443/api/v3/botx/events/reply_event"
            payload = {
                "source_sync_id": respond_to,
                "reply": {
                    "status": "ok",
                    "body": text,
                },
                "opts": {},
            }
            resp = requests.post(reply_url, headers=headers, data=json.dumps(payload), timeout=10)
            resp.raise_for_status()
            return resp.json()
        
        payload = {
            "group_chat_id": chat_id,
            "notification": {
                "status": "ok",
                "body": text,
            },
            "opts": {},
        }
    
    if send_to_buzz:
        resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=10)
        resp.raise_for_status()
        return resp.json()
    return None

def dedup_names(list):
    unique = set()
    string = ""
    for i in list:
        unique.add(i['name'])
        
    for name in unique:
        string += f'{name}\n'
    return string

def c_rounding(value, unit):
    value = float(value)
    if   value >= 1000000000:
        return f"{(value/1000000000):.2f} G{unit}"
    elif value >= 1000000:
        return f"{(value/1000000):.2f} M{unit}"
    #elif value > 1000:
    return f"{(value/1000):.2f} K{unit}"
    
######################

def beatify_alert_open(genie_event):
    logger.info(f"Genie event started: {genie_event}")
    
    attack_types = dedup_names(genie_event['attack'])
    # genie_event['attack'][0]['name']
    subnets = dedup_names(genie_event['resource'])
    # genie_event['resource'][0]['name']

    beautified = \
f'''🚨 Зафиксирована DDOS атака
🎫 ID События:
{genie_event['id']}

🔻 Тип:
{attack_types}

🎯 Target:
{genie_event['ip']}

📍 Sub-network:
{subnets}
📈 Параметры атаки:
Bandwidth:  {c_rounding(genie_event['traffic']['current_value_bps'], 'bps')}  (max: {c_rounding(genie_event['traffic']['max_value_bps'], 'bps')})
Packets:  {c_rounding(genie_event['traffic']['current_value_pps'], 'pps')}  (max: {c_rounding(genie_event['traffic']['max_value_pps'], 'pps')})

🕐 Начало атаки:
{genie_event['datetime']['start_time']}
'''
    return beautified

def beatify_alert_recovered(genie_event):
    logger.info(f"Genie event ended: {genie_event}")
    
    time_min = int(int(genie_event['datetime']['duration'])/60)
    if time_min < 60:
        time_str = f"{time_min} min"
    else:
        time_str = f"{time_min//60} hr {time_min%60} min"
    
    beautified = \
f'''✅ Аномалия окончена
🎫 ID События:
{genie_event['id']}

🎯 Target:
{genie_event['ip']}

📈 Пиковые значения:
{c_rounding(genie_event['traffic']['max_value_bps'], 'bps')}
{c_rounding(genie_event['traffic']['max_value_pps'], 'pps')}

🕐 Продолжительность аномалии:
{time_str}

🕐 Конец атаки:
{genie_event['datetime']['end_time']}
'''         
    return beautified

######################

def stat_report_day(current_attacks_num, attacks_started, attacks_ended, total_attacks_num, top_attack):
    top_id, top_bps, top_subnets = top_attack
    
    text = \
f'''
За последние сутки (с 9:00):
> Началось атак: {attacks_started}
> Завершенных атак: {attacks_ended}
> Общее количество атак: {total_attacks_num}

Текущих: {current_attacks_num}

Самая мощная атака:
    🎫 ID События: {top_id}
    🎯 Target: {top_subnets}
    📈 Объём: {(float(top_bps)/1000000000):.2f} Gbps
'''

    logger.info(f"Daily stats reported: {text}")
    
    try:
        send_notification(buzz_url, buzz_token, buzz_chat_id, text) 
    except Exception as e: logger.error(f"While attempting to report daily stats: {e}")

def stat_report_week(current_attacks_num, attacks_started, attacks_ended, total_attacks_num, top_attack):
    top_id, top_bps, top_subnets = top_attack
    
    text = \
f'''
За последнюю неделю (с четверга, 9:00):
> Началось атак: {attacks_started}
> Завершенных атак: {attacks_ended}
> Общее количество атак: {total_attacks_num}

Текущих: {current_attacks_num}

Самая мощная атака:
    🎫 ID События: {top_id}
    🎯 Target: {top_subnets} 
    📈 Объём: {(float(top_bps)/1000000000):.2f} Gbps
'''

    try:
        send_notification(buzz_url, buzz_token, buzz_chat_id, text)   
    except Exception as e: logger.error(f"While attempting to report daily stats: {e}")
    
    logger.info(f"Weekly stats reported: {text}")

######################


def query_for_stats(daily=True, weekly=True):
    '''
    Returns lists of [current_attacks_num, attacks_started, attacks_ended, total_attacks_num, top_attack]. Lets call this data. 
    If daily or weekly - return value is [[current_attacks_num, attacks_started, attacks_ended, total_attacks_num, top_attack]] (daily or weekly)
    If both daily and weekly - return value is [data_day, data_week] 
    '''
    today = datetime.now().date()
    
    # 9 AM
    today_start = int(datetime.combine(today, dt_time(9, 0, 0)).timestamp())
    # Thursday 9 AM
    week_start = today - timedelta(days=((today.weekday() + 4) % 7))
    week_start = int(datetime.combine(week_start, dt_time(9, 0, 0)).timestamp())

    import clickhouse_connect
    client = clickhouse_connect.get_client(host='localhost', port=8123, user='default', database='alert_center')
    
    client.command(f"OPTIMIZE TABLE genie_events FINAL CLEANUP")
    
    
    query = """SELECT COUNT(*) AS current_attacks_num
        FROM genie_events
        WHERE END_TIME IS NULL
        """
    # AND STATUS IN ('Open', 'Ongoing')  
    current_attacks_num = client.query(query).result_rows
    current_attacks_num = current_attacks_num[0][0] if (current_attacks_num and current_attacks_num[0]) else 0
    
    retval = []
    if daily:
        ######## Today
        query = f"""SELECT COUNT(*) AS attacks_started_today
        FROM genie_events
        WHERE START_TIME >= toDateTime('{today_start}')
        """
        attacks_started_today = client.query(query).result_rows
        attacks_started_today = attacks_started_today[0][0] if (attacks_started_today and attacks_started_today[0]) else 0

        query = f"""SELECT COUNT(*) AS attacks_ended_today
        FROM genie_events
        WHERE END_TIME >= toDateTime('{today_start}')
        """
        attacks_ended_today = client.query(query).result_rows
        attacks_ended_today = attacks_ended_today[0][0] if (attacks_ended_today and attacks_ended_today[0]) else 0

        query = f"""SELECT COUNT(*) AS total_attacks_today
        FROM genie_events
        WHERE START_TIME >= toDateTime('{today_start}') OR END_TIME >= toDateTime('{today_start}')
        """
        total_attacks_today = client.query(query).result_rows
        total_attacks_today = total_attacks_today[0][0] if (total_attacks_today and total_attacks_today[0]) else 0

        # Top attack
        query = f"""SELECT ID, MAX(MAX_BPS) AS top_attack_today_bps
        FROM genie_events
        WHERE START_TIME >= toDateTime('{today_start}') OR END_TIME >= toDateTime('{today_start}')
        GROUP BY ID
        """
        top_attack_today = client.query(query).result_rows
        if top_attack_today and top_attack_today[0]:
            query = f"""SELECT RESOURCE
            FROM genie_events
            WHERE ID = '{top_attack_today[0][0]}'
            """
            top_subnets_today = client.query(query).result_rows[0][0]
            top_attack_today_bps = top_attack_today[0][1]
            top_attack_today = [top_attack_today[0][0], top_attack_today_bps,top_subnets_today]      
        else:
            top_attack_today = [None, None, 0]
            
        retval.append([current_attacks_num, attacks_started_today, attacks_ended_today, total_attacks_today, top_attack_today])  
        
    if weekly:
        ######## Week
        query = f"""SELECT COUNT(*) AS attacks_started_week
        FROM genie_events
        WHERE START_TIME >= toDateTime('{week_start}')
        """
        attacks_started_week = client.query(query).result_rows
        attacks_started_week = attacks_started_week[0][0] if (attacks_started_week and attacks_started_week[0]) else 0

        query = f"""SELECT COUNT(*) AS attacks_ended_week
        FROM genie_events
        WHERE END_TIME >= toDateTime('{week_start}')
        """
        attacks_ended_week = client.query(query).result_rows
        attacks_ended_week = attacks_ended_week[0][0] if (attacks_ended_week and attacks_ended_week[0]) else 0

        query = f"""SELECT COUNT(*) AS total_attacks_week
        FROM genie_events
        WHERE START_TIME >= toDateTime('{week_start}') OR END_TIME >= toDateTime('{week_start}')
        """
        total_attacks_week = client.query(query).result_rows
        total_attacks_week = total_attacks_week[0][0] if (total_attacks_week and total_attacks_week[0]) else 0

        # Top attack
        query = f"""SELECT ID, MAX(MAX_BPS) AS top_attack_week_bps
        FROM genie_events
        WHERE START_TIME >= toDateTime('{week_start}') OR END_TIME >= toDateTime('{week_start}')
        GROUP BY ID
        """
        top_attack_week = client.query(query).result_rows
        if top_attack_week and top_attack_week[0]:
            query = f"""SELECT RESOURCE
            FROM genie_events
            WHERE ID = '{top_attack_week[0][0]}'
            """
            top_subnets_week = client.query(query).result_rows[0][0]
            top_attack_week_bps = top_attack_week[0][1]
            top_attack_week = [top_attack_week[0][0], top_attack_week_bps,top_subnets_week]      
        else:
            top_attack_week = [None, None, None]
        
        retval.append([current_attacks_num, attacks_started_week, attacks_ended_week, total_attacks_week, top_attack_week])
    return retval

'''def insert_genie_event(genie_event):    
    from sqlite3 import connect, Error
    conn = connect('alert_center.db')
    c = conn.cursor()
    if genie_event['status'] == 'Recovered':
        end_time_unix = int(datetime.strptime(genie_event['datetime']['end_time'], '%Y-%m-%d %H:%M:%S').timestamp())
    else:
        end_time_unix = 0
    start_time_unix = int(datetime.strptime(genie_event['datetime']['start_time'], '%Y-%m-%d %H:%M:%S').timestamp())
    end_time_unix = int(datetime.strptime(genie_event['datetime']['end_time'], '%Y-%m-%d %H:%M:%S').timestamp())

    # id - str, start - str, end - str,  max_bps, subnets - json, target_ip - str,   status - str (Open/Recovered (Ongoing))
    c.execute("INSERT OR REPLACE INTO genie_events VALUES (?, ?, ?, ?, ?, ?, ?)",  
                (
                    genie_event['id'],  
                    start_time_unix, end_time_unix, 
                    
                    int(genie_event['traffic']['max_value_bps']),  int(genie_event['traffic']['max_value_pps']),  
                    json.dumps([r['name'] for r in genie_event['resource']]), 
                    
                    genie_event['ip'], # dst ip.  relate to monitored objects table
                    
                    genie_event['status']
                )
            )
                # '\n'.join(r['name'] for r in genie_event['resource'])
    # table resources(id, subnet, ...)
    # table event_recourses(event_id, resource_id)
    conn.commit()
    conn.close()#'''
    
def insert_genie_event(genie_event):
    import clickhouse_connect
    import ipaddress
    
    client = clickhouse_connect.get_client(host='localhost', port=8123, user='default', database='alert_center')
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    end_time = 'NULL'
    if genie_event['status'] == 'Recovered':
        end_time = f"toDateTime('{genie_event['datetime']['end_time']}')"

    ip_range = ipaddress.ip_network(genie_event['ip'], strict=False)
    client.command(f"""INSERT INTO genie_events VALUES 
    (
        '{genie_event['id']}', 
        toDateTime('{now}'),
        toDateTime('{genie_event['datetime']['start_time']}'), {end_time}, 
        {genie_event['traffic']['max_value_bps']}, {genie_event['traffic']['max_value_pps']}, 
        {[r['name'] for r in genie_event['resource']]}, 
        '{genie_event['status']}',        
        '{ip_range.network_address}', '{ip_range.broadcast_address}'
    )
    """)

    
###################################################
###################################################


CURRENT_ATTACKS_INBOUND = {} # id : 
                     #   {alert_criteria : boolean,
                     #    alert_open_id : int}
CURRENT_ATTACKS_ALL = {}


def handle_buzz_bot_commands():
    command = request.get_json()
    
    if command['command']['body'] == '/report_statistics':
        try:
            stats_day, stats_week = query_for_stats(daily=True, weekly=True)
            stat_report_day(*stats_day)                 
            stat_report_week(*stats_week)   
                   
        except Exception as e: logger.error(e)
    return Response(status=200)


def return_response():
    global CURRENT_ATTACKS_INBOUND
    global CURRENT_ATTACKS_ALL

    genie_data = request.get_json()

    EVENT_FIELDS = ['status', 'attack_direction', 'severity', 'id']#, 'resource, 'attack', 'ip']
    def validate_data(genie_data):
        if 'event' in genie_data and \
        all(f in genie_data['event'] for f in EVENT_FIELDS) and \
        'type' in genie_data['event']['severity']:
            return True
        return False


    if validate_data(genie_data):
        logger.debug(genie_data)
    else:
        return Response(status=200)
    
    genie_event = genie_data['event']
    insert_genie_event(genie_event)
                    
    
    print(CURRENT_ATTACKS_INBOUND.keys())
    
    if genie_data['event']['attack_direction'] == 'Inbound' and \
       all(not (r['name'] == 'Home' or r['name'] == 'Non-Home') for r in genie_data['event']['resource']):

        if float(genie_event['traffic']['max_value_bps']) >= 1000000000: # Inbound, 1GB+     
            match(genie_event['status']):
                case 'Open':
                    sync_id = None
                    try:     
                        text = beatify_alert_open(genie_event)
                        res = send_notification(buzz_url, buzz_token, buzz_chat_id, text)
                        sync_id = res['result']['sync_id']
                    except Exception as e: logger.error(e)

                    CURRENT_ATTACKS_INBOUND[genie_event['id']] = {'alert_criteria': True, 'alert_open_id': sync_id}

                case 'Recovered':                
                    try:
                        sync_id = None
                        if (genie_event['id'] in CURRENT_ATTACKS_INBOUND and CURRENT_ATTACKS_INBOUND[genie_event['id']]['alert_criteria'] == False) or \
                          genie_event['id'] not in CURRENT_ATTACKS_INBOUND:                              
                            text = beatify_alert_open(genie_event)        
                            res = send_notification(buzz_url, buzz_token, buzz_chat_id, text) 
                            sync_id = res['result']['sync_id']
                        alert_open_id = sync_id or CURRENT_ATTACKS_INBOUND[genie_event['id']]['alert_open_id']
                        
                        text = beatify_alert_recovered(genie_event)           
                        send_notification(buzz_url, buzz_token, buzz_chat_id, text, alert_open_id)
                    except Exception as e: logger.error(e)
                    CURRENT_ATTACKS_INBOUND.pop(genie_event['id'], None)

                case 'Ongoing':
                    if (genie_event['id'] in CURRENT_ATTACKS_INBOUND and CURRENT_ATTACKS_INBOUND[genie_event['id']]['alert_criteria'] == False) or \
                      genie_event['id'] not in CURRENT_ATTACKS_INBOUND:                        
                        try:
                            text = beatify_alert_open(genie_event)         
                            res = send_notification(buzz_url, buzz_token, buzz_chat_id, text)
                            sync_id = res['result']['sync_id']
                            CURRENT_ATTACKS_INBOUND[genie_event['id']] = {'alert_criteria': True, 'alert_open_id': sync_id}
                        except Exception as e: logger.error(e)
                        
        else: # Inbound, < 1GB
            match(genie_event['status']):
                case 'Open':
                    CURRENT_ATTACKS_INBOUND[genie_event['id']] = {'alert_criteria': False, 'alert_open_id': None}

                case 'Recovered':
                    if genie_event['id'] in CURRENT_ATTACKS_INBOUND and CURRENT_ATTACKS_INBOUND[genie_event['id']]['alert_criteria'] == True:
                        try:
                            text = beatify_alert_recovered(genie_event)        
                            send_notification(buzz_url, buzz_token, buzz_chat_id, text, CURRENT_ATTACKS_INBOUND[genie_event['id']]['alert_open_id'])
                        except Exception as e: logger.error(e)
                    CURRENT_ATTACKS_INBOUND.pop(genie_event['id'], None)

                case 'Ongoing':
                    if genie_event['id'] not in CURRENT_ATTACKS_INBOUND:
                        CURRENT_ATTACKS_INBOUND[genie_event['id']] = {'alert_criteria': False, 'alert_open_id': None}

    ###############################  "Home/Non-Home or out"  ###############################
    ########################################################################################
    else: 
        if float(genie_event['traffic']['max_value_bps']) >= 1000000000: # Home/Non-Home/Not Inbound, 1GB +
            match(genie_event['status']):
                case 'Open':
                    sync_id = None
                    try:     
                        text = beatify_alert_open(genie_event)
                        res = send_notification(buzz_url, buzz_token, buzz_b2b_chat_id, text, rep_statistics=False)
                        sync_id = res['result']['sync_id']
                    except Exception as e: logger.error(e)
                    CURRENT_ATTACKS_ALL[genie_event['id']] = {'alert_criteria': True, 'alert_open_id': sync_id}

                case 'Recovered':                
                    try:
                        sync_id = None
                        if (genie_event['id'] in CURRENT_ATTACKS_ALL and CURRENT_ATTACKS_ALL[genie_event['id']]['alert_criteria'] == False) or \
                            genie_event['id'] not in CURRENT_ATTACKS_ALL:                              
                            text = beatify_alert_open(genie_event)         
                            res = send_notification(buzz_url, buzz_token, buzz_b2b_chat_id, text, rep_statistics=False)
                            sync_id = res['result']['sync_id']
                        alert_open_id = sync_id or CURRENT_ATTACKS_ALL[genie_event['id']]['alert_open_id']
                        
                        text = beatify_alert_recovered(genie_event)         
                        send_notification(buzz_url, buzz_token, buzz_b2b_chat_id, text, alert_open_id, rep_statistics=False)
                    except Exception as e: logger.error(e)
                    CURRENT_ATTACKS_ALL.pop(genie_event['id'], None)

                case 'Ongoing':
                    if (genie_event['id'] in CURRENT_ATTACKS_ALL and CURRENT_ATTACKS_ALL[genie_event['id']]['alert_criteria'] == False) or \
                        genie_event['id'] not in CURRENT_ATTACKS_ALL:                        
                        try:
                            text = beatify_alert_open(genie_event)  
                            res = send_notification(buzz_url, buzz_token, buzz_b2b_chat_id, text, rep_statistics=False)
                            sync_id = res['result']['sync_id']
                            CURRENT_ATTACKS_ALL[genie_event['id']] = {'alert_criteria': True, 'alert_open_id': sync_id}
                        except Exception as e: logger.error(e)
                        
        else: # Home/Non-Home/Not Inbound, < 1GB
            match(genie_event['status']):
                case 'Open':
                    CURRENT_ATTACKS_ALL[genie_event['id']] = {'alert_criteria': False, 'alert_open_id': None}

                case 'Recovered':
                    if genie_event['id'] in CURRENT_ATTACKS_ALL and CURRENT_ATTACKS_ALL[genie_event['id']]['alert_criteria'] == True:
                        try:
                            text = beatify_alert_recovered(genie_event)        
                            send_notification(buzz_url, buzz_token, buzz_b2b_chat_id, text, CURRENT_ATTACKS_ALL[genie_event['id']]['alert_open_id'], rep_statistics=False)
                        except Exception as e: logger.error(e)
                    CURRENT_ATTACKS_ALL.pop(genie_event['id'], None)

                case 'Ongoing':
                    if genie_event['id'] not in CURRENT_ATTACKS_ALL:
                        CURRENT_ATTACKS_ALL[genie_event['id']] = {'alert_criteria': False, 'alert_open_id': None}
    #########################################################################################
    #########################################################################################

    return Response(status=200)
    

def get_stats_template():
    return {'start': time.time(), 'attacks_started': 0, 'attacks_ended': 0}

from datetime import datetime
import time
import threading
stats_state_lock = threading.Lock()

def scheduler():
    while True:
        now = datetime.now()
        if (now.hour == 9 and now.minute == 0):
            daily = query_for_stats(daily=True, weekly=False)
            stat_report_day(*daily[0])
            
            if (now.weekday() == 3):
                weekly = query_for_stats(daily=False, weekly=True)
                stat_report_week(*weekly[0])
                
            time.sleep(61)
        time.sleep(30)


@app.route('/genie_command', methods=['POST'])
def handle_genie_bot_commands():
    return handle_buzz_bot_commands()

@app.route('/genie_wh', methods=['POST'])
def handle_genie_event():
    return return_response()


if __name__ == "__main__":
    import os, threading
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        t = threading.Thread(target=scheduler, daemon=True)
        t.start()

    app.run(host="0.0.0.0", port=6000, debug=True)

