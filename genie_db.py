import clickhouse_connect
from datetime import datetime, timedelta, time as dt_time

client = clickhouse_connect.get_client(
    host='localhost',
    port=8123,
    user='default',
    database='alert_center',
)

def create_clickhouse_db():
    client.command('CREATE DATABASE IF NOT EXISTS alert_center')
    
    try:
        client.command('DROP TABLE alert_center.genie_events')
        client.command('DROP TABLE alert_center.bee_resources')
        client.command('DROP TABLE alert_center.genie_events_monitored_objects')
    except:
        pass#'''
    
    # ID:  generateUUIDv4()
    client.command('''
        CREATE TABLE IF NOT EXISTS alert_center.bee_resources (
            NETWORK IPv4,
            BROADCAST IPv4,
            NAME String,
            EXTRA String
        )  
        ENGINE =  MergeTree()
        PRIMARY KEY (NETWORK, BROADCAST)
    ''')
    
    """# IPv4CIDRToRange(toIPv4('192.168.5.2'), 16)
    client.command('''
        CREATE TABLE IF NOT EXISTS alert_center.bee_subnetworks (
            NAME String,
            NETWORK IPv4,
            BROADCAST IPv4
        )
        ENGINE =  MergeTree()
        PRIMARY KEY (NETWORK, BROADCAST)
    ''')"""
    
    '''
    
    '''
    
    # ? DateTime64
    client.command('''
        CREATE TABLE IF NOT EXISTS alert_center.genie_events (
            ID String,
            UPDATE_TIME DateTime('Europe/Moscow'),
            START_TIME DateTime('Europe/Moscow'),
            END_TIME Nullable(DateTime('Europe/Moscow')),
            MAX_BPS UInt64,
            MAX_PPS UInt64,
            RESOURCE Array(String),
            STATUS String,
            
            TARGET_NETWORK IPv4,
            TARGET_BROADCAST IPv4,
        ) 
        ENGINE =  ReplacingMergeTree
        ORDER BY ID
    ''') 
    #         PRIMARY KEY (ID)
#         ORDER BY (ID, START_TIME, TARGET_NETWORK, TARGET_BROADCAST, MAX_BPS, MAX_PPS)
#           PARTITION BY toYYYYMMDD(START_TIME)

    # FOREIGN KEY (TARGET_IP_FK IPv4) REFERENCES alert_center.bee_resources (IP) ON DELETE SET NULL
    # CONSTRAINT fk_bee_resources FOREIGN KEY (TARGET_IP) REFERENCES alert_center.bee_resources (IP) ON DELETE SET NULL


    
    """client.command('''
        CREATE alert_center.genie_events_monitored_objects (
            GENIE_EVENT_ID String,
            MONITORED_OBJECT_IP IPv4,
            PRIMARY KEY (GENIE_EVENT_ID, MONITORED_OBJECT_IP),
            FOREIGN KEY (GENIE_EVENT_ID) REFERENCES alert_center.genie_events (ID),
            FOREIGN KEY (MONITORED_OBJECT_IP) REFERENCES alert_center.bee_resources (IP);
        )
    ''')#"""

    print("ok")
    print(f"Server ver: {client.server_version}")



def overview():
    def run(q):
        return client.query(q).result_rows

    def print_table(rows):
        for r in rows:
            print(r)
    
    print("Genie Events:")
    print_table(run("SELECT * FROM alert_center.genie_events LIMIT 20"))

    print("Bee Resources:")
    print_table(run("SELECT * FROM alert_center.bee_resources LIMIT 5"))

    #print("Genie Events Monitored Objects:")
    #print_table(run("SELECT * FROM alert_center.genie_events_monitored_objects LIMIT 5"))


'''
SELECT 
    event_time, 
    'a' AS source, 
    event_type, 
    user_id, 
    extra1 AS payload_json, 
    NULL AS extra_b, 
    NULL AS extra_c
FROM a_system_events

UNION ALL

SELECT 
    event_time, 
    'b' AS source, 
    type AS event_type, 
    NULL AS user_id, 
    NULL AS payload_json, 
    detail AS extra_b, 
    NULL AS extra_c
FROM b_system_events

UNION ALL

SELECT 
    event_time, 
    'c' AS source, 
    name AS event_type, 
    actor_id AS user_id, 
    NULL AS payload_json, 
    NULL AS extra_b, 
    info AS extra_c
FROM c_system_events

ORDER BY event_time DESC
LIMIT 1000

'''
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
            top_attack_today = [None, None, None]
            
        retval.append([attacks_started_today, attacks_ended_today, total_attacks_today, top_attack_today])  
        
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
        
        retval.append([attacks_started_week, attacks_ended_week, total_attacks_week, top_attack_week])
    return retval


def insert_genie_test_data():
    test_event = {
        'id': 'A217367',
        'traffic': {
            'max_value_bps': 1000,
            'max_value_pps': 5000
        },
        'resource': [{'name': 'test_resource'}],
        'status': 'Open',
        'ip': '192.168.1.1',
        'datetime': {
            'start_time': '2026-01-01 11:11:11',
            'end_time': '2026-02-02 22:22:22'
        }
    }
    
    test_event = {'status': 'Ongoing', 
            'direction': 'To Home', 
            'resource': [{'type': 'Sub-Network', 'name': 'WestCall - 20Gbit ID-4959365 wc6454101730'}, 
                        {'type': 'Sub-Network', 'name': 'WestCall - 20Gbit ID-4959365 wc1831151667'}], 
            'severity': {'threshold_value': 7000000.0, 'watermark': 'over', 
                        'max_value': 18778533.333333332, 'counter': 'bps', 'current_value': 3804400.0, 
                        'type': 'yellow', 'detected_value': 9119866.666666666}, 
            'ip': '81.94.129.0/24', 
            'datetime': {'duration': 493, 'start_time': '2026-03-12 16:43:17'}, 
            'attack': [{'counter': 'bps', 'type': 'DDOS', 'name': 'UDP Flooding'}], 
            'traffic': {'current_value_bps': 3804400.0, 'max_value_bps': 18778533.333333332, 
                        'current_value_pps': 333.3333333333333, 'max_value_pps': 1683.3333333333333},
            'attack_direction': 'Inbound', 
            'id': 'A854482'}



    a = {'traffic_characteristics': [], 
     'event': {'status': 'Open', 'direction': 'To Home', 
               'resource': [{'type': 'Home Scope', 'name': 'Home'}],
               'severity': {'threshold_value': 400000000.0, 'watermark': 'over', 'max_value': 463438666.6666667, 'counter': 'bps', 'current_value': 463438666.6666667, 'type': 'yellow', 'detected_value': 463438666.6666667},
                'ip': '66.90.90.98', 'datetime': {'duration': 1, 'start_time': '2026-03-05 17:04:00'}, 'attack': [{'counter': 'bps', 'type': 'DDOS', 'name': 'UDP Flooding'}], 'traffic': {'current_value_bps': 463438666.6666667, 'max_value_bps': 463438666.6666667, 'current_value_pps': 47566.666666666664, 'max_value_pps': 47566.666666666664}, 'attack_direction': 'Inbound', 'id': 'A845888'}}
    b = {'traffic_characteristics': [], 
     'event': {'status': 'Open', 'direction': 'To Home', 
               'resource': [{'type': 'Sub-Network', 'name': 'Agroliga ID-3296934'}], 
               'severity': {'threshold_value': 140000000.0, 'watermark': 'over', 'max_value': 223286533.33333334, 'counter': 'bps', 'current_value': 223286533.33333334, 'type': 'yellow', 'detected_value': 223286533.33333334},
                'ip': '87.229.210.14', 'datetime': {'duration': 1, 'start_time': '2026-03-05 17:04:00'}, 'attack': [{'counter': 'bps', 'type': 'DDOS', 'name': 'UDP Flooding'}], 'traffic': {'current_value_bps': 223286533.33333334, 'max_value_bps': 223286533.33333334, 'current_value_pps': 19266.666666666668, 'max_value_pps': 19266.666666666668}, 'attack_direction': 'Inbound', 'id': 'A845887'}}
    c = {'traffic_characteristics': [],
     'event': {'status': 'Recovered', 'direction': 'To Home',
               'resource': [{'type': 'Sub-Network', 'name': 'Экпресс прачечная ID-3729175'}], 
               'severity': {'threshold_value': 7000000.0, 'watermark': 'over', 'max_value': 7257600.0, 'counter': 'bps', 'current_value': 0.0, 'type': 'yellow', 'detected_value': 7257600.0}, 
               'ip': '194.186.204.210', 'datetime': {'duration': 60, 'start_time': '2026-03-05 17:03:00', 'end_time': '2026-03-05 17:04:00'}, 'attack': [{'counter': 'bps', 'type': 'DDOS', 'name': 'UDP Flooding'}], 'traffic': {'current_value_bps': 0.0, 'max_value_bps': 7257600.0, 'current_value_pps': 0.0, 'max_value_pps': 700.0}, 'attack_direction': 'Inbound', 'id': 'A845886'}}
    events = [a['event'], b['event'], c['event']]

    end_time = 0
    if test_event['status'] == 'Recovered':
        end_time = test_event['datetime']['end_time']
    
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    import ipaddress
    a = ipaddress.ip_network(test_event['ip'], strict=False)
    client.command(f"""INSERT INTO genie_events VALUES 
    (
        '{test_event['id']}', 
        toDateTime('{now}'),
        toDateTime('{test_event['datetime']['start_time']}'), toDateTime('{end_time}'), 
        {test_event['traffic']['max_value_bps']}, {test_event['traffic']['max_value_pps']}, 
        {[r['name'] for r in test_event['resource']]}, 
        '{test_event['status']}',        
        '{a.network_address}', '{a.broadcast_address}'
    )
    """)
    
    for event in events:
        if event['status'] == 'Recovered':
            end_time = event['datetime']['end_time']
        a = ipaddress.ip_network(event['ip'], strict=False)
        client.command(f"""INSERT INTO genie_events VALUES 
        (
            '{event['id']}', 
            toDateTime('{now}'),
            toDateTime('{event['datetime']['start_time']}'), toDateTime('{end_time}'), 
            {event['traffic']['max_value_bps']}, {event['traffic']['max_value_pps']}, 
            {[r['name'] for r in event['resource']]}, 
            '{event['status']}',        
            '{a.network_address}', '{a.broadcast_address}'
        )
        """)



create_clickhouse_db()
#insert_genie_test_data()
overview()
print(query_for_stats())


