import clickhouse_connect
from datetime import datetime, timedelta, time as dt_time

client = clickhouse_connect.get_client(
    host='localhost',
    port=8123,
    user='default',
    database='alert_center',
)
def iso_now_utc():
    return datetime.now().replace(microsecond=0)
def default_last_hour():
    end = datetime.now().replace(microsecond=0)#)
    start = end - timedelta(hours=1)
    return start, end
def time_filter_sql(start_iso=None, end_iso=None):
    if start_iso and end_iso:
        return f"WHERE UPDATE_TIME >= toDateTime('{start_iso}') AND UPDATE_TIME <= toDateTime('{end_iso}')"
    elif start_iso:
        return f"WHERE UPDATE_TIME >= toDateTime('{start_iso}')"
    elif end_iso:
        return f"WHERE UPDATE_TIME <= toDateTime('{end_iso}')"
    else:
        s, e = default_last_hour()
        return f"WHERE UPDATE_TIME >= toDateTime('{s}')"# AND UPDATE_TIME <= toDateTime('{e}')"

now_iso = iso_now_utc()
s = (datetime.now().replace(microsecond=0)-timedelta(hours=24)); e = now_iso
start, end = s, e
tf = time_filter_sql()


unique_id_condition = '''
(ID, UPDATE_TIME) IN (
    SELECT ID, MAX(UPDATE_TIME) as UPDATE_TIME
    FROM genie_events
    GROUP BY ID
)
'''

genie_rows = client.query(f"""
SELECT ID, STATUS, UPDATE_TIME, START_TIME, END_TIME, MAX_BPS, MAX_PPS, RESOURCE, TARGET_NETWORK, TARGET_BROADCAST
FROM genie_events
WHERE {unique_id_condition} AND UPDATE_TIME >= toDateTime('{s}') AND (STATUS = 'Ongoing' OR STATUS = 'Open' OR STATUS = 'New')
""").result_rows

for r in genie_rows[::-1][:5]:
    print(f"{r[0]}:\n \
Status: {r[1]}\n \
Last update: {r[2]}\n \
Start:End: {r[3]}->{r[4]}\n \
Max BPS: {r[5]}\n \
Max PPS: {r[6]}\n \
Resource: {r[7]}\n \
Target Network: {r[8]}\n \
Target Broadcast: {r[9]}\n-----------------------------") 

