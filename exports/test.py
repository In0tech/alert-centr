import sqlite3
import pandas as pd

DB_PATH = '/export/home/lvelueta/alert_center/dbs/mitigations.db'

def check_db_for_sbh(sqlite3_cursor: sqlite3.Cursor):
    sqlite3_cursor.execute('SELECT * FROM mitigations WHERE CURRENT_MITIGATION = "SBH"')
    sbh_rows = sqlite3_cursor.fetchall()
    if len(sbh_rows) > 0:
        sbh_df = pd.DataFrame(sbh_rows, columns=['TARGET_CIDR', 'TARGET_NETWORK', 'TARGET_BROADCAST', 'CURRENT_MITIGATION', 'UPDATE_TIME_UNIX'])
        return sbh_df
    return pd.DataFrame() 

cur = sqlite3.connect(DB_PATH).cursor()
print(check_db_for_sbh(cur ))
