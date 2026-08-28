import configparser
import os

import clickhouse_connect

config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), '..', 'alert_center.conf'))

CLICKHOUSE_HOST = config.get('CLICKHOUSE', 'HOST')
CLICKHOUSE_PORT = config.getint('CLICKHOUSE', 'PORT')
CLICKHOUSE_USER = config.get('CLICKHOUSE', 'USER')
CLICKHOUSE_DATABASE = config.get('CLICKHOUSE', 'DATABASE')
clickhouse_client = clickhouse_connect.get_client(host=CLICKHOUSE_HOST, port=CLICKHOUSE_PORT, user=CLICKHOUSE_USER, database=CLICKHOUSE_DATABASE)


def print_rows(header, rows, col_names):
    print(f"\n--- {header} ---")
    print(' | '.join(col_names))
    for r in rows:
        print(' | '.join(str(x) for x in r))


def main():
    print("=== alert_center.mitigations_events ===")

    try:
        total = clickhouse_client.query("SELECT count() FROM alert_center.mitigations_events").result_rows
        print(f"Total rows: {total[0][0]}")
    except Exception as e:
        print("Could not query alert_center.mitigations_events.")
        print("Hint: uncomment recreate_mitigations_events() in ingests/as_routing_data_ingest.py and run the module once to create the table.")
        print("Error:")
        print(e)
        return

    rows = clickhouse_client.query(
        "SELECT TARGET_CIDR, CURRENT_MITIGATION, UPDATE_TIME "
        "FROM alert_center.mitigations_events "
        "ORDER BY UPDATE_TIME DESC LIMIT 20"
    ).result_rows
    print_rows("Latest 20 events", rows, ["TARGET_CIDR", "CURRENT_MITIGATION", "UPDATE_TIME"])

    rows = clickhouse_client.query(
        "SELECT TARGET_CIDR, count() AS changes "
        "FROM alert_center.mitigations_events "
        "GROUP BY TARGET_CIDR "
        "ORDER BY changes DESC LIMIT 10"
    ).result_rows
    print_rows("Top 10 most-changed CIDRs", rows, ["TARGET_CIDR", "changes"])

    rows = clickhouse_client.query(
        "SELECT TARGET_CIDR, argMax(CURRENT_MITIGATION, UPDATE_TIME) AS latest, max(UPDATE_TIME) AS last_seen "
        "FROM alert_center.mitigations_events "
        "GROUP BY TARGET_CIDR "
        "ORDER BY last_seen DESC LIMIT 30"
    ).result_rows
    print_rows("Latest state per CIDR", rows, ["TARGET_CIDR", "latest", "last_seen"])


if __name__ == '__main__':
    main()

