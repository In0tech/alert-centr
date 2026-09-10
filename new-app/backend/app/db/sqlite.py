import sqlite3
from contextlib import contextmanager
from collections.abc import Iterator


@contextmanager
def sqlite_connection(path: str) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(path, timeout=10, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
    finally:
        connection.close()
