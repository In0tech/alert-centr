r"""
MSSQL connectivity test + Remedy / CRQ ticket access cheat sheet.

Target (from alert_center.conf [MSSQL]):
    Server:   SQL0101HA013\SQL101   (real name: MS-SQLHACLS013, resolves to 172.21.224.36)
    Database: SMP
    Login:    Tech_CRQ524935        (ТУЗ provisioned for CRQ ticket access)
    SQL Server 2016 (SP2-CU6) Enterprise, 13.0.5292.0, on Windows Server 2012 R2.

Connection requirements
-----------------------
1. pymssql (in requirements.txt). Bundled FreeTDS 1.4.x on Windows.
2. freetds.conf at project root MUST set `encryption = off` for this server.
   Otherwise FreeTDS sends a TLS ClientHello after TDS pre-login that the
   corporate firewall/DPI silently drops, and pymssql hangs forever
   (login_timeout is not honoured by this Windows build). Server signals
   ENCRYPT_OFF so disabling TLS is allowed.
3. This module sets FREETDSCONF env var to <project>/freetds.conf before
   importing pymssql — any other MSSQL client module should do the same.
4. SQL Browser (UDP 1434) confirmed reachable; instance SQL101 listens on
   TCP 1433 (verified via SQL Browser response). Named instance resolution
   works, but we connect via the freetds.conf [SQL0101HA013] section which
   hardcodes host=172.21.224.36 port=1433.

Remedy / CRQ ticket tables in SMP
---------------------------------
The Remedy "Request For Change" (RFC) ticket id format is `CRQ<number>`,
e.g. CRQ285693, CRQ391923. Confirmed locations of CRQ-format values:

  dbo.OP_Request                  (15.7M rows, 128 cols) — main TT (trouble ticket) table.
      `Number`          int       — internal TT id (e.g. 40098089)
      `Number_EXT_ORG`  varchar   — **CRQ tickets land here** when a TT was
                                    opened from / linked to a Remedy ticket.
                                    Confirmed values: CRQ285693, CRQ299528,
                                    CRQ391923, CRQ421280. NOTE: column can
                                    contain multi-line lists, e.g.
                                    'CRQ391923\\nCRQ391923' — split on '\\n'
                                    and dedupe when parsing.
      `Number_RFC`      varchar   — RFC column exists but is empty in this DB.
      `ShortDescription`, `Status`, `DateCreate`, `DateClose`, `Priority`,
      `FIOAssigned`, `Branch`, `SuperRegion`, `DITProduct`, `ITService`,
      `Description`, `ResumeInc`, `CauseTT`, `GroupeCause` — ticket metadata.
      `RequestType`    int        — see dbo.DIC_TypeTT for code mapping
                                    (TTclient / TTintUser / TTnet).
      Other "external number" columns (Number_ACRM, Number_1C, NUMBER_MTS,
      NUMBER_MEGAFON, Number_TTMS, NetCool_TT_ID, Number_Defect) — probed,
      none contain CRQ-format values.

  dbo.OP_Request_ARC              — archive of OP_Request (same schema).
  dbo.OP_Request_Kafka            — Kafka-fed staging copy.
  dbo.OP_Request_Queue_New        — pending queue.

  dbo.REMEDY_RIGA                  (100,495 rows) — single-column table
      `NumberTT`       int        — TT integer id of tickets that originated
                                    in / are tracked by Remedy Riga. Use as a
                                    filter set: join on OP_Request.Number to
                                    restrict to Remedy-originated tickets.

  dbo.ELK_Index                    — small ref table mapping ELK indices.
      `CRQ`            nvarchar   — lowercase CRQ ids, e.g. 'crq160996',
                                    'crq129805'. Maps an ELK index/Pipeline
                                    to its owning Remedy change ticket.

  dbo.Inside_Prometheus_2         — Prometheus monitoring host registry.
      `CRQ`            varchar    — proper-case CRQ ids, e.g. 'CRQ156672_',
                                    'CRQ128936_2'. Suffix `_N` denotes a
                                    sub-ticket / re-occurrence of the same
                                    CRQ. Other cols: IP, Host, Port, Metrics.

  dbo.1C_Retail                    — 1C retail integration table.
      `Number_Remedy`  varchar    — Remedy-side numeric ids, but stored as
                                    zero-padded 9-digit strings
                                    ('000002209', '000002210') — NOT in CRQ
                                    format. Likely the Remedy Request ID
                                    (internal) rather than the CRQ display id.

  dbo.DIC_TypeTT                   (3 rows) — TT type dictionary:
      TTclient  = Клиентский
      TTintUser = Внутренний пользователь
      TTnet     = Сетевой

  dbo.TTMS_V_*  (~17 views)        — TTMS dimension views (Cause, Classifier,
                                    Employee, Coordinator, Status, Priority,
                                    Region, Filial, Orgstructure, Work_Time,
                                    Type_TT, ...). Join via TTMS_OWNER /
                                    EMPNUM_* / CODE_OS_* columns on OP_Request.

  V_RFC_*_OP_REQUEST               — 4 pre-built RFC views on OP_Request
                                    (one per CRQ-based formal request):
                                    V_RFC_332577_14_OIB_Request(_ALL/_TEMP),
                                    V_RFC_424693_16_OP_REQUEST,
                                    V_RFC_456857_16_OP_REQUEST,
                                    V_RFC_486534_17_OP_REQUEST.

Sample queries
--------------
# All TTs linked to a specific CRQ:
SELECT Number, ShortDescription, Status, DateCreate, DateClose,
       FIOAssigned, Branch, SuperRegion, Priority
FROM dbo.OP_Request WITH (NOLOCK)
WHERE Number_EXT_ORG LIKE '%CRQ391923%'
ORDER BY DateCreate DESC;

# All CRQ ids referenced by Remedy-originated tickets:
SELECT DISTINCT o.Number_EXT_ORG
FROM dbo.REMEDY_RIGA r
JOIN dbo.OP_Request o WITH (NOLOCK) ON o.Number = r.NumberTT
WHERE o.Number_EXT_ORG LIKE 'CRQ%';

# Prometheus hosts grouped by owning CRQ:
SELECT CRQ, COUNT(*) AS host_count
FROM dbo.Inside_Prometheus_2 WITH (NOLOCK)
WHERE CRQ IS NOT NULL AND CRQ <> ''
GROUP BY CRQ
ORDER BY host_count DESC;

Performance notes
-----------------
- ALWAYS use `WITH (NOLOCK)` (or wrap reads in a READ UNCOMMITTED txn).
  OP_Request has 15.7M rows; plain SELECTs without NOLOCK will block on
  writers and time out.
- Do NOT run COUNT(*) or `ORDER BY ... DESC` over LIKE 'CRQ%' filters
  without an index on Number_EXT_ORG — confirmed they time out (>5 min).
  Use TOP N + app-side pagination instead.
- Indexes present on OP_Request (SQL Server 2016): clustered PK on (Number),
  nonclustered on DateCreate, on Number, on
  (Code_TypeBus, RegistrationIn, SourceClime), on
  (EMPNUM_INITIATOR, DateCreate). **Number_EXT_ORG is NOT indexed** — any
  LIKE '%...%' / LIKE 'CRQ...%' filter on it forces a 15.7M-row scan and
  hangs >30s. To search by CRQ, restrict by DateCreate range first, then
  apply the LIKE; even so, plan for multi-second responses.
- Avoid `SELECT *` on OP_Request (128 columns, several TEXT fields up to
  2GB each). Always project explicit columns.

CRQ524935 search results (do NOT repeat — already exhausted)
------------------------------------------------------------
CRQ524935 (the ticket that authorised creating the Tech_CRQ524935 ТУЗ)
is NOT in this SMP database. Confirmed absent from:
  - dbo.ELK_Index.CRQ                       (0 rows, instant scan)
  - dbo.Inside_Prometheus_2.CRQ             (0 rows, instant scan)
  - dbo.OP_Request WHERE Number = 524935    (0 rows, 0.1s indexed seek)
  - dbo.OP_Request.Number_RFC               (column is empty in this DB)
  - dbo.OP_Request.Number_EXT_ORG           (cannot fully scan — no index,
                                            15.7M rows; only the coincidental
                                            substring '30524935' exists in
                                            dbo.1C_Retail.Number_Remedy, which
                                            is an unrelated Remedy Request ID)
Reason: this SMP MSSQL is the **TTMS** (Trouble Ticket Management System),
an internal trouble-ticket operational DB — NOT Remedy ARSystem / SmartIT.
CRQ change tickets are filed in the real BMC Remedy ARSystem server
(database `BMC.ARSYSTEM`, form `Change_Request`), hosted elsewhere.
SMP only carries CRQ IDs as cross-references in OP_Request.Number_EXT_ORG
when an internal TT was linked to a Remedy change. The ТУЗ naming
convention `Tech_CRQ<N>` records the authorising CRQ id, but the CRQ data
itself is not replicated here.

Schema overview
---------------
Schemas present: dbo (514 tables), VIMPELCOM_MAIN\YuNudelman (12),
cdc (11 — Change Data Capture metadata, not user data), Inside (1).
All Remedy/CRQ content is in the `dbo` schema.
"""

import os
import tempfile

import pymssql


# FreeTDS config hardcoded here so there is no external freetds.conf to import.
# Required because the bundled FreeTDS defaults to TLS login, but a corporate
# firewall/DPI silently drops the TLS handshake to SQL0101HA013 — causing
# pymssql to hang indefinitely. SQL Server signals ENCRYPT_OFF (encryption
# optional) so disabling it is safe.
_FREETDS_CONF = """\
[global]
\ttds version = 7.4
\tencryption = off

[SQL0101HA013]
\thost = 172.21.224.36
\tport = 1433
\ttds version = 7.4
\tencryption = off
"""

_FREETDS_CONF_PATH = os.path.join(tempfile.gettempdir(), 'alert_center_freetds.conf')
with open(_FREETDS_CONF_PATH, 'w', encoding='ascii') as _f:
    _f.write(_FREETDS_CONF)

os.environ['FREETDSCONF'] = _FREETDS_CONF_PATH

# MSSQL connection parameters hardcoded — no config file needed.
MSSQL_SERVER = 'SQL0101HA013\\SQL101'
MSSQL_DATABASE = 'SMP'
MSSQL_USER = 'Tech_CRQ524935'
MSSQL_PASSWORD = '3MDg*wio@6gTUjS@^F)B'


def connect():
    return pymssql.connect(
        server=MSSQL_SERVER,
        database=MSSQL_DATABASE,
        user=MSSQL_USER,
        password=MSSQL_PASSWORD,
        tds_version='7.4',
        as_dict=True,
    )


if __name__ == '__main__':
    conn = None
    try:
        print(f'Connecting to {MSSQL_SERVER} / {MSSQL_DATABASE} as {MSSQL_USER} ...')
        conn = connect()
        print('Connected.\n')

        with conn.cursor() as cur:
            cur.execute('SELECT @@VERSION AS version')
            row = cur.fetchone()
            print('@@VERSION:')
            print(row['version'] if row else '(no row)')
            print()

            cur.execute(
                'SELECT TOP 5 TABLE_NAME FROM INFORMATION_SCHEMA.TABLES '
                'ORDER BY TABLE_NAME'
            )
            rows = cur.fetchall()
            print('Top 5 tables in INFORMATION_SCHEMA.TABLES:')
            for r in rows:
                print(' -', r['TABLE_NAME'])
    except Exception as e:
        print(f'ERROR: {type(e).__name__}: {e}')
        raise
    finally:
        if conn is not None:
            conn.close()
            print('\nConnection closed.')

