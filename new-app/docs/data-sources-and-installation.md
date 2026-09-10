# Alert Centre: реальные источники данных и установка

## 1. Что изменено

Новый backend больше не использует демонстрационные `_SAMPLE_ALERTS`. Данные разделены по источникам:

- `alerts.db` (SQLite) — текущее состояние алертов;
- `mitigations.db` (SQLite) — текущее состояние mitigations;
- ClickHouse — история mitigations, Genie events и агрегированные метрики;
- frontend — только REST API `/api/v1/*`, без прямого доступа к БД.

Архитектура: `React -> FastAPI -> adapters -> SQLite / ClickHouse`.

## 2. Требуемые компоненты

Для Debian 12/13 нужны: Python 3.12+, `python3-venv`, `python3-pip`, `sqlite3`, Docker/Compose (опционально), ClickHouse Server и ClickHouse Client.

SQLite является файловой БД и не требует отдельного сервиса. ClickHouse запускается как системный сервис либо как Docker-контейнер.

## 3. Установка SQLite

```bash
apt update
apt install -y sqlite3 libsqlite3-dev
sqlite3 --version
python3 -c "import sqlite3; print(sqlite3.sqlite_version)"
```

Создайте каталог данных:

```bash
mkdir -p /opt/alert-centr/new-app/data
```

Если у вас уже есть рабочие `alerts.db`, `mitigations.db` и `kuma_status.db`, скопируйте их в этот каталог вместо создания пустых БД.

## 4. Схема alerts.db

```sql
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS alerts (
  UID INTEGER PRIMARY KEY,
  TARGET_CIDR TEXT NOT NULL,
  TARGET_NETWORK_INT INTEGER,
  TARGET_BROADCAST_INT INTEGER,
  START_TIME TEXT NOT NULL,
  END_TIME TEXT,
  MAX_BPS INTEGER DEFAULT 0,
  CURRENT_MAX_BPS INTEGER DEFAULT 0,
  LEVEL INTEGER DEFAULT 3,
  WAF_BLOCKS INTEGER DEFAULT 0,
  DP_BLOCKS INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_start_time ON alerts(START_TIME);
CREATE INDEX IF NOT EXISTS idx_alerts_end_time ON alerts(END_TIME);
```

## 5. Схема mitigations.db

```sql
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS mitigations (
  TARGET_CIDR TEXT PRIMARY KEY,
  TARGET_NETWORK_INT INTEGER NOT NULL,
  TARGET_BROADCAST_INT INTEGER NOT NULL,
  CURRENT_MITIGATION TEXT,
  UPDATE_TIME_UNIX INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mitigations_range
ON mitigations(TARGET_NETWORK_INT, TARGET_BROADCAST_INT);
```

## 6. Установка ClickHouse на Debian

```bash
apt update
apt install -y ca-certificates curl gnupg apt-transport-https
curl -fsSL https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key \
  | gpg --dearmor > /usr/share/keyrings/clickhouse-keyring.gpg
ARCH=$(dpkg --print-architecture)
echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=${ARCH}] https://packages.clickhouse.com/deb stable main" \
  > /etc/apt/sources.list.d/clickhouse.list
apt update
apt install -y clickhouse-server clickhouse-client
systemctl enable --now clickhouse-server
clickhouse-client --query "SELECT version()"
```

## 7. Подготовка ClickHouse

```sql
CREATE DATABASE IF NOT EXISTS alert_center;

CREATE TABLE IF NOT EXISTS alert_center.genie_events (
  ID UInt64,
  STATUS LowCardinality(String),
  UPDATE_TIME DateTime,
  START_TIME DateTime,
  END_TIME Nullable(DateTime),
  MAX_BPS UInt64,
  MAX_PPS UInt64,
  RESOURCE Array(String),
  TARGET_NETWORK IPv4,
  TARGET_BROADCAST IPv4
)
ENGINE = ReplacingMergeTree(UPDATE_TIME)
ORDER BY ID;

CREATE TABLE IF NOT EXISTS alert_center.mitigations_events (
  TARGET_CIDR String,
  CURRENT_MITIGATION Nullable(String),
  UPDATE_TIME DateTime
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(UPDATE_TIME)
ORDER BY (TARGET_CIDR, UPDATE_TIME);

CREATE TABLE IF NOT EXISTS alert_center.kuma_events (
  TARGET_IP IPv4,
  STATUS LowCardinality(String),
  UPDATE_TIME DateTime
)
ENGINE = ReplacingMergeTree(UPDATE_TIME)
ORDER BY (TARGET_IP, UPDATE_TIME);
```

Создайте отдельного пользователя приложения:

```sql
CREATE USER IF NOT EXISTS alert_center
IDENTIFIED WITH sha256_password BY 'CHANGE_THIS_PASSWORD';
GRANT SELECT, INSERT ON alert_center.* TO alert_center;
```

## 8. Переменные окружения

Скопируйте `.env.example` в `.env` и задайте реальные значения:

```env
ALERTS_DB_PATH=/app/data/alerts.db
MITIGATIONS_DB_PATH=/app/data/mitigations.db
KUMA_STATUS_DB_PATH=/app/data/kuma_status.db
CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=alert_center
CLICKHOUSE_PASSWORD=CHANGE_THIS_PASSWORD
CLICKHOUSE_DATABASE=alert_center
VITE_API_URL=http://localhost:8000/api/v1
```

Не коммитьте реальные пароли в Git.

## 9. Установка backend без Docker

```bash
cd new-app/backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Проверка:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/alerts
curl http://127.0.0.1:8000/api/v1/mitigations
curl "http://127.0.0.1:8000/api/v1/mitigations/history?days=7"
curl "http://127.0.0.1:8000/api/v1/metrics/summary"
```

Swagger: `http://127.0.0.1:8000/docs`.

## 10. Frontend

```bash
cd new-app/frontend
npm install
npm run dev
```

Frontend получает алерты из `/api/v1/alerts` и обновляет их каждые 30 секунд. Переключатель темы находится в правой части заголовка. Выбор `light/dark` хранится в `localStorage`; при первом запуске используется системная тема браузера.

## 11. Docker Compose

```bash
cd new-app
cp .env.example .env
# отредактируйте .env
docker compose up --build -d
```

Frontend: `http://localhost:8080`, backend: `http://localhost:8000`, Swagger: `http://localhost:8000/docs`.

При использовании внешнего ClickHouse задайте его DNS/IP в `CLICKHOUSE_HOST`. При использовании локальных SQLite-файлов убедитесь, что они находятся в `new-app/data`, потому что каталог монтируется в контейнер как `/app/data`.

## 12. Миграция со старого data_fetcher.py

Старый `services/data_fetcher.py` пока остаётся источником эталонной бизнес-логики. Новые адаптеры переносятся по доменам, а не копированием файла целиком:

- `app/adapters/alerts.py` — SQLite alerts;
- `app/adapters/mitigations.py` — SQLite current state + ClickHouse history;
- `app/adapters/metrics.py` — ClickHouse aggregates;
- последующие адаптеры: KUMA, Genie, WAF/DP и OpenSearch.

После проверки функционального паритета соответствующие вызовы из Dash можно отключать по одному. Это снижает риск одновременной миграции UI, API и ingest-процессов.

## 13. Основные изменения относительно старого кода

1. Удалены mock-алерты из FastAPI.
2. SQL-параметры для UID передаются через bind-параметр вместо f-string.
3. Подключения к БД вынесены из endpoint-логики.
4. SQLite включён в WAL-режим и получает `busy_timeout=10000`.
5. ClickHouse client создаётся централизованно.
6. Метрики агрегируются в ClickHouse, а не на frontend.
7. Frontend работает только через REST API.
8. Добавлены светлая и тёмная темы с сохранением пользовательского выбора.
9. Frontend автоматически повторно получает live alerts каждые 30 секунд.

## 14. Что проверить перед production

- соответствие схем реальных SQLite-файлов приведённым колонкам;
- доступ backend к ClickHouse по HTTP-порту 8123;
- timezone старых данных (`START_TIME`, `END_TIME`, `UPDATE_TIME`);
- права пользователя ClickHouse;
- резервное копирование SQLite и ClickHouse;
- TLS/reverse proxy перед публикацией API;
- секреты только через `.env`/secret manager;
- добавление authentication/authorization до внешней публикации.
