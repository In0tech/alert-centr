# Alert Centre New

Новая архитектура Alert Centre с раздельными frontend и backend.

## Что входит

- `backend/` — FastAPI REST API и адаптеры к реальным SQLite/ClickHouse источникам;
- `frontend/` — React + TypeScript интерфейс на основе `design-front-alert-centre-proto`;
- `docs/` — архитектура, миграция и подробные инструкции по установке;
- `docker-compose.yml` — локальный запуск frontend/backend и ClickHouse;
- `.env.example` — полный список параметров окружения.

## Реальные источники данных

Backend больше не использует `_SAMPLE_ALERTS`.

- SQLite `alerts.db` — активные и завершённые алерты;
- SQLite `mitigations.db` — текущее состояние mitigations;
- ClickHouse `mitigations_events` — история изменений защиты;
- ClickHouse `genie_events` — события атак и источник агрегированных метрик.

Доступные API:

- `GET /api/v1/alerts`
- `GET /api/v1/alerts/{uid}`
- `GET /api/v1/mitigations`
- `GET /api/v1/mitigations/history?days=7`
- `GET /api/v1/metrics/summary`
- `GET /health`

Swagger: `http://localhost:8000/docs`.

## Темы frontend

Frontend поддерживает `dark` и `light` темы. Переключатель расположен в заголовке. Выбор сохраняется в `localStorage`; при первом запуске используется системная тема браузера. Дизайн сохраняет структуру и визуальный язык предоставленного прототипа Alert Centre.

## Быстрый запуск Docker

```bash
cd new-app
cp .env.example .env
# обязательно измените CLICKHOUSE_PASSWORD и APP_SECRET_KEY
docker compose up --build -d
```

После запуска:

- frontend: `http://localhost:8080`
- backend API: `http://localhost:8000`
- Swagger: `http://localhost:8000/docs`
- ClickHouse HTTP: `http://localhost:8123`

## Подготовка реальных SQLite БД

Поместите существующие рабочие файлы в `new-app/data/`:

```text
data/
├── alerts.db
├── mitigations.db
└── kuma_status.db
```

Backend видит этот каталог как `/app/data`.

Если файлов ещё нет, схемы и команды создания приведены в `docs/data-sources-and-installation.md`.

## Установка без Docker

Для backend:

```bash
cd new-app/backend
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Для frontend:

```bash
cd new-app/frontend
npm install
npm run dev
```

## Документация

Главная подробная инструкция: [`docs/data-sources-and-installation.md`](docs/data-sources-and-installation.md).

В ней описаны:

- установка SQLite;
- структура `alerts.db` и `mitigations.db`;
- установка ClickHouse на Debian;
- создание `genie_events`, `mitigations_events`, `kuma_events`;
- пользователь и права ClickHouse;
- переменные `.env`;
- запуск backend/frontend;
- Docker Compose;
- перенос функций из старого `services/data_fetcher.py`;
- различия старой и новой архитектуры;
- production checklist.

## Архитектура

```text
React frontend
      |
      | REST /api/v1
      v
FastAPI backend
      |
      +---- AlertsRepository ----------> SQLite alerts.db
      |
      +---- MitigationsRepository -----> SQLite mitigations.db
      |                    |
      |                    +-----------> ClickHouse mitigations_events
      |
      +---- MetricsRepository ----------> ClickHouse genie_events
```

Frontend не открывает базы напрямую. Все обращения к данным проходят через FastAPI.

## Следующие этапы миграции

Старое Flask/Dash приложение пока сохраняется как эталон функциональности. Следующие адаптеры для переноса: KUMA, Genie, WAF/DP, OpenSearch, Search и Reports. После достижения функционального паритета соответствующие Dash callbacks можно выводить из эксплуатации по одному.
