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

## Основная инструкция по установке

Для серверной установки используйте:

[`docs/installation.md`](docs/installation.md)

В ней подробно описаны:

- получение и обновление `main` с Git;
- первоначальное клонирование приватного репозитория;
- SSH-доступ GitHub;
- подготовка Ubuntu 26.04 LTS (Resolute);
- установка Docker Engine и Docker Compose;
- отдельная установка Docker из России через зеркало официального Docker APT-репозитория Yandex;
- действия при недоступности Docker Hub и использование собственного/Yandex Container Registry;
- запуск всего приложения через Docker Compose;
- обновление и полная пересборка контейнеров после `git pull`;
- запуск backend без Docker;
- запуск frontend без Docker;
- установка и настройка SQLite без Docker;
- запуск и инициализация ClickHouse без Docker;
- systemd unit для FastAPI backend;
- Nginx для production frontend и проксирования `/api/`;
- проверка API, портов и логов;
- типовые ошибки и production checklist.

## Быстрый запуск Docker

Если Docker уже установлен:

```bash
cd /opt/alert-centr
git fetch origin
git checkout main
git pull origin main

cd new-app

# только при первом запуске
cp .env.example .env
nano .env

docker compose up --build -d
docker compose ps
```

После запуска:

- frontend: `http://SERVER_IP:8080`
- backend API: `http://SERVER_IP:8000`
- Swagger: `http://SERVER_IP:8000/docs`
- ClickHouse HTTP: `http://SERVER_IP:8123` (не рекомендуется публиковать наружу в production).

Проверка:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/alerts
curl http://127.0.0.1:8000/api/v1/mitigations
curl http://127.0.0.1:8000/api/v1/metrics/summary
```

## Обновление существующего сервера

Обычный вариант:

```bash
cd /opt/alert-centr
git checkout main
git pull origin main

cd new-app
docker compose down
docker compose build --no-cache
docker compose up -d
docker compose ps
```

Если сервер должен полностью соответствовать Git и локальные изменения не нужны:

```bash
cd /opt/alert-centr
git fetch origin
git checkout main
git reset --hard origin/main
```

> `git reset --hard` удаляет незакоммиченные локальные изменения.

Если `.env` уже настроен, не выполняйте повторно `cp .env.example .env` — иначе вы перезапишете локальные секреты и адреса БД.

## Подготовка реальных SQLite БД

Поместите существующие рабочие файлы в `new-app/data/`:

```text
data/
├── alerts.db
├── mitigations.db
└── kuma_status.db
```

Backend в Docker видит этот каталог как `/app/data`.

Если файлов ещё нет, схемы и команды создания приведены в [`docs/data-sources-and-installation.md`](docs/data-sources-and-installation.md).

## Установка без Docker

Полная последовательность для Ubuntu 26.04 приведена в [`docs/installation.md`](docs/installation.md).

Кратко backend:

```bash
cd /opt/alert-centr/new-app/backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Кратко frontend:

```bash
cd /opt/alert-centr/new-app/frontend
npm install
VITE_API_URL=http://SERVER_IP:8000/api/v1 npm run build
```

Для production готовую `frontend/dist/` рекомендуется отдавать через Nginx.

## Документация

- [`docs/installation.md`](docs/installation.md) — установка, обновление, Ubuntu 26.04, Docker, Docker из России, manual deployment, systemd/Nginx и troubleshooting;
- [`docs/data-sources-and-installation.md`](docs/data-sources-and-installation.md) — SQLite/ClickHouse, структуры таблиц, миграция `services/data_fetcher.py`, адаптеры и источники данных;
- [`docs/architecture.md`](docs/architecture.md) — новая архитектура frontend/backend.

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
