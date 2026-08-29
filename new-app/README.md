# Alert Centre New

Новая архитектура Alert Centre с раздельными frontend и backend.

## Структура

- `backend/` — FastAPI REST API и адаптеры к существующим источникам данных.
- `frontend/` — React + TypeScript интерфейс на основе прототипа `design-front-alert-centre-proto`.
- `docs/` — архитектура, миграция и инструкции по установке.
- `docker-compose.yml` — локальный запуск полного приложения.

## Быстрый запуск

```bash
cp .env.example .env
docker compose up --build
```

После запуска:

- frontend: http://localhost:8080
- backend API: http://localhost:8000
- Swagger: http://localhost:8000/docs

## Статус миграции

Каркас новой архитектуры создан в ветке `refactor/alert-centr-new`. Старое приложение пока не удаляется: его сервисы будут переноситься поэтапно в `backend/app/integrations/legacy` и закрываться REST API.