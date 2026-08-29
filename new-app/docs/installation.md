# Установка frontend и backend

## Вариант 1: Docker Compose

Требования: Docker Engine 24+ и Docker Compose v2.

```bash
git clone https://github.com/In0tech/alert-centr.git
cd alert-centr
git checkout refactor/alert-centr-new
cd new-app
cp .env.example .env
docker compose up --build -d
```

Проверка:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/api/v1/alerts
```

Frontend будет доступен на `http://localhost:8080`, Swagger — на `http://localhost:8000/docs`.

## Вариант 2: Backend без Docker

Требования: Python 3.12+.

```bash
cd new-app/backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

В Windows активация окружения выполняется командой:

```powershell
.venv\Scripts\Activate.ps1
```

## Вариант 3: Frontend без Docker

Требования: Node.js 22+.

```bash
cd new-app/frontend
npm install
VITE_API_URL=http://localhost:8000/api/v1 npm run dev
```

В PowerShell:

```powershell
$env:VITE_API_URL="http://localhost:8000/api/v1"
npm run dev
```

## Production

В production обязательно задайте уникальный `APP_SECRET_KEY`, ограниченный список `CORS_ORIGINS`, реальные DSN источников данных и HTTPS reverse proxy. Файл `.env` не должен попадать в Git.