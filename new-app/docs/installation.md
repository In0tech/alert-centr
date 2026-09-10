# Установка, обновление и запуск Alert Centre New

Инструкция предназначена для `new-app` в репозитории `In0tech/alert-centr` и рассчитана прежде всего на Ubuntu 26.04 LTS (Resolute). Описаны обновление проекта с Git, запуск через Docker Compose, ручная установка без Docker и отдельный сценарий установки Docker из России.

## 1. Получение новой версии с Git

Если репозиторий уже клонирован:

```bash
cd /opt/alert-centr

git status
git branch --show-current
git fetch origin
git checkout main
git pull origin main
```

Новая версия приложения находится в:

```text
/opt/alert-centr/new-app
```

Если на сервере есть локальные незакоммиченные изменения:

```bash
cd /opt/alert-centr
git stash
git pull origin main
git stash pop
```

Если локальные изменения не нужны и сервер должен в точности соответствовать `origin/main`:

```bash
cd /opt/alert-centr
git fetch origin
git checkout main
git reset --hard origin/main
```

> Внимание: `git reset --hard` удаляет незакоммиченные локальные изменения.

Если репозиторий ещё не клонирован:

```bash
cd /opt
git clone https://github.com/In0tech/alert-centr.git
cd alert-centr/new-app
```

Для приватного репозитория рекомендуется SSH-доступ:

```bash
ssh-keygen -t ed25519 -C "alert-centr-server"
cat ~/.ssh/id_ed25519.pub
```

Добавьте публичный ключ в GitHub, затем переключите remote:

```bash
cd /opt/alert-centr
git remote set-url origin git@github.com:In0tech/alert-centr.git
ssh -T git@github.com
git pull origin main
```

---

## 2. Подготовка Ubuntu 26.04 LTS

Проверка версии ОС:

```bash
cat /etc/os-release
uname -a
```

Обновление системы:

```bash
sudo apt update
sudo apt upgrade -y
```

Базовые пакеты:

```bash
sudo apt install -y \
  ca-certificates \
  curl \
  wget \
  gnupg \
  git \
  unzip \
  jq \
  sqlite3 \
  libsqlite3-dev \
  build-essential
```

---

# Вариант A. Запуск через Docker Compose

## 3. Установка Docker Engine на Ubuntu 26.04 — официальный репозиторий

Ubuntu 26.04 LTS (`resolute`) поддерживается Docker Engine официально.

Удалите конфликтующие пакеты, если они есть:

```bash
sudo apt remove -y docker.io docker-compose docker-compose-v2 docker-doc docker-buildx podman-docker containerd runc || true
```

Создайте каталог для ключей:

```bash
sudo install -m 0755 -d /etc/apt/keyrings
```

Добавьте официальный GPG-ключ Docker:

```bash
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo tee /etc/apt/keyrings/docker.asc > /dev/null
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

Добавьте официальный APT-репозиторий:

```bash
sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
```

Установите Docker:

```bash
sudo apt update
sudo apt install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin
```

Запуск и автозапуск:

```bash
sudo systemctl enable --now docker
sudo systemctl status docker --no-pager
```

Проверка:

```bash
sudo docker run --rm hello-world
docker compose version
```

Чтобы запускать Docker без `sudo`:

```bash
sudo usermod -aG docker "$USER"
```

После этого выйдите из SSH-сессии и войдите снова либо выполните:

```bash
newgrp docker
```

Проверка:

```bash
docker ps
```

> Участие в группе `docker` фактически даёт пользователю привилегии уровня root. На production-серверах предоставляйте его только администраторам.

---

## 4. Установка Docker из России на Ubuntu 26.04

Если `download.docker.com` недоступен или работает нестабильно, можно использовать зеркало официального Docker APT-репозитория Yandex:

```text
https://mirror.yandex.ru/mirrors/download.docker.com/linux/ubuntu/
```

Зеркало содержит каталоги `dists/` и официальный GPG-ключ `gpg`.

Удалите старый Docker source при необходимости:

```bash
sudo rm -f /etc/apt/sources.list.d/docker.list
sudo rm -f /etc/apt/sources.list.d/docker.sources
```

Подготовьте keyring:

```bash
sudo install -m 0755 -d /etc/apt/keyrings
```

Получите ключ с зеркала:

```bash
curl -fsSL https://mirror.yandex.ru/mirrors/download.docker.com/linux/ubuntu/gpg \
  | sudo tee /etc/apt/keyrings/docker.asc > /dev/null
sudo chmod a+r /etc/apt/keyrings/docker.asc
```

Добавьте зеркальный репозиторий:

```bash
sudo tee /etc/apt/sources.list.d/docker.sources > /dev/null <<EOF
Types: deb
URIs: https://mirror.yandex.ru/mirrors/download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
```

Проверьте, что система определяет Ubuntu 26.04 как `resolute`:

```bash
. /etc/os-release
echo "$VERSION_CODENAME"
```

Ожидаемо:

```text
resolute
```

Установите Docker:

```bash
sudo apt update
sudo apt install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-buildx-plugin \
  docker-compose-plugin
```

Запуск:

```bash
sudo systemctl enable --now docker
```

Проверка пакетов:

```bash
docker --version
docker compose version
systemctl is-active docker
```

### Если Docker Engine установлен, но Docker Hub недоступен

Сам Docker Engine и APT-репозиторий — это отдельная часть от скачивания container images. `docker compose build` для проекта использует базовые образы Python, Node, Nginx и ClickHouse, поэтому серверу также нужен доступ к registry, где лежат эти образы.

Для production в РФ рекомендуется заранее зеркалировать нужные образы в доступный вам корпоративный registry или Yandex Container Registry и ссылаться на него в `Dockerfile`/`docker-compose.yml`.

Проверить доступность Docker Hub:

```bash
docker pull hello-world
```

Если pull не работает, но у вас есть собственный registry, сначала загрузите туда нужные образы с машины, имеющей доступ, например:

```bash
docker pull python:3.12-slim
docker tag python:3.12-slim REGISTRY/alert-centre/python:3.12-slim
docker push REGISTRY/alert-centre/python:3.12-slim
```

Аналогично рекомендуется зеркалировать:

```text
python:3.12-slim
node:22-alpine
nginx:1.27-alpine
clickhouse/clickhouse-server
```

После этого замените `FROM` в Dockerfile и `image:` в Compose на адреса вашего registry.

---

## 5. Настройка и запуск проекта через Docker

Перейдите в приложение:

```bash
cd /opt/alert-centr/new-app
```

Создайте `.env` только при первом запуске:

```bash
cp .env.example .env
nano .env
```

Если `.env` уже настроен, не перезаписывайте его.

Минимально проверьте:

```env
APP_ENV=production
APP_SECRET_KEY=CHANGE_TO_LONG_RANDOM_SECRET
CORS_ORIGINS=http://SERVER_IP:8080

ALERTS_DB_PATH=/app/data/alerts.db
MITIGATIONS_DB_PATH=/app/data/mitigations.db
KUMA_STATUS_DB_PATH=/app/data/kuma_status.db

CLICKHOUSE_HOST=clickhouse
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=alert_center
CLICKHOUSE_PASSWORD=CHANGE_TO_STRONG_PASSWORD
CLICKHOUSE_DATABASE=alert_center

VITE_API_URL=http://SERVER_IP:8000/api/v1
```

Подготовьте рабочие SQLite БД:

```bash
mkdir -p /opt/alert-centr/new-app/data
```

В каталог должны быть помещены рабочие файлы:

```text
new-app/data/
├── alerts.db
├── mitigations.db
└── kuma_status.db
```

Запуск:

```bash
docker compose up -d --build
```

Проверка контейнеров:

```bash
docker compose ps
```

Проверка backend:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/api/v1/alerts
curl http://127.0.0.1:8000/api/v1/mitigations
curl 'http://127.0.0.1:8000/api/v1/mitigations/history?days=7'
curl http://127.0.0.1:8000/api/v1/metrics/summary
```

Frontend:

```text
http://SERVER_IP:8080
```

Swagger:

```text
http://SERVER_IP:8000/docs
```

Логи:

```bash
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f clickhouse
```

Перезапуск:

```bash
docker compose restart
```

Полная пересборка после обновления Git:

```bash
cd /opt/alert-centr
git fetch origin
git checkout main
git pull origin main

cd new-app
docker compose down
docker compose build --no-cache
docker compose up -d
docker compose ps
```

Обновление без удаления volumes:

```bash
docker compose pull
docker compose up -d --build
```

Остановка:

```bash
docker compose down
```

Не используйте `docker compose down -v`, если не хотите удалить volume ClickHouse.

---

# Вариант B. Установка без Docker на Ubuntu 26.04

В этом варианте frontend, backend, SQLite и ClickHouse работают непосредственно в Ubuntu.

## 6. Backend без Docker

Установите Python и инструменты сборки:

```bash
sudo apt update
sudo apt install -y \
  python3 \
  python3-venv \
  python3-pip \
  python3-dev \
  build-essential \
  sqlite3 \
  libsqlite3-dev
```

Проверка:

```bash
python3 --version
sqlite3 --version
```

Создайте окружение:

```bash
cd /opt/alert-centr/new-app/backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
pip install -e .
```

Создайте `.env` в `new-app` либо экспортируйте переменные окружения. Для запуска из каталога backend можно использовать:

```bash
export APP_ENV=production
export APP_SECRET_KEY='CHANGE_ME'
export CORS_ORIGINS='http://SERVER_IP:8080'
export ALERTS_DB_PATH='/opt/alert-centr/new-app/data/alerts.db'
export MITIGATIONS_DB_PATH='/opt/alert-centr/new-app/data/mitigations.db'
export KUMA_STATUS_DB_PATH='/opt/alert-centr/new-app/data/kuma_status.db'
export CLICKHOUSE_HOST='127.0.0.1'
export CLICKHOUSE_PORT='8123'
export CLICKHOUSE_USER='alert_center'
export CLICKHOUSE_PASSWORD='CHANGE_ME'
export CLICKHOUSE_DATABASE='alert_center'
```

Запуск backend вручную:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Для разработки:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### systemd unit для backend

Создайте:

```bash
sudo nano /etc/systemd/system/alert-centre-backend.service
```

Пример:

```ini
[Unit]
Description=Alert Centre FastAPI Backend
After=network-online.target clickhouse-server.service
Wants=network-online.target

[Service]
Type=simple
User=alertcentre
Group=alertcentre
WorkingDirectory=/opt/alert-centr/new-app/backend
EnvironmentFile=/opt/alert-centr/new-app/.env
ExecStart=/opt/alert-centr/new-app/backend/.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Создайте системного пользователя:

```bash
sudo useradd --system --home /opt/alert-centr --shell /usr/sbin/nologin alertcentre || true
sudo chown -R alertcentre:alertcentre /opt/alert-centr/new-app
```

Активируйте сервис:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now alert-centre-backend
sudo systemctl status alert-centre-backend --no-pager
```

Логи:

```bash
journalctl -u alert-centre-backend -f
```

---

## 7. Frontend без Docker

Для production рекомендуется Node.js LTS и сборка статических файлов с последующей раздачей Nginx.

Установите Node.js из доступного вам репозитория/пакета, затем проверьте:

```bash
node --version
npm --version
```

Сборка:

```bash
cd /opt/alert-centr/new-app/frontend
npm install
VITE_API_URL=http://SERVER_IP:8000/api/v1 npm run build
```

Результат будет в:

```text
frontend/dist/
```

Установите Nginx:

```bash
sudo apt install -y nginx
```

Скопируйте сборку:

```bash
sudo mkdir -p /var/www/alert-centre
sudo rsync -a --delete dist/ /var/www/alert-centre/
```

Создайте конфигурацию:

```bash
sudo nano /etc/nginx/sites-available/alert-centre
```

```nginx
server {
    listen 80;
    server_name _;

    root /var/www/alert-centre;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /docs {
        proxy_pass http://127.0.0.1:8000/docs;
    }
}
```

Активируйте сайт:

```bash
sudo ln -sf /etc/nginx/sites-available/alert-centre /etc/nginx/sites-enabled/alert-centre
sudo nginx -t
sudo systemctl enable --now nginx
sudo systemctl reload nginx
```

В таком варианте frontend доступен на:

```text
http://SERVER_IP/
```

---

## 8. SQLite без Docker

SQLite не является отдельным серверным daemon. Backend открывает файлы БД напрямую.

Установка:

```bash
sudo apt install -y sqlite3 libsqlite3-dev
```

Проверка:

```bash
sqlite3 --version
python3 -c 'import sqlite3; print(sqlite3.sqlite_version)'
```

Каталог:

```bash
sudo mkdir -p /opt/alert-centr/new-app/data
sudo chown -R alertcentre:alertcentre /opt/alert-centr/new-app/data
```

Проверка alerts DB:

```bash
sqlite3 /opt/alert-centr/new-app/data/alerts.db '.tables'
sqlite3 /opt/alert-centr/new-app/data/alerts.db 'SELECT COUNT(*) FROM alerts;'
```

Рекомендуемый режим:

```bash
sqlite3 /opt/alert-centr/new-app/data/alerts.db 'PRAGMA journal_mode=WAL;'
sqlite3 /opt/alert-centr/new-app/data/mitigations.db 'PRAGMA journal_mode=WAL;'
```

---

## 9. ClickHouse без Docker

Установите ClickHouse Server и Client из официального или доступного вам зеркала пакетов. После установки:

```bash
sudo systemctl enable --now clickhouse-server
sudo systemctl status clickhouse-server --no-pager
```

Проверка:

```bash
clickhouse-client --query 'SELECT version()'
curl 'http://127.0.0.1:8123/?query=SELECT%201'
```

Инициализируйте схему проекта:

```bash
clickhouse-client --multiquery < /opt/alert-centr/new-app/deploy/clickhouse/init.sql
```

Проверка:

```bash
clickhouse-client --query 'SHOW DATABASES'
clickhouse-client --query 'SHOW TABLES FROM alert_center'
```

Backend без Docker должен использовать:

```env
CLICKHOUSE_HOST=127.0.0.1
CLICKHOUSE_PORT=8123
CLICKHOUSE_DATABASE=alert_center
```

---

## 10. Проверка после установки

Backend health:

```bash
curl -fsS http://127.0.0.1:8000/health | jq
```

Alerts:

```bash
curl -fsS http://127.0.0.1:8000/api/v1/alerts | jq
```

Mitigations:

```bash
curl -fsS http://127.0.0.1:8000/api/v1/mitigations | jq
```

Metrics:

```bash
curl -fsS http://127.0.0.1:8000/api/v1/metrics/summary | jq
```

Порты:

```bash
ss -lntp | grep -E ':(80|8000|8080|8123|9000)\b'
```

---

## 11. Типовые ошибки

### `permission denied while trying to connect to the Docker daemon socket`

```bash
sudo usermod -aG docker "$USER"
newgrp docker
```

### `docker: command not found`

```bash
apt-cache policy docker-ce
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### `docker compose` не найден

```bash
sudo apt install docker-compose-plugin
docker compose version
```

### `connection refused` к ClickHouse

```bash
systemctl status clickhouse-server
ss -lntp | grep 8123
curl 'http://127.0.0.1:8123/?query=SELECT%201'
```

### Backend не видит SQLite

```bash
ls -lah /opt/alert-centr/new-app/data
sqlite3 /opt/alert-centr/new-app/data/alerts.db '.tables'
```

Проверьте `ALERTS_DB_PATH`, `MITIGATIONS_DB_PATH` и права пользователя, под которым запущен backend.

### Frontend показывает `Backend недоступен`

Проверьте:

```bash
curl http://127.0.0.1:8000/health
curl http://SERVER_IP:8000/health
```

И переменные:

```env
VITE_API_URL=http://SERVER_IP:8000/api/v1
CORS_ORIGINS=http://SERVER_IP:8080,http://SERVER_IP
```

После изменения `VITE_API_URL` frontend нужно пересобрать.

---

## 12. Production checklist

Перед production-запуском:

- заменить `APP_SECRET_KEY`;
- заменить `CLICKHOUSE_PASSWORD`;
- не хранить `.env` в Git;
- ограничить CORS;
- не публиковать ClickHouse 8123/9000 в Internet без необходимости;
- разместить backend за Nginx/reverse proxy;
- включить HTTPS;
- ограничить firewall;
- организовать backup SQLite и ClickHouse;
- использовать отдельного системного пользователя;
- закрепить версии container images;
- использовать собственный/корпоративный registry для production;
- проверить `docker compose ps` или systemd units после каждого обновления.

Дополнительное описание структуры данных и миграции из `services/data_fetcher.py` находится в [`data-sources-and-installation.md`](data-sources-and-installation.md).
