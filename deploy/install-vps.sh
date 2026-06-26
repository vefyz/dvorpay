#!/bin/bash
# Быстрый деплой на VPS (Ubuntu/Debian). Запуск на сервере:
#   curl -sL ... | bash   ИЛИ   chmod +x install-vps.sh && ./install-vps.sh

set -e

APP_DIR="${APP_DIR:-/opt/dvorpay}"
REPO_URL="${REPO_URL:-}"  # задайте URL git-репозитория

echo "=== ДворPay: установка на VPS ==="

if ! command -v docker &>/dev/null; then
  echo "Установка Docker..."
  curl -fsSL https://get.docker.com | sh
  systemctl enable docker
  systemctl start docker
fi

mkdir -p "$APP_DIR"
cd "$APP_DIR"

if [ -n "$REPO_URL" ]; then
  git clone "$REPO_URL" . 2>/dev/null || git pull
else
  echo "Скопируйте файлы проекта в $APP_DIR вручную (scp / git)"
fi

if [ ! -f .env ]; then
  cp .env.example .env
  KEY=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p)
  echo "SECRET_KEY=$KEY" >> .env
  echo "Создан .env с SECRET_KEY"
fi

docker compose build
docker compose up -d

echo ""
echo "Готово! Приложение: http://$(hostname -I | awk '{print $1}'):8000"
echo "Для домена настройте nginx: deploy/nginx-dvorpay.conf"
