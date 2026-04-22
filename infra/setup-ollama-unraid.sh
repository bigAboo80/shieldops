#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Script: setup-ollama-unraid.sh
# Description: Деплой Ollama + Qwen3-Coder-30B на Unraid с RTX 3060
# Target: Unraid сервер ShieldOps
# Author: Art / ShieldOps
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

# --- Проверки ---
command -v docker &>/dev/null || err "Docker не найден. Установи Docker на Unraid."
nvidia-smi &>/dev/null || warn "nvidia-smi не найден — GPU может быть недоступен в контейнере"

# --- Шаг 1: Запуск Ollama ---
log "Запускаю контейнер Ollama..."

if docker ps -a --format '{{.Names}}' | grep -q '^ollama$'; then
    warn "Контейнер 'ollama' уже существует. Перезапускаю..."
    docker stop ollama 2>/dev/null || true
    docker rm ollama 2>/dev/null || true
fi

docker run -d \
  --name ollama \
  --gpus all \
  -v /mnt/user/appdata/ollama:/root/.ollama \
  -p 11434:11434 \
  --restart unless-stopped \
  ollama/ollama:latest

log "Контейнер запущен. Жду готовности API..."
sleep 5

# Ждём до 60 секунд
for i in $(seq 1 12); do
    if curl -s http://localhost:11434/api/tags &>/dev/null; then
        log "Ollama API готов!"
        break
    fi
    sleep 5
done

# --- Шаг 2: Скачиваем модель ---
log "Скачиваю Qwen3-Coder-30B-A3B (≈18GB, это займёт время)..."
docker exec ollama ollama pull qwen3-coder-30b-a3b

# --- Шаг 3: Проверка ---
log "Проверяю модель..."
RESPONSE=$(docker exec ollama ollama run qwen3-coder-30b-a3b "Reply with exactly: OK_READY" 2>/dev/null | head -1)

if echo "$RESPONSE" | grep -qi "OK_READY"; then
    log "Модель работает!"
else
    warn "Модель ответила, но не 'OK_READY'. Проверь вручную:"
    echo "  docker exec -it ollama ollama run qwen3-coder-30b-a3b 'Hello'"
fi

# --- Шаг 4: Тест API endpoint ---
log "Проверяю OpenAI-совместимый API..."
curl -s http://localhost:11434/v1/models | python3 -m json.tool 2>/dev/null || warn "python3 не найден для pretty-print, но API работает"

# --- Итог ---
echo ""
echo "═══════════════════════════════════════════════════════════"
log "Ollama + Qwen3-Coder-30B-A3B развёрнут!"
echo ""
echo "  API endpoint:  http://$(hostname -I | awk '{print $1}'):11434"
echo "  OpenAI API:    http://$(hostname -I | awk '{print $1}'):11434/v1"
echo "  Модель:        qwen3-coder-30b-a3b"
echo ""
echo "  Для aider:"
echo "    aider --model openai/qwen3-coder-30b-a3b \\"
echo "      --openai-api-base http://$(hostname -I | awk '{print $1}'):11434/v1 \\"
echo "      --openai-api-key not-needed"
echo ""
echo "═══════════════════════════════════════════════════════════"
