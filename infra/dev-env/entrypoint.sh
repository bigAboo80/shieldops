#!/bin/bash
set -e

# Запуск SSH если нужен удалённый доступ
if [ -f /var/run/sshd ]; then
    sudo /usr/sbin/sshd 2>/dev/null || true
fi

# Настройка git если не настроен
if [ ! -f /home/dev/.gitconfig ]; then
    git config --global user.name "Art"
    git config --global user.email "art@shieldops.tech"
    git config --global init.defaultBranch main
    git config --global --add safe.directory /workspace
fi

# Проверка Ollama
if curl -s "${OLLAMA_HOST:-http://host.docker.internal:11434}/api/tags" > /dev/null 2>&1; then
    echo "[✓] Ollama доступен: ${OLLAMA_HOST:-http://host.docker.internal:11434}"
else
    echo "[!] Ollama недоступен — проверь что контейнер ollama запущен"
fi

# Проверка API ключа Claude
if [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "[✓] Claude API key настроен"
else
    echo "[!] ANTHROPIC_API_KEY не задан — Claude Code не будет работать"
    echo "    Добавь в .env: ANTHROPIC_API_KEY=sk-ant-..."
fi

exec "$@"
