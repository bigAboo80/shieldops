# ShieldOps Dev Environment — Quick Setup на Unraid

## Шаг 1: Создай репо на Gitea (через Brave)

1. Зайди на https://git.mscsrv.ru → "+" → New Repository
2. Name: `shieldops`, Private, Init with README
3. Через веб-интерфейс загрузи файлы (Upload File):
   - `CLAUDE.md` → корень
   - `Makefile` → корень
   - `.claudeignore` → корень (может потребоваться "New File")

## Шаг 2: На Unraid через SSH

```bash
# Клонируй репо
cd /mnt/user/appdata
git clone https://git.mscsrv.ru/<user>/shieldops.git

# Скопируй dev-env файлы в репо
# (скачай docker-compose.yml, Dockerfile.dev, entrypoint.sh из чата)
cd shieldops
mkdir -p infra/dev-env
# Положи туда docker-compose.yml, Dockerfile.dev, entrypoint.sh
```

## Шаг 3: Создай .env файл

```bash
cd /mnt/user/appdata/shieldops/infra/dev-env
cat > .env << 'EOF'
ANTHROPIC_API_KEY=sk-ant-ТВОЙ_КЛЮЧ_СЮДА
EOF
```

Получить API ключ: https://console.anthropic.com/settings/keys

## Шаг 4: Запусти dev-контейнер

```bash
cd /mnt/user/appdata/shieldops/infra/dev-env
chmod +x entrypoint.sh
docker compose up -d --build
```

Первая сборка ~3-5 минут (скачивает Go, Node, Claude Code).

## Шаг 5: Зайди в контейнер

```bash
docker exec -it shieldops-dev bash
```

Увидишь:
```
=== ShieldOps Dev Environment ===
Go:        go version go1.24.x linux/amd64
Node:      v22.x.x
Ollama:    http://host.docker.internal:11434
Workspace: /workspace
```

## Шаг 6: Инициализируй Go проект

```bash
# Внутри контейнера
cd /workspace
go mod init github.com/shieldops/core

# Создай структуру
mkdir -p cmd/scan \
  internal/{connector,inventory,graph,detectors,report} \
  pkg/trivy \
  .claude/rules

# Проверь
go version && make --version && claude --version
```

## Шаг 7: Первый тест Claude Code

```bash
claude
# В Claude Code набери:
# "Create cmd/scan/main.go — minimal CLI entry point using flag package.
#  Accept --kubeconfig flag with default ~/.kube/config. Print 'ShieldOps scanner v0.1'"
```

## Шаг 8: Первый тест Qwen через aider

```bash
aider --model openai/qwen3-coder:30b \
  --openai-api-base http://host.docker.internal:11434/v1 \
  --openai-api-key not-needed \
  internal/connector/k8s.go
```

## Доступ с рабочего Windows PC

SSH в dev-контейнер:
```
ssh -p 8822 dev@<UNRAID_IP>
```

Или через VS Code Remote SSH:
- Host: `<UNRAID_IP>`
- Port: `8822`
- User: `dev`

## Что где живёт

```
Unraid Host
├── Docker: ollama (порт 11434) — AI модели
├── Docker: shieldops-dev (порт 8822) — разработка
│   ├── Go 1.24 + golangci-lint
│   ├── Node 22 + Claude Code CLI
│   ├── aider + подключение к Ollama
│   └── /workspace → /mnt/user/appdata/shieldops (volume)
└── /mnt/user/appdata/shieldops — исходники (git repo)
```
