#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Script: token-benchmark.sh
# Description: Замер стоимости токенов Claude vs Qwen для типовых задач
# Author: Art / ShieldOps
# ============================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
info() { echo -e "${CYAN}[i]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

OLLAMA_URL="${OLLAMA_URL:-http://localhost:11434}"
RESULTS_FILE="benchmark-results.md"

echo "# ShieldOps Token Benchmark — $(date +%Y-%m-%d)" > "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# --- Тест 1: Создание Go файла ---
info "=== ТЕСТ 1: Создание Go файла (connector) ==="

PROMPT_1="Create a Go file internal/connector/k8s.go with:
- func NewClient(kubeconfigPath string) (*kubernetes.Clientset, error)
- func ListPods(ctx context.Context, client *kubernetes.Clientset, namespace string) ([]v1.Pod, error)
- func ListServiceAccounts(ctx context.Context, client *kubernetes.Clientset, namespace string) ([]v1.ServiceAccount, error)
Use client-go. Add proper error wrapping with fmt.Errorf and %w."

echo "## Тест 1: Создание Go файла (K8s connector)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# Qwen тест
info "Qwen3-Coder-30B..."
START=$(date +%s%N)
QWEN_RESPONSE=$(curl -s "$OLLAMA_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{
    \"model\": \"qwen3-coder-30b-a3b\",
    \"messages\": [{\"role\": \"user\", \"content\": \"$PROMPT_1\"}],
    \"temperature\": 0.7,
    \"max_tokens\": 2000
  }" 2>/dev/null)
END=$(date +%s%N)
QWEN_TIME=$(( (END - START) / 1000000 ))

QWEN_TOKENS=$(echo "$QWEN_RESPONSE" | python3 -c "
import json, sys
d = json.load(sys.stdin)
u = d.get('usage', {})
print(f\"input={u.get('prompt_tokens',0)} output={u.get('completion_tokens',0)}\")
" 2>/dev/null || echo "input=? output=?")

log "Qwen: ${QWEN_TIME}ms | $QWEN_TOKENS | стоимость: \$0.00"
echo "- **Qwen**: ${QWEN_TIME}ms | $QWEN_TOKENS | \$0.00" >> "$RESULTS_FILE"

# Claude оценка (не вызываем реально — считаем по формуле)
echo "- **Claude Sonnet (оценка)**: ~2000 input + ~1500 output = \$0.03" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# --- Тест 2: Генерация тестов ---
info "=== ТЕСТ 2: Генерация table-driven тестов ==="

PROMPT_2="Write table-driven tests for a Go function NewClient(kubeconfigPath string) (*kubernetes.Clientset, error). Include cases: valid kubeconfig path, empty path returns error, nonexistent file returns error. Use t.Run subtests."

echo "## Тест 2: Table-driven тесты" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

START=$(date +%s%N)
QWEN_RESPONSE_2=$(curl -s "$OLLAMA_URL/v1/chat/completions" \
  -H "Content-Type: application/json" \
  -d "{
    \"model\": \"qwen3-coder-30b-a3b\",
    \"messages\": [{\"role\": \"user\", \"content\": \"$PROMPT_2\"}],
    \"temperature\": 0.7,
    \"max_tokens\": 2000
  }" 2>/dev/null)
END=$(date +%s%N)
QWEN_TIME_2=$(( (END - START) / 1000000 ))

QWEN_TOKENS_2=$(echo "$QWEN_RESPONSE_2" | python3 -c "
import json, sys
d = json.load(sys.stdin)
u = d.get('usage', {})
print(f\"input={u.get('prompt_tokens',0)} output={u.get('completion_tokens',0)}\")
" 2>/dev/null || echo "input=? output=?")

log "Qwen: ${QWEN_TIME_2}ms | $QWEN_TOKENS_2 | стоимость: \$0.00"
echo "- **Qwen**: ${QWEN_TIME_2}ms | $QWEN_TOKENS_2 | \$0.00" >> "$RESULTS_FILE"
echo "- **Claude Sonnet (оценка)**: ~1500 input + ~1200 output = \$0.02" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# --- Тест 3: Сложная задача (только оценка Claude) ---
echo "## Тест 3: Сложный детектор (только Claude)" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "- **Claude Sonnet (оценка)**: ~3000 input + ~2500 output = \$0.05-0.08" >> "$RESULTS_FILE"
echo "- Qwen: не рекомендуется — сложная бизнес-логика с K8s-спецификой" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"

# --- Итог ---
echo "## Итоговая оценка бюджета" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "| Параметр | Claude Sonnet | Qwen (локально) |" >> "$RESULTS_FILE"
echo "|----------|---------------|-----------------|" >> "$RESULTS_FILE"
echo "| Стоимость/день | ~\$0.30-0.50 | \$0.00 |" >> "$RESULTS_FILE"
echo "| Стоимость/мес | ~\$10-15 | \$0.00 |" >> "$RESULTS_FILE"
echo "| Скорость ответа | 2-5 сек | 10-30 сек |" >> "$RESULTS_FILE"
echo "| Качество Go/K8s | 9/10 | 7/10 |" >> "$RESULTS_FILE"
echo "| Подходит для | Архитектура, детекторы, review | Бойлерплейт, тесты, docs |" >> "$RESULTS_FILE"
echo "" >> "$RESULTS_FILE"
echo "**Вывод:** При гибридной стратегии укладываемся в \$15-20/мес." >> "$RESULTS_FILE"

log "Результаты сохранены в $RESULTS_FILE"
cat "$RESULTS_FILE"
