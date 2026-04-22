# ShieldOps — K8s CNAPP Security Scanner

Go 1.24 + client-go + PostgreSQL. Agentless K8s сканер с security graph.

## Команды
- make build — собрать бинарник
- make test — go test -race -count=1 ./...
- make lint — golangci-lint run ./...
- make scan — запуск на тестовом кластере

## Архитектура
cmd/scan/ → CLI | internal/connector/ → K8s API
internal/inventory/ → сбор assets | internal/graph/ → PostgreSQL edges
internal/detectors/ → 3 toxic combination | internal/report/ → JSON+HTML
pkg/trivy/ → CVE сканирование образов

## Go-конвенции
- ctx context.Context первый параметр всегда
- fmt.Errorf("verb object: %w", err) + errors.Is/As
- Принимай интерфейсы, возвращай конкретные типы
- Table-driven тесты с t.Run, t.Parallel
- Go 1.24: slices, maps, range-over-int

## K8s правила
- client-go clientsets (НЕ controller-runtime — это не оператор)
- apierrors.IsNotFound → log + skip, не паниковать
- Все вызовы API с context.WithTimeout

## НИКОГДА
- Не хардкодь namespace
- Не игнорируй ошибки K8s API
- Не пиши Java-style Go (factory, builder, DI framework)
- Не используй controller-runtime (это CLI-сканер, не оператор)

## /compact
Сохрани: пути изменённых файлов, ошибки, арх. решения.
Удаляй: debug вывод, результаты исследований.

# CLAUDE.md

Behavioral guidelines to reduce common LLM coding mistakes. Merge with project-specific instructions as needed.

**Tradeoff:** These guidelines bias toward caution over speed. For trivial tasks, use judgment.

## 1. Think Before Coding

**Don't assume. Don't hide confusion. Surface tradeoffs.**

Before implementing:
- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them - don't pick silently.
- If a simpler approach exists, say so. Push back when warranted.
- If something is unclear, stop. Name what's confusing. Ask.

## 2. Simplicity First

**Minimum code that solves the problem. Nothing speculative.**

- No features beyond what was asked.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

## 3. Surgical Changes

**Touch only what you must. Clean up only your own mess.**

When editing existing code:
- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it - don't delete it.

When your changes create orphans:
- Remove imports/variables/functions that YOUR changes made unused.
- Don't remove pre-existing dead code unless asked.

The test: Every changed line should trace directly to the user's request.

## 4. Goal-Driven Execution

**Define success criteria. Loop until verified.**

Transform tasks into verifiable goals:
- "Add validation" → "Write tests for invalid inputs, then make them pass"
- "Fix the bug" → "Write a test that reproduces it, then make it pass"
- "Refactor X" → "Ensure tests pass before and after"

For multi-step tasks, state a brief plan:
```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Strong success criteria let you loop independently. Weak criteria ("make it work") require constant clarification.

---

**These guidelines are working if:** fewer unnecessary changes in diffs, fewer rewrites due to overcomplication, and clarifying questions come before implementation rather than after mistakes.
