# CI / SAST — план внедрения (финальная версия)

Сведено из черновика + внешнего ревью (`docs/CI_SAST_PLAN_REVIEWED.md`) —
расхождения разобраны, финальные решения ниже. Ничего ещё не внедрено.

Контекст: соло-разработка, Kotlin/Gradle (Android) + Python
(`Server/server.py`), публичный репозиторий на GitHub, сейчас нет ни CI,
ни SAST, ни реальных тестов (`ExampleUnitTest.kt`/`ExampleInstrumentedTest.kt`
— boilerplate-заглушки).

Цели:
1. минимальная инженерная и security-гигиена;
2. снижение риска регрессий (в том числе тех классов багов, что нашли
   сегодня в `docs/ANDROID_AUDIT.md`);
3. Audit Readiness Pack для NLnet/OSTIF/Alpha-Omega;
4. **не создавать ложное впечатление**, что наличие CI/SAST само по себе
   означает, что продукт безопасен — протокольная логика и concurrency
   остаются предметом независимого аудита, не покрываются автоматикой
   полностью.

---

## Секреты — два барьера, не один

**Важная поправка к первому черновику**: Gitleaks-в-CI сам по себе не
предотвращает попадание секрета в публичную историю — workflow стартует
**после** того, как push уже принят GitHub. Нужна комбинация:

```
локальный pre-commit/pre-push hook (Gitleaks)
    ↓
GitHub Secret Scanning + Push Protection (блокирует ДО принятия push —
    бесплатно для публичных репозиториев)
    ↓
репозиторий
    ↓
Gitleaks в CI (дополнительный, а не единственный слой)
```

`.gitignore` — гигиена, не security-контроль сам по себе.

Full-history scan Gitleaks — один раз при первом внедрении; дальше на
каждом PR — только `base commit → HEAD`, на каждом push — только новые
коммиты. Полный скан истории — периодически/вручную, не на каждом PR
(иначе лишний шум и время CI).

`.gitleaks.toml` — только под реальные false positives, не широкие
allowlist, которые могут спрятать настоящий секрет.

## Dependency / supply-chain

Не просто "включить Dependabot" — отдельно настроить:
- Dependabot Alerts
- Dependabot Security Updates
- Dependabot Version Updates
- Dependency Review на PR
- `pip-audit` для Python (CVE-база специально для Python-пакетов)

Ecosystems в `.github/dependabot.yml`: `gradle`, `pip`, **`github-actions`**
(сами Actions — тоже supply-chain зависимость, легко забыть).

## SAST

- **Semgrep** — один основной сканер на старте, покрывает и Kotlin, и
  Python, community ruleset (`p/security-audit`, `p/secrets`), проще
  настроить и меньше шума, чем CodeQL — лучше подходит как первый SAST
  для кодовой базы 25k+ строк, которая раньше вообще не проверялась
  статически. Позже — свои custom rules под project-specific инварианты
  (например, запрет прямой мутации `token_pending`/group-key state вне
  определённых функций).
- **CodeQL** — добавить следующим, не откладывать надолго (внешнее ревью
  справедливо указало, что для публичного репо его можно включать рано —
  семантический анализ, дополняет Semgrep). Решение по точному порядку
  Semgrep/CodeQL — на усмотрение, оба мнения разумны.
- **Bandit** (опционально) — дешёвый Python-guardrail (`eval`/`exec`,
  небезопасный `subprocess`, слабая крипта) — не ждать от него сложных
  protocol-багов, просто постоянный guard rail.
- **Detekt** (низкий приоритет) — Kotlin code-quality/static-analysis,
  security-ценность ниже, чем у Semgrep/CodeQL.

## Security regression tests — не откладывать до "потом"

**Главная поправка к первому черновику**: для E2EE-мессенджера самые
важные баги — протокольная логика и concurrency, а не типичные
SAST-паттерны (см. сегодняшний `docs/ANDROID_AUDIT.md` — ни один из
найденных багов SAST/линтер бы не поймал). Минимальное ядро — 5-10 тестов
на конкретные инварианты, привязанные к реально найденным сегодня багам:

1. recovery-код потребляется атомарно (concurrent redemption → ровно один SUCCESS)
2. одновременная регистрация нового device_id с одним recovery-кодом — только одна проходит
3. ACK одного получателя не подтверждает доставку чужого сообщения (`token_to_ws` ownership)
4. `token_pending` не удаляется раньше подтверждённого ACK
5. отозванный (`revoked`) fingerprint не получает доступ после revoke
6. удалённый участник группы не получает новый ключ после ротации
7. повтор/replay уже потраченного анонимного токена отклоняется (`spent_tokens`)
8. `MAX_REGISTERED_USERS`/access-code редемпшн атомарны под конкурентной нагрузкой

Каждый новый исправленный security-баг — новый regression test, не просто
запись в CHANGELOG.

## Hardening самого CI

Пропущено в первом черновике полностью — CI сам является частью
supply chain:
- `permissions: contents: read` по умолчанию, `write` — только где реально нужно
- сторонние Actions — пиновать на конкретный commit SHA, не на тег/branch
- минимизировать число сторонних Actions
- не передавать repo secrets в workflow от недоверенных PR
- разделять build/test jobs и jobs, которым реально нужны secrets
- осторожно с `pull_request_target` — использовать только при полном понимании его security-модели (классический источник supply-chain инцидентов в GitHub Actions)

## Branch protection — тоже пропущено в черновике

Наличие workflow ничего не гарантирует, если можно смёржить в `main` при
красном CI. Для `main`: Pull Request required, required status checks, no
direct push. Минимальный набор required checks: Android build, server
check, secret scan, dependency review, SAST, security tests. Для соло-
разработки review-approval можно не требовать, но required checks — да.

---

## Порядок внедрения

**Сначала (дёшево и быстро):**
1. `build.yml` — `./gradlew assembleDebug` + `./gradlew lint`, `python -m compileall Server/` (только syntax-check, не ловит runtime-логику вроде сегодняшнего бага с рекурсией в `db_connect()`)
2. GitHub Secret Scanning + Push Protection (включить в настройках репо)
3. Gitleaks — локальный pre-push hook + CI workflow
4. Dependabot (alerts + security updates + version updates) + Dependency Review + `pip-audit`

**Затем:**
5. Semgrep
6. CodeQL
7. Первые 5-10 security regression tests (список инвариантов выше)
8. Branch protection / required checks

**После этого:**
9. Bandit
10. Detekt
11. Custom Semgrep rules под project-specific инварианты
12. Расширение concurrency/integration test suite

---

## Что писать в Audit Readiness Pack

Не писать: *"Product is secure because SAST and CI are enabled."*

Писать: *"Automated CI is configured for build verification, dependency
review, secret scanning, SAST, and selected security regression tests.
Security-critical protocol and concurrency properties remain in scope for
independent review."* Если покрытие тестами пока маленькое — так и
написать, это выглядит честнее и лучше, чем заявлять несуществующую полноту.

**Главный принцип**: CI/SAST ≠ доказательство безопасности. CI/SAST +
security regression tests + независимый аудит = нормальная база
security-процесса, не замена ему.
