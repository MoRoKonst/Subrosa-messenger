#!/usr/bin/env python3
"""
TOTP-защищённое чтение логов сервера — отдельный инструмент для админа,
запускаемый им самим на VPS (по SSH или локально), никак не связанный с
мессенджер-протоколом/приложением. См. docs/ISSUE_backup_identity_hijack.md,
"Server-side registration TOTP" / "admin log access".

Идея: у админа уже есть shell-доступ к машине (SSH, консоль хостера и т.п.) —
этот скрипт не заменяет и не защищает сам SSH-вход (см. Tier 3, п.7 в том же
файле — отдельная, независимая задача). Он защищает саму КОМАНДУ чтения
логов: даже если кто-то получил shell на машине, прочитать логи через этот
скрипт он не сможет без текущего TOTP-кода — секрет живёт в отдельном файле,
не в репозитории и не в бэкапах приложения.

Использование:
    python3 admin_logs.py setup                  # один раз, привязывает секрет
    python3 admin_logs.py logs                    # docker-compose logs (по умолчанию)
    python3 admin_logs.py logs --source file --log-file /var/log/subrosa/server.log
    python3 admin_logs.py setup --force            # перевыпустить (нужен текущий код)
"""

import argparse
import base64
import hashlib
import hmac
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

TIME_STEP_SECONDS = 30
CODE_DIGITS = 6
DRIFT_WINDOW = 1

DEFAULT_SECRET_FILE = Path(
    os.environ.get("SUBROSA_ADMIN_TOTP_FILE", str(Path.home() / ".subrosa_admin_totp"))
)


def _totp_code_at_counter(secret_b32: str, counter: int) -> str:
    padded = secret_b32.strip().upper()
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(binary % 1_000_000).zfill(6)


def totp_code_matches(secret_b32: str, code: str, window: int = DRIFT_WINDOW) -> bool:
    code = (code or "").strip()
    if not code:
        return False
    counter_now = int(time.time() // TIME_STEP_SECONDS)
    for drift in range(-window, window + 1):
        try:
            if hmac.compare_digest(_totp_code_at_counter(secret_b32, counter_now + drift), code):
                return True
        except Exception:
            return False
    return False


def generate_secret() -> str:
    raw = os.urandom(20)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def otpauth_uri(secret_b32: str, account: str = "subrosa-admin", issuer: str = "Subrosa-Admin") -> str:
    return f"otpauth://totp/{issuer}:{account}?secret={secret_b32}&issuer={issuer}&digits={CODE_DIGITS}&period={TIME_STEP_SECONDS}"


def read_secret(secret_file: Path) -> str | None:
    if not secret_file.exists():
        return None
    return secret_file.read_text(encoding="utf-8").strip()


def write_secret(secret_file: Path, secret_b32: str) -> None:
    secret_file.write_text(secret_b32 + "\n", encoding="utf-8")
    try:
        os.chmod(secret_file, 0o600)
    except Exception:
        pass


# ─── Простая защита от перебора кода ───────────────────────────────────────
# Отдельный файл рядом с секретом — не общая с сервером, чисто локальная,
# на случай если кто-то запускает этот скрипт скриптом же, подбирая код.
FAIL_THRESHOLD = 3
FAIL_LOCKOUT_SECONDS = 30


def _fail_file(secret_file: Path) -> Path:
    return secret_file.with_suffix(secret_file.suffix + ".fails")


def check_and_wait_lockout(secret_file: Path) -> None:
    f = _fail_file(secret_file)
    if not f.exists():
        return
    try:
        count, last_fail = f.read_text(encoding="utf-8").strip().split(",")
        count = int(count)
        last_fail = float(last_fail)
    except Exception:
        return
    if count < FAIL_THRESHOLD:
        return
    remaining = FAIL_LOCKOUT_SECONDS - (time.time() - last_fail)
    if remaining > 0:
        print(f"Слишком много неверных попыток — подождите {int(remaining) + 1}с.")
        time.sleep(remaining)


def record_attempt(secret_file: Path, success: bool) -> None:
    f = _fail_file(secret_file)
    if success:
        f.unlink(missing_ok=True)
        return
    count = 1
    if f.exists():
        try:
            count = int(f.read_text(encoding="utf-8").strip().split(",")[0]) + 1
        except Exception:
            count = 1
    f.write_text(f"{count},{time.time()}", encoding="utf-8")


def prompt_code(label: str = "TOTP-код") -> str:
    return input(f"{label}: ").strip()


def cmd_setup(args) -> int:
    secret_file = Path(args.secret_file)
    existing = read_secret(secret_file)

    if existing and not args.force:
        print(f"Уже настроено ({secret_file}). Для перевыпуска: setup --force (нужен текущий код).")
        return 1

    if existing and args.force:
        check_and_wait_lockout(secret_file)
        code = prompt_code("Текущий код (для подтверждения перевыпуска)")
        if not totp_code_matches(existing, code):
            record_attempt(secret_file, False)
            print("Неверный код — перевыпуск отклонён.")
            return 1
        record_attempt(secret_file, True)

    secret = generate_secret()
    print()
    print("Новый TOTP-секрет (сохрани в оффлайн-менеджере паролей, НЕ в этом репозитории):")
    print(f"  {secret}")
    print()
    print("Для ручного добавления в любое TOTP-приложение (Google Authenticator и т.п.):")
    print(f"  {otpauth_uri(secret)}")
    print()

    code = prompt_code("Введи текущий код из приложения, чтобы подтвердить и сохранить")
    if not totp_code_matches(secret, code):
        print("Код не совпал — секрет НЕ сохранён. Запусти setup заново.")
        return 1

    write_secret(secret_file, secret)
    print(f"Готово. Секрет сохранён в {secret_file} (права 600).")
    return 0


def cmd_logs(args) -> int:
    secret_file = Path(args.secret_file)
    secret = read_secret(secret_file)
    if not secret:
        print(f"Не настроено. Сначала: python3 {sys.argv[0]} setup")
        return 1

    check_and_wait_lockout(secret_file)
    code = prompt_code()
    if not totp_code_matches(secret, code):
        record_attempt(secret_file, False)
        print("Неверный код.")
        return 1
    record_attempt(secret_file, True)

    if args.source == "docker":
        cmd = ["docker-compose", "logs", "--tail", str(args.tail), args.service]
        result = subprocess.run(cmd, cwd=args.compose_dir)
        return result.returncode
    else:
        log_path = Path(args.log_file)
        if not log_path.exists():
            print(f"Файл не найден: {log_path}")
            return 1
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        for line in lines[-args.tail:]:
            print(line, end="")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="TOTP-защищённое чтение логов Subrosa-сервера")
    parser.add_argument("--secret-file", default=str(DEFAULT_SECRET_FILE))
    sub = parser.add_subparsers(dest="command", required=True)

    p_setup = sub.add_parser("setup", help="Один раз привязать TOTP-секрет")
    p_setup.add_argument("--force", action="store_true", help="Перевыпустить существующий секрет (нужен текущий код)")
    p_setup.set_defaults(func=cmd_setup)

    p_logs = sub.add_parser("logs", help="Прочитать логи (требует TOTP-код)")
    p_logs.add_argument("--source", choices=["docker", "file"], default="docker")
    p_logs.add_argument("--tail", type=int, default=500)
    p_logs.add_argument("--service", default="subrosa-server", help="Имя сервиса в docker-compose.yml")
    p_logs.add_argument("--compose-dir", default=".", help="Директория с docker-compose.yml")
    p_logs.add_argument("--log-file", default="/var/log/subrosa/server.log", help="Путь к файлу лога (--source file)")
    p_logs.set_defaults(func=cmd_logs)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
