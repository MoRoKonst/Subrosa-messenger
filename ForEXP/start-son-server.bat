@echo off
chcp 65001 > nul
title Subrosa Mesh Server

echo ============================================
echo   Subrosa Messenger — Сервер-сын (меш-узел)
echo ============================================
echo.

:: ─── Проверка Python ──────────────────────────────────────────────────────────
python --version > nul 2>&1
if errorlevel 1 (
    echo [ОШИБКА] Python не найден.
    echo Скачай и установи Python 3.11+ с https://python.org/downloads
    echo При установке поставь галочку "Add Python to PATH"
    pause
    exit /b 1
)

:: ─── Зависимости ──────────────────────────────────────────────────────────────
if not exist ".venv" (
    echo [УСТАНОВКА] Первый запуск — устанавливаю зависимости...
    python -m venv .venv
)
call .venv\Scripts\activate.bat > nul 2>&1
pip install -q -r requirements.txt

:: ─── Конфигурация ─────────────────────────────────────────────────────────────
setlocal enabledelayedexpansion
if not exist ".env" (
    echo [ПЕРВЫЙ ЗАПУСК] Введи общий секрет федерации.
    echo Его тебе сообщает владелец ГЛАВНОГО сервера ТВОЕЙ федерации —
    echo это не обязательно публичный сервер Subrosa, это может быть
    echo любой другой узел (в том числе твой собственный).
    echo.
    set /p FED_SECRET="Секрет федерации: "

    echo.
    echo К какому главному серверу подключить этот узел?
    echo   [1] К публичному серверу Subrosa (wss://api.subrosamessenger.com)
    echo   [2] К своему собственному главному серверу — введу адрес сам
    echo   [3] Ни к какому — этот узел сам будет главным (ждёт входящие подключения)
    echo.
    set /p FED_CHOICE="Выбор [1/2/3, по умолчанию 3]: "

    if "!FED_CHOICE!"=="1" (
        set "FED_PEERS=wss://api.subrosamessenger.com"
    ) else if "!FED_CHOICE!"=="2" (
        echo.
        set /p FED_PEERS="Адрес твоего главного сервера (wss://...): "
    ) else (
        set "FED_PEERS="
    )

    echo.
    echo Введи публичный адрес этого сервера — по нему пользователи будут подключаться.
    echo Пример: wss://myserver.ru  или  wss://1.2.3.4:9000
    echo Если адрес неизвестен — оставь пустым (UPnP попробует определить автоматически).
    echo.
    set /p SRV_URL="Адрес сервера (wss://...): "

    echo FEDERATION_SECRET=%FED_SECRET%> .env
    echo FEDERATION_PEERS=!FED_PEERS!>> .env
    echo SERVER_URL=%SRV_URL%>> .env
    echo.
    echo [OK] Настройки сохранены в .env
    echo [INFO] Изменить федерацию позже — отредактируй FEDERATION_PEERS в .env вручную.
    echo.
)

:: ─── Загрузка .env ────────────────────────────────────────────────────────────
for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
    if not "%%A"=="" (
        set first=%%A
        if not "!first:~0,1!"=="#" set "%%A=%%B"
    )
)

:: ─── Запуск ───────────────────────────────────────────────────────────────────
echo [СТАРТ] Открываю порт через UPnP...
if defined FEDERATION_PEERS (
    echo [INFO]  Главный сервер: %FEDERATION_PEERS%
) else (
    echo [INFO]  Федерация: без главного сервера — этот узел сам главный
)
echo [INFO]  Остановить: Ctrl+C
echo.
echo [ВНИМАНИЕ] Запуск в DEV-режиме — соединение БЕЗ TLS. Сообщения по-прежнему
echo            end-to-end зашифрованы на устройствах, но сам транспорт до этого
echo            сервера не защищён TLS. Для продакшена настрой TLS-сертификат
echo            вручную — см. раздел "VPS / Linux / macOS" на странице self-hosting.
echo.

python server.py --dev

pause
