@echo off
chcp 65001 > nul
title Beacon Mesh Server

echo ============================================
echo   Beacon Messenger — Сервер-сын (меш-узел)
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
if not exist ".env" (
    echo [ПЕРВЫЙ ЗАПУСК] Введи общий секрет федерации.
    echo Его тебе сообщает владелец главного сервера.
    echo.
    set /p FED_SECRET="Секрет федерации: "

    echo.
    echo Введи публичный адрес этого сервера — по нему пользователи будут подключаться.
    echo Пример: wss://myserver.ru  или  wss://1.2.3.4:9000
    echo Если адрес неизвестен — оставь пустым (UPnP попробует определить автоматически).
    echo.
    set /p SRV_URL="Адрес сервера (wss://...): "

    echo FEDERATION_SECRET=%FED_SECRET%> .env
    echo FEDERATION_PEERS=wss://api.beacon-app.org>> .env
    echo SERVER_URL=%SRV_URL%>> .env
    echo CHANNEL_ADMIN_SECRET=>> .env
    echo.
    echo [OK] Настройки сохранены в .env
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
echo [СТАРТ] Подключаюсь к главному серверу и открываю порт через UPnP...
echo [INFO]  Главный сервер: wss://api.beacon-app.org
echo [INFO]  Остановить: Ctrl+C
echo.

python server.py --dev

pause
