@echo off
REM Quick start script for Subrosa Messenger on Windows
cd /d "%~dp0"

echo.
echo ========================================
echo Subrosa Messenger Docker Quick Start
echo ========================================
echo.

REM Check Docker is installed
docker --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker is not installed or not in PATH
    echo Install from: https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

REM Check if certificates exist
if not exist "certs" (
    echo.
    echo Generating self-signed certificate...
    REM Try using WSL if available, otherwise notify user
    bash generate-certs.sh 2>nul
    if errorlevel 1 (
        echo.
        echo ERROR: Could not generate certificates
        echo On Windows, you need to run from WSL or Git Bash:
        echo   wsl bash generate-certs.sh
        echo Or manually:
        echo   mkdir certs
        echo   openssl req -x509 -newkey rsa:4096 -nodes -days 365 ^
        echo     -keyout certs/key.pem -out certs/cert.pem
        pause
        exit /b 1
    )
)

REM Check .env exists (lives at repo root, one level up from deploy\)
if not exist "..\.env" (
    echo.
    echo Creating .env from template...
    copy ..\.env.example ..\.env
)

REM Start services
echo.
echo Starting Subrosa Messenger services...
echo.

docker compose up -d

if errorlevel 1 (
    echo ERROR: Failed to start services
    pause
    exit /b 1
)

timeout /t 3 /nobreak

echo.
echo ? Services started!
echo.
echo Container status:
docker compose ps
echo.
echo Next steps:
echo   1. View logs: docker compose logs -f
echo   2. Test connection: 
echo      - On Windows, open a browser console and run:
echo        ws = new WebSocket('wss://localhost/ws');
echo   3. Stop server: docker compose down
echo.
echo For production deployment, see DEPLOY.md
echo.
pause
