@echo off
setlocal enabledelayedexpansion

echo ============================================
echo  GENESIS — Security Intelligence Platform
echo  Generative Engine for Novel Exploitation
echo  ^& Security Intelligence Study
echo ============================================
echo.

:: Check for .env file
if not exist ".env" (
    echo [SETUP] Creating .env from .env.example...
    copy ".env.example" ".env"
    echo [WARN] Please edit .env with your API keys before continuing.
    echo        Press any key after editing .env...
    pause
)

:: Create storage directory
if not exist "E:\SecurityResearchData" (
    echo [SETUP] Creating storage directory E:\SecurityResearchData...
    mkdir "E:\SecurityResearchData"
)

:: Check Docker
docker --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Docker is not installed or not in PATH.
    echo         Install Docker Desktop from https://www.docker.com/products/docker-desktop/
    exit /b 1
)

:: Start infrastructure services first
echo [START] Starting infrastructure services (PostgreSQL, MongoDB, Redis, ChromaDB)...
docker-compose up -d postgres mongodb redis chromadb

echo [WAIT] Waiting for databases to be healthy (30s)...
timeout /t 30 /nobreak >nul

:: Run database migrations
echo [DB] Running database migrations...
docker-compose run --rm backend alembic upgrade head

:: Start all services
echo [START] Starting all services...
docker-compose up -d

echo.
echo ============================================
echo  GENESIS is starting up!
echo ============================================
echo.
echo  Frontend:    http://localhost:3000
echo  Backend API: http://localhost:8000
echo  API Docs:    http://localhost:8000/docs
echo  MCP Server:  http://localhost:3001
echo.
echo  Open http://localhost:3000/setup on first run.
echo.
echo  To stop: docker-compose down
echo  Logs:    docker-compose logs -f
echo ============================================

:: Open browser after short delay
timeout /t 5 /nobreak >nul
start http://localhost:3000

endlocal
