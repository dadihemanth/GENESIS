@echo off
setlocal enabledelayedexpansion

echo ============================================
echo  GENESIS — Dev Mode (No Docker)
echo  Generative Engine for Novel Exploitation
echo  ^& Security Intelligence Study
echo ============================================
echo.

:: Check for .env
if not exist ".env" (
    copy ".env.example" ".env"
    echo [SETUP] Created .env from template. Edit it with your API keys.
)

:: Create storage dir
if not exist "E:\SecurityResearchData" mkdir "E:\SecurityResearchData"

echo [INFO] Prerequisites needed:
echo   Python 3.11+    (python --version)
echo   Node.js 20+     (node --version)
echo   PostgreSQL 16   (running on localhost:5432)
echo   MongoDB 7.0     (running on localhost:27017)
echo   Redis 7.2       (running on localhost:6379)
echo   ChromaDB        (pip install chromadb, run: chroma run --port 8001)
echo.
echo [INFO] Starting services in separate windows...
echo.

:: --- MCP Server ---
echo [MCP] Starting MCP server on port 3001...
start "MCP Server" cmd /k "cd mcp-server && npm install && npm run dev"

timeout /t 3 /nobreak >nul

:: --- Backend ---
echo [API] Starting FastAPI backend on port 8000...
start "Backend API" cmd /k "cd backend && pip install -r requirements.txt && alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload"

timeout /t 3 /nobreak >nul

:: --- Celery Worker ---
echo [CELERY] Starting Celery worker...
start "Celery Worker" cmd /k "cd backend && celery -A app.services.celery_app worker --loglevel=info -c 2 -Q research"

timeout /t 3 /nobreak >nul

:: --- Frontend ---
echo [UI] Starting React frontend on port 3000...
start "Frontend" cmd /k "cd frontend && npm install && npm run dev"

echo.
echo ============================================
echo  Services starting in separate windows
echo ============================================
echo.
echo  Frontend:    http://localhost:3000
echo  Backend API: http://localhost:8000
echo  API Docs:    http://localhost:8000/docs
echo  MCP Server:  http://localhost:3001
echo.
echo  First run: open http://localhost:3000/setup
echo ============================================

timeout /t 8 /nobreak >nul
start http://localhost:3000
