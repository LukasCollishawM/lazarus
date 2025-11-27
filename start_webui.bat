@echo off
echo Starting Lazarus Web UI...
echo.
echo Checking if port 8000 is available...
netstat -ano | findstr :8000 >nul
if %errorlevel% == 0 (
    echo Port 8000 is in use. Trying port 8001...
    set PORT=8001
    set URL=http://localhost:8001/ui
) else (
    set PORT=8000
    set URL=http://localhost:8000/ui
)
echo.
echo Server will be available at: %URL%
echo Press CTRL+C to stop the server
echo.
python -m uvicorn lazarus.webui.backend.server:app --reload --host localhost --port %PORT%
pause

