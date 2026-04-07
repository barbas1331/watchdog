@echo off
title Watchdog de Red — Iniciando...
cd /d "%~dp0"

echo.
echo ============================================
echo   Watchdog de Red - Monitor de Privacidad
echo ============================================
echo.

REM Verificar si ya existe el entorno virtual
if not exist ".venv\Scripts\python.exe" (
    echo [!] Creando entorno virtual...
    python -m venv .venv
    echo [!] Instalando dependencias...
    .venv\Scripts\pip install flask flask-socketio psutil requests eventlet scapy
)

echo [*] Iniciando servicio en http://127.0.0.1:5757
echo [*] El navegador se abrirá automáticamente.
echo [*] Cierra esta ventana para detener el servicio.
echo.

.venv\Scripts\python.exe run.py
pause
