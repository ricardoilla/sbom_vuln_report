@echo off
REM Crea el entorno virtual (si no existe), instala dependencias y abre la app.
cd /d "%~dp0"

if not exist .venv (
  echo Creando entorno virtual...
  python -m venv .venv || goto :error
)

echo Instalando dependencias...
.venv\Scripts\pip install -q -r requirements.txt || goto :error

where osv-scanner >nul 2>nul
if errorlevel 1 (
  echo Falta osv-scanner. Instalalo desde https://github.com/google/osv-scanner/releases
  pause
  exit /b 1
)

.venv\Scripts\python main.py
exit /b 0

:error
echo Algo fallo. Revisa que Python 3.10+ este instalado y en el PATH.
pause
exit /b 1
