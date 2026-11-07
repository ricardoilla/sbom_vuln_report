#!/usr/bin/env bash
# Crea el entorno virtual (si no existe), instala dependencias y abre la app.
set -e
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "Creando entorno virtual..."
  python3 -m venv .venv
fi

# Reinstala solo si cambió requirements.txt
if [ ! -f .venv/.deps_ok ] || [ requirements.txt -nt .venv/.deps_ok ]; then
  echo "Instalando dependencias..."
  .venv/bin/pip install -q -r requirements.txt
  touch .venv/.deps_ok
fi

if ! command -v osv-scanner >/dev/null 2>&1; then
  echo "Falta osv-scanner. Instalalo con: brew install osv-scanner"
  exit 1
fi

exec .venv/bin/python main.py
