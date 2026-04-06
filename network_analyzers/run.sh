#!/bin/bash

# Script para lanzar DHCP Monitor con HTTPS

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Activar virtual environment
source venv/bin/activate

# Lanzar aplicación
echo "🚀 Iniciando DHCP Monitor (HTTPS en puerto 5443)..."
python3 ogDHCP-Observer.py
