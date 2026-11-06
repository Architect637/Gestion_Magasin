#!/usr/bin/env bash
# Lanceur de l'application de gestion de stock.
# Usage : ./lancer.sh            (ordinateur seulement)
#         ./lancer.sh --reseau   (ordinateur et téléphone sur le même Wi-Fi)

set -euo pipefail

DOSSIER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DOSSIER"

if ! command -v python3 >/dev/null 2>&1; then
    echo "Python 3 est introuvable. Installe-le (sudo apt install python3) puis relance ce script."
    exit 1
fi

exec python3 server.py "$@"
