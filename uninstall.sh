#!/usr/bin/env bash
set -euo pipefail

program="$HOME/.local/lib/fritzmonitor"
unit="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/fritzmonitor.service"
if (( EUID == 0 )); then
    printf '%s\n' "Run uninstall.sh as a regular user." >&2
    exit 1
fi

if [[ -f "$unit" ]]; then
    systemctl --user disable --now fritzmonitor.service
    rm -- "$unit"
    systemctl --user daemon-reload
fi
rm -f -- "$program"/{fritzmonitor,probe,configure,fritzrouter,hosts,collector,archive,webapp}.py
rm -f -- "$program"/web/{index.html,style.css,app.js}
rmdir -- "$program/web" "$program" 2>/dev/null || true
printf '%s\n' 'Installazione rimossa. Configurazione e archive rimangono nelle directory utente.'
