#!/usr/bin/env bash
set -euo pipefail

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
program="$HOME/.local/lib/fritzmonitor"
units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
if (( EUID == 0 )); then
    printf '%s\n' "Run install.sh as a regular user." >&2
    exit 1
fi

/usr/bin/python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))'
install -d -m 755 "$program" "$program/web" "$units"
install -m 644 "$source_dir"/{fritzmonitor,probe,configure,fritzrouter,hosts,collector,archive,webapp}.py "$program/"
install -m 644 "$source_dir"/web/{index.html,style.css,app.js} "$program/web/"
install -m 644 "$source_dir/fritzmonitor.service" "$units/fritzmonitor.service"
systemctl --user daemon-reload

printf 'Program installed in %s\n' "$program"
printf 'Initial setup    python3 %s/configure.py\n' "$program"
printf '%s\n' 'Start at boot              systemctl --user enable --now fritzmonitor.service'
