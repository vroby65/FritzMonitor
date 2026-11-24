# Guida del progetto

FritzMonitor è un monitor Internet locale per Linux Mint, FRITZ!Box, Python 3.12, SQLite e TShark. L'interfaccia predefinita `3-0` è stata verificata su FRITZ!Box 7530 AX con FRITZ!OS 8.25.

- `configurazione.py` verifica HTTPS e accesso nel terminale e conserva le credenziali in TOML 0600. `config.example.toml` mostra i campi. `exclusive_capture` serializza il demone e le prove con lo stesso file di configurazione.
- `fritzrouter.py` implementa pin del certificato, sessione, elenco e URL di cattura. Converte il PCAP modificato del router nella pipe verso TShark.
- `prototipo.py` espone diagnostica, copertura e cattura di prova e contiene il decodificatore e la pipeline condivisi con il demone.
- `hosts.py` legge l'inventario TR-064 sul router e le informazioni IPv6 disponibili nel sistema locale.
- `fritzmonitor.py` è l'entry point permanente. `collector.py` si occupa di attribuzione e buffering. `archivio.py` contiene schema e letture SQLite. `webapp.py` serve gli asset di `web/`, API e CSV dal solo loopback IPv4.
- `install.sh`, `uninstall.sh` e `fritzmonitor.service` installano e gestiscono l'unità utente systemd.

La pipeline apre una sola interfaccia, accetta la cattura in HTTPS dal router e passa i pacchetti in memoria. SQLite conserva solo aggregati. La dashboard usa query parametrizzate e non richiede servizi esterni. L'identità deriva da IP, MAC osservato o inventario. Valori assenti restano vuoti. TShark legge da standard input senza acquisire dalle interfacce di Linux.

Prima di consegnare una modifica esegui `python3 -m unittest discover -s tests -v`, `node --check web/app.js` e `bash -n install.sh uninstall.sh`. Verifica l'unità con `systemd-analyze --user verify fritzmonitor.service`. Per cambi nella cattura, segui la diagnostica autenticata e le prove Wi-Fi ed Ethernet del README. Per cambi web, controlla filtri, esportazione CSV e layout a dimensione mobile sullo stesso server locale. Tieni allineato il README per comandi, schema di configurazione, sicurezza, risultati misurati e comportamento utente.
