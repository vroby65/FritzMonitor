# FritzMonitor

Monitor Internet locale per Linux Mint 22.2 e FRITZ!Box. Legge il flusso diagnostico del router via HTTPS, usa TShark per estrarre metadati e conserva aggregati di cinque minuti in SQLite. La dashboard si apre su [127.0.0.1:8090](http://127.0.0.1:8090/). L'acquisizione richiede solo la macchina che esegue FritzMonitor e il router.

## Compatibilità verificata

Il router provato è un **FRITZ!Box 7530 AX con FRITZ!OS 8.25**, rilevato direttamente da `/jason_boxinfo.xml` come versione `256.08.25` il 24 novembre 2026. L'accesso PBKDF2 su `/login_sid.lua?version=2` e la verifica del SID hanno funzionato. `/html/capture.html` apre la pagina autenticata `/?lp=cap`, che su questo firmware restituisce HTML da `POST /data.lua` con `page=cap`.

| Interfaccia | Risultato della prova locale |
| --- | --- |
| `3-0`, instradamento | IPv4 dei client prima del NAT e IPv6. Prova controllata di 12 invii e 12 risposte ciascuna per Wi-Fi IPv4, Ethernet IPv4 e Wi-Fi IPv6. Ogni sequenza è comparsa una volta per direzione. |
| `1-lan`, `1-wl0`, `1-wl1` | Risposta vuota nelle prove su questa unità. |
| `3-17`, internet | PCAP valido. I due IPv4 privati attesi erano assenti. |
| `4-129`, radio Wi-Fi | PCAP Wi-Fi. Nessun pacchetto IP decodificato nel campione. |
| `4-130`, radio Wi-Fi | Il campione presentava record diversi dal formato usato dalla pipeline. |

La prova prolungata su `3-0` ha ricevuto 118.261 frame IP in 20 minuti e 50 secondi con una sola apertura dello stream. Entrambi i client IPv4 attesi sono comparsi in invio e in ricezione.

L'acquisizione usa **una sola interfaccia**, `3-0` per impostazione predefinita, e conta il traffico con esattamente un indirizzo dei prefissi locali e un peer pubblico unicast. I controlli puntuali misurano i campioni osservati. Offload, percorsi VPN, cambi di firmware e prefissi guest possono modificare la copertura effettiva.

`3-0` trasmette IP senza intestazioni Ethernet. I due client IPv4 della prova sono stati associati al rispettivo MAC e nome tramite l'inventario TR‑064 HTTPS. Il demone usa anche indirizzi e tabella IPv6 del sistema locale quando c'è una corrispondenza esatta. Dove manca una corrispondenza, l'identità resta l'IP osservato. [Specifica Hosts TR‑064](https://fritz.support/resources/TR-064_Hosts.pdf)

Il firmware consegna un PCAP modificato con magic `0xa1b2cd34` e otto byte aggiuntivi per record. TShark 4.2 rifiuta quel formato quando legge da stdin. FritzMonitor lo converte in memoria in PCAP standard, preservando timestamp e lunghezze originali. Per l'incapsulamento 14 dell'interfaccia di instradamento scrive il link type standard RAW IP 101. [Formato PCAP di Wireshark](https://wiki.wireshark.org/Development/LibpcapFileFormat/) [Mappatura RAW IP di Wireshark](https://github.com/wireshark/wireshark/blob/master/wiretap/pcap-common.c)

### Progetti studiati

- `fritz-capture` documenta il login challenge/response e gli URL Start e Stop di `capture_notimeout`. Il repository riporta prove su FRITZ!Box 7530 e FRITZ!OS fino a 7.29. [J-Gras/fritz-capture](https://github.com/J-Gras/fritz-capture)
- `fritzdump` documenta FRITZ!OS 8.x e la lettura degli ID da `/data.lua`. FritzMonitor usa anche i parametri Stop ricavati dalla pagina HTML del dispositivo. [arn-c0de/fritzdump](https://github.com/arn-c0de/fritzdump)
- La documentazione del produttore descrive l'autenticazione PBKDF2 e la verifica del SID. [Nota tecnica FRITZ! sul SID](https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/AVM_Technical_Note_-_Session_ID_english_2021-05-03.pdf)

## Installazione

Sono richiesti Python 3.12, `ip` di iproute2 e TShark. Per l'installazione di TShark su Mint si può usare il pacchetto di sistema. Se il pacchetto chiede di abilitare la cattura locale agli utenti ordinari, scegliere **No**. FritzMonitor legge da una pipe e gira con i privilegi dell'utente. [Manuale TShark](https://www.wireshark.org/docs/man-pages/tshark.html)

```bash
sudo apt install tshark
python3 prototipo.py diagnostica
python3 configurazione.py
python3 prototipo.py diagnostica --autenticata
./install.sh
systemctl --user enable --now fritzmonitor.service
```

`configurazione.py` mostra l'impronta SHA-256 del certificato HTTPS del router e richiede che sia confermata. La password si digita nel terminale senza eco. Quando la pagina web chiede solo la password, premere Invio al prompt del nome utente per usare l'account selezionato dal router. FritzMonitor verifica l'impronta sulle connessioni successive. Se il certificato cambia, verificarlo e ripetere `python3 configurazione.py --aggiorna`.

La configurazione si trova in `~/.config/fritzmonitor/config.toml`, oppure sotto `XDG_CONFIG_HOME`. Il proprietario deve essere l'utente del servizio e i permessi devono essere `600`. Usare i campi di [config.example.toml](config.example.toml) per impostare subnet guest o aggiuntive, la conservazione, una porta locale diversa o un percorso di TShark. In assenza di prefissi espliciti, FritzMonitor ricava quelli IPv4 e IPv6 dall'interfaccia Linux sullo stesso collegamento del router. Dopo una modifica della configurazione, riavviare il servizio.

`loginctl show-user "$USER" -p Linger` indica se systemd può avviare l'unità utente al boot. Per abilitarlo, usare `loginctl enable-linger "$USER"` con un account autorizzato. Il servizio gira sotto l'utente e non richiede accesso al dispositivo di cattura locale. Per aggiornare i file dell'applicazione, rilanciare `./install.sh` e `systemctl --user restart fritzmonitor.service`.

```bash
systemctl --user status fritzmonitor.service
journalctl _SYSTEMD_USER_UNIT=fritzmonitor.service _UID="$(id -u)" -f
./uninstall.sh
```

La disinstallazione rimuove il servizio e il programma. Il file di configurazione e il database restano disponibili nelle directory utente. Il database predefinito è `~/.local/state/fritzmonitor/monitor.sqlite3`, oppure sotto `XDG_STATE_HOME`.

## Dashboard e dati

- La panoramica mostra l'ultima ora, lo stato dell'acquisizione e i byte inviati e ricevuti. Lo storico aggrega i dati per giorno, settimana o mese nel fuso orario locale.
- Il filtro **Dispositivo** restringe le comunicazioni a quel client. La vista mostra IP locale, nome e MAC disponibili, IP remoto, dominio osservato, protocollo e porta remota, byte, paese se disponibile e prima e ultima osservazione. La ricerca accetta anche MAC, paese e protocollo. Il CSV contiene tutte le righe corrispondenti ai filtri, incluse le pagine successive.
- Il dominio proviene dal nome in TLS/HTTP o da risposte DNS visibili e ancora valide. DNS cifrato, ECH, risposte mancanti e IP condivisi possono lasciare il campo vuoto. Il paese proviene da un database MMDB locale facoltativo indicato da `storage.geoip`. Il lettore opzionale si installa con `sudo apt install python3-maxminddb`. [Formati GeoIP supportati](https://dev.maxmind.com/geoip/docs/databases/)
- I byte sono le lunghezze originali riportate dal punto di cattura. L'archivio conserva 90 giorni per impostazione iniziale. Conserva solo metadati e conteggi, senza PCAP su disco. La dashboard non usa CDN, telemetria o servizi remoti e si limita al loopback IPv4.
- Il demone verifica la sessione ogni cinque minuti, gestisce i blocchi temporanei di accesso e ritenta con attesa crescente fino a un minuto. Un flusso interrotto può lasciare un intervallo senza osservazioni. Il cambio del certificato o le credenziali rifiutate richiedono una correzione locale.

### Attività da esaminare

- **Nuove destinazioni** indica un IP remoto osservato per la prima volta dalla rete nel periodo scelto. Il riferimento è l'archivio di FritzMonitor, soggetto alla conservazione configurata.
- **Volumi insoliti** seleziona finestre di cinque minuti con almeno 16 MiB e oltre quattro volte la media del dispositivo, calcolata su almeno 12 finestre attive nei sette giorni precedenti al confronto.
- **Dispositivi sconosciuti** mostra comunicazioni prive di un nome dall'inventario; **Porte insolite** usa un elenco fisso di porte remote comuni.
- **Attività periodiche** cerca almeno tre intervalli consecutivi fra finestre osservate, con scostamento massimo del 20% tra intervallo minimo e massimo. Sono possibili attività in background.
- **Attività notturne** usa la fascia locale configurata, inizialmente dalle 00:00 alle 06:00. Gli indicatori descrivono caratteristiche del traffico da esaminare.

## Diagnostica e copertura

Per evitare sovrapposizioni durante il collaudo, fermare temporaneamente il servizio. Annotare IP e MAC di un client Wi-Fi e uno Ethernet e far produrre traffico Internet a entrambi dopo l'apertura di ogni stream. Il comando del prototipo non scrive pacchetti su disco.

```bash
systemctl --user stop fritzmonitor.service
python3 prototipo.py diagnostica --autenticata
python3 prototipo.py copertura --secondi 20 --interfaccia 3-0 --interfaccia 1-lan --interfaccia 3-17 \
  --atteso IP_WIFI@MAC_WIFI --atteso IP_CABLATO@MAC_CABLATO
python3 prototipo.py cattura --interfaccia 3-0 --secondi 1200 \
  --atteso IP_WIFI@MAC_WIFI --atteso IP_CABLATO@MAC_CABLATO
systemctl --user start fritzmonitor.service
```

Sostituire i segnaposto con i valori reali. `bidirezionale` segnala che l'IP e l'eventuale MAC indicati compaiono sia in invio sia in ricezione. `origine_mac` distingue il MAC letto dal frame da quello associato tramite l'inventario. `--destinazione IP` isola un peer in una prova controllata. Omettere `--secondi` in `cattura` per lasciarla attiva fino a Ctrl+C. I risultati sono cumulativi per tentativo e riportati ogni dieci secondi. Per verificare IPv6, ripetere la prova con un client e un peer IPv6.

Se un firmware futuro impedisce l'acquisizione, l'alternativa senza cambiare la rete è combinare l'inventario Hosts TR‑064 con i contatori WAN del router. Questa modalità offre totali della connessione e inventario dei client. Per ottenere anche i flussi per dispositivo servirebbe un punto di osservazione pre-NAT con visibilità del traffico, per esempio un gateway o un'infrastruttura con mirroring. [Interfacce FRITZ!](https://fritz.com/en/pages/interfaces)

## Verifica del codice

```bash
python3 -m unittest discover -s tests -v
node --check web/app.js
bash -n install.sh uninstall.sh
systemd-analyze --user verify fritzmonitor.service
```
