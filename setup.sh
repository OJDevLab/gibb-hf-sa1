#!/bin/bash

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Create log file with timestamp in the same directory as the script
LOG_FILE="$SCRIPT_DIR/hfi_sa_hardening_$(date +"%Y%m%d_%H%M%S").log"
echo "Script started at $(date)" > "$LOG_FILE"

# Execute the original script and tee its output to the log file
exec > >(tee -a "$LOG_FILE") 2>&1

# Fernzugriff-Skript für HFI_SA Server-Härtung
# Ausführung auf vmKL1 (Kali Linux)

# Konfiguration für SSH
SERVER_IP="192.168.120.60"
USERNAME="vmadmin"
PASSWORD="sml12345"
SSH_PORT=22
NEW_SSH_PORT=23344
SSH_TIMEOUT=10  # Timeout für SSH-Verbindungen in Sekunden

# Pfad für lokale Backups
BACKUP_DIR="$HOME/hfi_sa_backups"

# Farbdefinitionen
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Hilfsfunktion für bessere Lesbarkeit
print_section() {
  echo -e "${BLUE}==========================================================${NC}"
  echo -e "${YELLOW}$1${NC}"
  echo -e "${BLUE}==========================================================${NC}"
  echo ""
}

# Hilfsfunktion für Screenshot-Pausen
pause_for_screenshot() {
  echo ""
  echo -e "${RED}>>> SCREENSHOT JETZT MACHEN! <<<${NC}"
  echo -e "${YELLOW}Drücke ENTER um fortzufahren...${NC}"
  read -p ""
}

# Funktion zum Löschen von SSH-Daten
clean_ssh_data() {
  print_section "SSH-Verbindungsdaten löschen"
  
  echo "Lösche Host-Keys für $SERVER_IP..."
  ssh-keygen -f "$HOME/.ssh/known_hosts" -R "$SERVER_IP" 2>/dev/null
  status_ip=$?
  
  echo "Lösche Host-Keys für Hostnamen (li223-vmLM1, vmlm1)..."
  ssh-keygen -f "$HOME/.ssh/known_hosts" -R "li223-vmLM1" 2>/dev/null
  ssh-keygen -f "$HOME/.ssh/known_hosts" -R "vmlm1" 2>/dev/null
  
  if [ $status_ip -eq 0 ]; then
    echo -e "${GREEN}✓ SSH-Verbindungsdaten wurden erfolgreich bereinigt${NC}"
  else
    echo -e "${YELLOW}ℹ Keine Einträge für $SERVER_IP gefunden oder bereits gelöscht${NC}"
  fi
  
  echo -e "\n${YELLOW}Drücke ENTER um fortzufahren...${NC}"
  read -p ""
}

# SSH-Befehl mit Passwort (für die erste Verbindung)
run_ssh_command_with_password() {
  # Führt den Befehl mit Timeout aus und gibt Exit-Status zurück
  sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT -p $SSH_PORT $USERNAME@$SERVER_IP "$1"
  local exit_status=$?
  if [ $exit_status -ne 0 ]; then
    echo -e "${RED}Fehler beim Ausführen des Befehls über SSH: $1${NC}"
    return $exit_status
  fi
  return 0
}

# SSH-Befehl mit Key (nach der SSH-Härtung)
run_ssh_command_with_key() {
  # Führt den Befehl mit Timeout aus und gibt Exit-Status zurück
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -p $NEW_SSH_PORT $USERNAME@$SERVER_IP "$1"
  local exit_status=$?
  if [ $exit_status -ne 0 ]; then
    echo -e "${RED}Fehler beim Ausführen des Befehls über SSH mit Key: $1${NC}"
    return $exit_status
  fi
  return 0
}

# Hilfsfunktion zum Ausführen von Befehlen je nach SSH-Status
run_command() {
  if [ "$SSH_HARDENED" = true ]; then
    run_ssh_command_with_key "$1"
    return $?
  else
    run_ssh_command_with_password "$1"
    return $?
  fi
}

# Hilfsfunktion zur Überprüfung des Erfolgs eines Befehls
check_command() {
  if [ $1 -eq 0 ]; then
    echo -e "${GREEN}✓ Erfolgreich ausgeführt${NC}"
    return 0
  else
    echo -e "${RED}✗ Fehler bei der Ausführung (Exit-Code: $1)${NC}"
    return 1
  fi
}

# Hilfsfunktion für Backup von Konfigurationsdateien
backup_remote_file() {
  local remote_file=$1
  local backup_name=$(basename "$remote_file")
  local timestamp=$(date +"%Y%m%d_%H%M%S")
  local backup_file="${BACKUP_DIR}/${backup_name}_${timestamp}"
  
  # Erstelle Backup-Verzeichnis wenn es nicht existiert
  mkdir -p "$BACKUP_DIR"
  
  echo "Erstelle Backup von $remote_file..."
  
  if [ "$SSH_HARDENED" = true ]; then
    scp -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT $USERNAME@$SERVER_IP:$remote_file "$backup_file"
  else
    sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT $USERNAME@$SERVER_IP:$remote_file "$backup_file"
  fi
  
  if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Backup erstellt: $backup_file${NC}"
    return 0
  else
    echo -e "${RED}✗ Fehler beim Erstellen des Backups von $remote_file${NC}"
    return 1
  fi
}

# Prüfen, ob der Server erreichbar ist
check_server_connectivity() {
  echo "Prüfe Verbindung zum Server $SERVER_IP..."
  
  if ping -c 1 -W 2 "$SERVER_IP" &> /dev/null; then
    echo -e "${GREEN}✓ Server ist erreichbar${NC}"
    return 0
  else
    echo -e "${RED}✗ Server ist nicht erreichbar!${NC}"
    return 1
  fi
}

# ====================================================================
# Auftrag 1: Server Härtung
# ====================================================================

# Aufgabe 1: Automatische Updates
setup_auto_updates() {
  print_section "Aufgabe 1: Automatische Updates einrichten"
  
  # Prüfe Konnektivität
  check_server_connectivity || return 1
  
  echo "Updates werden installiert..."
  run_ssh_command_with_password "sudo apt update && sudo apt upgrade -y"
  check_command $?
  
  echo "Installation von unattended-upgrades..."
  run_ssh_command_with_password "sudo apt install -y unattended-upgrades"
  check_command $?
  
  # Prüfe ob das Paket installiert wurde
  echo "Prüfe Installation..."
  run_ssh_command_with_password "dpkg -l | grep unattended-upgrades"
  check_command $? || echo -e "${YELLOW}Warnung: Installation konnte nicht verifiziert werden${NC}"
  
  echo "Konfiguration von unattended-upgrades..."
  echo "HINWEIS: Bei der Konfiguration wird 'Yes' für die automatische Installation der Updates gewählt"
  run_ssh_command_with_password "DEBIAN_FRONTEND=noninteractive sudo -E dpkg-reconfigure --priority=low unattended-upgrades"
  check_command $?
  
  # Aktiviere den Dienst
  echo "Aktiviere und starte den Dienst..."
  run_ssh_command_with_password "sudo systemctl enable unattended-upgrades && sudo systemctl start unattended-upgrades"
  check_command $?
  
  echo -e "\n${YELLOW}Status der automatischen Updates:${NC}"
  run_ssh_command_with_password "sudo systemctl status unattended-upgrades"
  
  echo -e "\n${YELLOW}Konfigurationsdatei für automatische Updates:${NC}"
  run_ssh_command_with_password "cat /etc/apt/apt.conf.d/20auto-upgrades"
  
  # Prüfen ob Updates automatisch konfiguriert sind
  echo "Prüfe Konfiguration..."
  run_ssh_command_with_password "grep 'APT::Periodic::Unattended-Upgrade' /etc/apt/apt.conf.d/20auto-upgrades"
  if check_command $?; then
    echo -e "${GREEN}✓ Automatische Updates sind konfiguriert${NC}"
  else
    echo -e "${RED}✗ Automatische Updates scheinen nicht korrekt konfiguriert zu sein${NC}"
  fi
  
  pause_for_screenshot
}

# Aufgabe 2: SSH-Härtung
setup_ssh_hardening() {
  print_section "Aufgabe 2: SSH-Härtung konfigurieren (mit Server-Neustart)"

  # Prüfe Konnektivität zum Server via Ping
  check_server_connectivity || return 1

  echo "1. SSH-Key auf vmKL1 generieren (falls nicht vorhanden)..."
  if [ ! -f ~/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
    if ! check_command $?; then
      echo -e "${RED}✗ Fehler beim Generieren des SSH-Keys. Abbruch.${NC}"
      return 1
    fi
  else
    echo -e "${GREEN}✓ SSH-Key existiert bereits (~/.ssh/id_ed25519).${NC}"
  fi

  echo "2. Vorbereitung der SSH-Verzeichnisse auf vmLM1 (via Port $SSH_PORT)..."
  run_ssh_command_with_password "mkdir -p ~/.ssh && chmod 700 ~/.ssh"
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler bei der Verzeichnisvorbereitung auf dem Server. Abbruch.${NC}"
    return 1
  fi

  echo "3. SSH-Key auf vmLM1 kopieren (via Port $SSH_PORT)..."
  # Temporäre Datei für authorized_keys erstellen, um existierende Keys nicht zu überschreiben, sondern hinzuzufügen
  # Stattdessen kopieren wir direkt, wie im Original, was bei erstmaliger Einrichtung üblich ist.
  # Für robustere Skripte würde man `ssh-copy-id` ähnliche Logik (Key anhängen) verwenden.
  # Originalskript überschreibt authorized_keys. Wir behalten das bei.
  mkdir -p ~/.ssh/temp # Lokales Temp-Verzeichnis
  cat ~/.ssh/id_ed25519.pub > ~/.ssh/temp/authorized_keys_for_vmLM1 # Name geändert für Klarheit
  sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT ~/.ssh/temp/authorized_keys_for_vmLM1 $USERNAME@$SERVER_IP:~/.ssh/authorized_keys
  rm -rf ~/.ssh/temp # Lokales Temp-Verzeichnis aufräumen
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Kopieren des SSH-Keys. Abbruch.${NC}"
    return 1
  fi

  echo "4. Berechtigungen für authorized_keys auf vmLM1 setzen (via Port $SSH_PORT)..."
  run_ssh_command_with_password "chmod 600 ~/.ssh/authorized_keys"
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Setzen der Berechtigungen für authorized_keys. Abbruch.${NC}"
    return 1
  fi

  echo "5. Testen des SSH-Keys (auf Port $SSH_PORT) vor der Konfigurationsänderung..."
  # Dieser Test verwendet den Standard-SSH-Port (oder $SSH_PORT) und den neu kopierten Key.
  # Wichtig: -o PasswordAuthentication=no hier erzwingen für den Test, um sicherzustellen, dass der Key verwendet wird.
  if ! ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT \
           -o PasswordAuthentication=no -o PubkeyAuthentication=yes -o KbdInteractiveAuthentication=no -o ChallengeResponseAuthentication=no \
           -p $SSH_PORT -i ~/.ssh/id_ed25519 $USERNAME@$SERVER_IP "echo 'SSH-Schlüssel funktioniert auf Port $SSH_PORT'" &>/dev/null; then
    echo -e "${RED}✗ SSH-Key-Authentifizierung auf Port $SSH_PORT fehlgeschlagen. ${NC}"
    echo -e "${YELLOW}  Mögliche Gründe: PubkeyAuthentication ist serverseitig (in /etc/ssh/sshd_config) noch nicht auf 'yes' oder der Key wurde nicht korrekt übernommen.${NC}"
    echo -e "${YELLOW}  Abbruch. Bitte manuell prüfen.${NC}"
    return 1
  else
    echo -e "${GREEN}✓ SSH-Key-Authentifizierung auf Port $SSH_PORT funktioniert!${NC}"
  fi

  echo "6. Backup der aktuellen SSH-Server-Konfiguration (/etc/ssh/sshd_config)..."
  if ! backup_remote_file "/etc/ssh/sshd_config"; then # Nutzt $SSH_HARDENED, was hier 'false' sein sollte
    echo -e "${RED}✗ Fehler beim Erstellen des lokalen Backups der Server-SSH-Konfig. Abbruch.${NC}"
    return 1
  fi
  run_ssh_command_with_password "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak_$(date +\"%Y%m%d_%H%M%S\")"
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Erstellen des Backups der SSH-Konfig auf dem Server. Abbruch.${NC}"
    return 1
  fi

  echo "7. Neue, gehärtete SSH-Konfiguration erstellen..."
  # Temporäre lokale Datei für die neue Konfiguration
  local temp_ssh_config_new="ssh_config_new_$(date +%s)"
  cat > "$temp_ssh_config_new" << EOF
# SSH Configuration with Hardened Security Settings
Protocol 2
Port $NEW_SSH_PORT
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key
MaxSessions 5
MaxAuthTries 3
LoginGraceTime 30
StrictModes yes
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
AuthorizedKeysFile .ssh/authorized_keys
ClientAliveInterval 300
ClientAliveCountMax 2
SyslogFacility AUTH
LogLevel VERBOSE
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF
  # Kein Placeholder mehr nötig, da $NEW_SSH_PORT direkt verwendet wird.

  echo "8. Neue SSH-Konfiguration auf vmLM1 übertragen (via Port $SSH_PORT)..."
  sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT "$temp_ssh_config_new" $USERNAME@$SERVER_IP:~/sshd_config_new_remote
  rm "$temp_ssh_config_new" # Lokale temporäre Datei löschen
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Übertragen der neuen SSH-Konfiguration. Abbruch.${NC}"
    return 1
  fi

  echo "9. Neue SSH-Konfiguration auf vmLM1 anwenden (via Port $SSH_PORT)..."
  run_ssh_command_with_password "sudo mv ~/sshd_config_new_remote /etc/ssh/sshd_config && sudo chmod 644 /etc/ssh/sshd_config"
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Anwenden der neuen SSH-Konfiguration. Abbruch.${NC}"
    # Versuch, das Server-Backup wiederherzustellen, falls vorhanden (Name ist dynamisch)
    # Dies ist schwierig, da wir den genauen Namen des .bak_timestamp nicht kennen ohne weitere Abfrage.
    # Das Original-Skript verwendete einen festen .bak Namen, was einfacher wiederherzustellen war.
    # Für jetzt belassen wir es bei der Fehlermeldung.
    return 1
  fi

  echo "10. Überprüfen der Syntax der neuen SSH-Konfiguration auf vmLM1 (via Port $SSH_PORT)..."
  if ! run_ssh_command_with_password "sudo sshd -t"; then
    echo -e "${RED}✗ Die neue SSH-Konfiguration enthält Syntaxfehler.${NC}"
    echo -e "${YELLOW}  Versuche, die unmittelbar zuvor erstellte Server-Sicherungskopie wiederherzustellen...${NC}"
    # Wir müssen den Namen des Backups kennen. Das Original-Skript nannte es sshd_config.bak
    # Wir haben es sshd_config.bak_TIMESTAMP genannt.
    # Sicherer wäre, den ursprünglichen .bak Namen des Originalskripts zu verwenden
    # oder den Namen hier zu konstruieren/abzurufen.
    # Für jetzt: Annahme, der Benutzer stellt es manuell wieder her oder das .bak des Originalskripts.
    run_ssh_command_with_password "ls -t /etc/ssh/sshd_config.bak_* | head -n 1 | xargs -I {} sudo cp {} /etc/ssh/sshd_config"
    echo -e "${YELLOW}  Wiederherstellungsversuch ausgeführt. Bitte Server manuell prüfen. Abbruch.${NC}"
    return 1
  else
    echo -e "${GREEN}✓ Die neue SSH-Konfiguration ist syntaktisch gültig.${NC}"
  fi

  echo "11. Neustart des SSH-Dienstes auf vmLM1 (via Port $SSH_PORT)..."
  # Diese Befehle werden über die alte Verbindung gesendet. Nach 'start' sollte der Server auf dem neuen Port lauschen.
  run_ssh_command_with_password "sudo systemctl stop ssh && sudo systemctl start ssh"
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Neustart des SSH-Dienstes auf dem Server.${NC}"
    echo -e "${YELLOW}  Versuche, die ursprüngliche SSH-Konfiguration wiederherzustellen (falls möglich)...${NC}"
    run_ssh_command_with_password "ls -t /etc/ssh/sshd_config.bak_* | head -n 1 | xargs -I {} sudo cp {} /etc/ssh/sshd_config && sudo systemctl restart ssh"
    echo -e "${YELLOW}  Wiederherstellungsversuch ausgeführt. Bitte Server manuell prüfen. Abbruch.${NC}"
    return 1
  fi
  echo "   SSH-Dienst-Neustart-Befehl gesendet. Warte 10 Sekunden, damit der Dienst auf dem neuen Port ($NEW_SSH_PORT) starten kann..."
  sleep 10

  echo "12. Kurzer Test der SSH-Verbindung auf neuem Port $NEW_SSH_PORT (vor dem Server-Neustart)..."
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -p $NEW_SSH_PORT $USERNAME@$SERVER_IP "echo 'SSH-Verbindung auf neuem Port $NEW_SSH_PORT funktioniert'" &>/dev/null; then
    echo -e "${GREEN}✓ SSH scheint auf Port $NEW_SSH_PORT zu laufen und akzeptiert Verbindungen (vor Server-Neustart).${NC}"
  else
    echo -e "${RED}✗ SSH auf Port $NEW_SSH_PORT ist NICHT erreichbar (vor Server-Neustart).${NC}"
    echo -e "${YELLOW}  Die SSH-Härtung scheint fehlgeschlagen zu sein, der Dienst läuft nicht wie erwartet auf dem neuen Port.${NC}"
    echo -e "${YELLOW}  Versuche, die ursprüngliche SSH-Konfiguration wiederherzustellen (via Port $SSH_PORT, falls noch möglich)...${NC}"
    run_ssh_command_with_password "ls -t /etc/ssh/sshd_config.bak_* | head -n 1 | xargs -I {} sudo cp {} /etc/ssh/sshd_config && sudo systemctl restart ssh"
    echo -e "${YELLOW}  Wiederherstellungsversuch ausgeführt. Bitte Server manuell prüfen. Abbruch.${NC}"
    return 1
  fi

  echo "13. Server $SERVER_IP wird neu gestartet (sudo reboot)..."
  # Sende den Reboot-Befehl über die NEUE, gerade getestete SSH-Verbindung
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -p $NEW_SSH_PORT $USERNAME@$SERVER_IP "sudo reboot" &>/dev/null
  # Kurze Pause, um dem Server Zeit zu geben, den Reboot-Befehl zu verarbeiten
  echo "   Reboot-Befehl an $SERVER_IP gesendet. Warte einige Sekunden, bevor mit Ping-Checks begonnen wird..."
  sleep 15

  echo "14. Warte, bis der Server $SERVER_IP nach dem Neustart wieder via Ping erreichbar ist..."
  local reboot_ping_retries=0
  local max_reboot_ping_retries=60 # Bis zu 5 Minuten (60 Versuche * 5 Sekunden Intervall)
  local server_is_back_ping=false
  while [ $reboot_ping_retries -lt $max_reboot_ping_retries ]; do
    if ping -c 1 -W 3 "$SERVER_IP" &> /dev/null; then
      echo -e "\n${GREEN}✓ Server $SERVER_IP ist via Ping erreichbar (nach Neustart).${NC}"
      server_is_back_ping=true
      break
    else
      reboot_ping_retries=$((reboot_ping_retries + 1))
      echo -ne "${YELLOW}\rWarte auf Server (Ping)... Versuch $reboot_ping_retries/$max_reboot_ping_retries. Nächster Versuch in 5 Sekunden... ${NC}"
      sleep 5
    fi
  done
  echo "" # Neue Zeile nach der Ping-Schleife

  if [ "$server_is_back_ping" = false ]; then
    echo -e "${RED}✗ Server $SERVER_IP ist nach $max_reboot_ping_retries Ping-Versuchen nicht erreichbar.${NC}"
    echo -e "${RED}✗ SSH-Härtung fehlgeschlagen. Server könnte Probleme beim Neustart haben oder Netzwerkprobleme.${NC}"
    return 1
  fi

  echo "15. Server ist via Ping erreichbar. Warte nun auf den SSH-Dienst auf Port $NEW_SSH_PORT..."
  # Zusätzliche Pause, damit der SSH-Dienst nach dem Booten vollständig gestartet ist
  echo "    (Warte 20 zusätzliche Sekunden für den SSH-Dienststart)"
  sleep 20

  local ssh_after_reboot_retries=0
  # Kürzere Timeout-Periode für SSH nach erfolgreichem Ping, da der Server booten sollte.
  local max_ssh_after_reboot_retries=12 # Bis zu 1 Minute (12 Versuche * 5 Sekunden Intervall)
  local ssh_on_new_port_confirmed=false
  while [ $ssh_after_reboot_retries -lt $max_ssh_after_reboot_retries ]; do
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -p $NEW_SSH_PORT $USERNAME@$SERVER_IP "echo 'SSH-Verbindung auf neuem Port $NEW_SSH_PORT nach Reboot erfolgreich'" &>/dev/null; then
      echo -e "\n${GREEN}✓ SSH läuft auf Port $NEW_SSH_PORT und akzeptiert Verbindungen (nach Server-Neustart)!${NC}"
      ssh_on_new_port_confirmed=true
      break
    else
      ssh_after_reboot_retries=$((ssh_after_reboot_retries + 1))
      echo -ne "${YELLOW}\rVersuch $ssh_after_reboot_retries/$max_ssh_after_reboot_retries: SSH auf Port $NEW_SSH_PORT (nach Reboot) nicht erreichbar. Warte 5 Sekunden... ${NC}"
      sleep 5
    fi
  done
  echo "" # Neue Zeile nach der SSH-Schleife

  if [ "$ssh_on_new_port_confirmed" = false ]; then
    echo -e "${RED}✗ SSH auf Port $NEW_SSH_PORT ist nach dem Server-Neustart und $max_ssh_after_reboot_retries Versuchen nicht erreichbar.${NC}"
    echo -e "${RED}✗ SSH-Härtung fehlgeschlagen. Überprüfen Sie den Server $SERVER_IP manuell.${NC}"
    echo -e "${YELLOW}  Eine automatische Wiederherstellung ist in diesem Zustand (nach Reboot mit vermutlich aktiver neuer SSH-Konfig) nicht sicher durchführbar.${NC}"
    return 1
  fi

  echo -e "\n${GREEN}✓ SSH-Härtung erfolgreich abgeschlossen.${NC}"
  echo -e "${GREEN}  Server $SERVER_IP läuft jetzt mit SSH auf Port $NEW_SSH_PORT und Key-Authentifizierung.${NC}"
  echo -e "${GREEN}  Passwort-Authentifizierung ist deaktiviert.${NC}"
  # Die globale Variable SSH_HARDENED wird von setup_firewall() gesetzt, basierend auf eigenen Tests.
  # Diese Funktion gibt bei Erfolg 0 zurück, was signalisiert, dass die Härtung erfolgt sein sollte.
  return 0
}

# Aufgabe 3: Firewall konfigurieren
setup_firewall() {
  print_section "Aufgabe 3: Firewall mit Default Deny konfigurieren"
  
  # Prüfe Konnektivität grundsätzlich
  check_server_connectivity || return 1
  
  # SSH-Status prüfen und lokale Variable setzen
  echo "Prüfe SSH-Verbindungsstatus..."
  local current_ssh_mode="standard"
  local ssh_works_on_new_port=false
  
  # Testen ob SSH auf Standardport funktioniert
  if ssh -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no $USERNAME@$SERVER_IP "echo 'SSH auf Port 22 funktioniert'" &> /dev/null; then
    echo -e "${GREEN}✓ SSH auf Port 22 möglich${NC}"
    current_ssh_mode="standard"
  else
    # Testen ob SSH auf dem neuen Port mit Key funktioniert
    if ssh -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 -p $NEW_SSH_PORT $USERNAME@$SERVER_IP "echo 'SSH auf Port $NEW_SSH_PORT funktioniert'" &> /dev/null; then
      echo -e "${GREEN}✓ SSH auf Port $NEW_SSH_PORT möglich${NC}"
      current_ssh_mode="hardened"
      ssh_works_on_new_port=true
    else
      echo -e "${RED}✗ Keine SSH-Verbindung möglich! Überprüfe die Server-Verbindung.${NC}"
      return 1
    fi
  fi
  
  # Setze SSH_HARDENED basierend auf dem festgestellten Status
  if [ "$current_ssh_mode" = "hardened" ]; then
    SSH_HARDENED=true
    echo -e "${GREEN}SSH läuft bereits im gehärteten Modus auf Port $NEW_SSH_PORT.${NC}"
  else
    SSH_HARDENED=false
    echo -e "${YELLOW}SSH läuft im Standardmodus auf Port 22.${NC}"
  fi
  
  # Installation der UFW prüfen oder durchführen
  echo "Installation der UFW Firewall..."
  if ! run_command "which ufw" &>/dev/null; then
    run_command "sudo apt update && sudo apt install -y ufw" 
    if ! check_command $?; then
      echo -e "${RED}✗ Fehler bei der Installation von UFW. Abbruch.${NC}"
      return 1
    fi
  else
    echo -e "${GREEN}✓ UFW ist bereits installiert.${NC}"
  fi
  
  # Backup der Firewall-Konfiguration
  echo "Backup der Firewall-Konfiguration erstellen..."
  run_command "sudo cp /etc/default/ufw /etc/default/ufw.bak"
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Erstellen des Backups. Abbruch.${NC}"
    return 1
  fi
  
  # Zurücksetzen aller Regeln
  echo "Zurücksetzen aller vorhandenen Regeln..."
  run_command "sudo ufw --force reset"
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Zurücksetzen der Firewall-Regeln. Abbruch.${NC}"
    return 1
  fi
  
  # KRITISCHER TEIL: Konfiguration der Firewall mit sicherem Ansatz
  echo -e "${YELLOW}WICHTIG: Kritischer Teil der Firewall-Konfiguration beginnt...${NC}"
  
  # 1. Den neuen SSH-Port öffnen BEVOR wir die Default-Deny-Regel setzen
  echo "Öffnen von Port $NEW_SSH_PORT für SSH..."
  run_command "sudo ufw allow $NEW_SSH_PORT/tcp"
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Öffnen des Ports $NEW_SSH_PORT. Abbruch.${NC}"
    return 1
  fi
  
  # 2. Standardport 22 temporär offen halten, wenn SSH noch nicht gehärtet ist
  if [ "$SSH_HARDENED" = false ]; then
    echo "Temporäres Offenhalten von Port 22 für die Übergangsphase..."
    run_command "sudo ufw allow 22/tcp"
    if ! check_command $?; then
      echo -e "${RED}✗ Fehler beim Öffnen des Ports 22. Abbruch.${NC}"
      return 1
    fi
  fi
  
  # 3. Default-Deny-Regel setzen
  echo "Setzen der Default-Deny-Regel..."
  run_command "sudo ufw default deny incoming && sudo ufw default allow outgoing"
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Setzen der Default-Deny-Regel. Abbruch.${NC}"
    return 1
  fi
  
  # 4. Firewall aktivieren
  echo "Aktivieren der Firewall..."
  run_command "sudo ufw --force enable"
  if ! check_command $?; then
    echo -e "${RED}✗ Fehler beim Aktivieren der Firewall. Abbruch.${NC}"
    return 1
  fi
  
  # Überprüfen, ob die Firewall korrekt aktiviert wurde
  echo "Überprüfe Firewall-Status..."
  if run_command "sudo ufw status | grep -q 'Status: active'"; then
    echo -e "${GREEN}✓ Firewall ist aktiv${NC}"
  else
    echo -e "${RED}✗ Firewall konnte nicht aktiviert werden. Abbruch.${NC}"
    return 1
  fi
  
  # Überprüfen, ob der neue SSH-Port tatsächlich geöffnet ist
  echo "Überprüfe, ob Port $NEW_SSH_PORT geöffnet ist..."
  if run_command "sudo ufw status | grep -q '$NEW_SSH_PORT/tcp'"; then
    echo -e "${GREEN}✓ Port $NEW_SSH_PORT ist offen${NC}"
  else
    echo -e "${RED}✗ Port $NEW_SSH_PORT ist nicht offen! Versuche Wiederherstellung...${NC}"
    run_command "sudo ufw allow $NEW_SSH_PORT/tcp && sudo ufw reload"
    if run_command "sudo ufw status | grep -q '$NEW_SSH_PORT/tcp'"; then
      echo -e "${GREEN}✓ Port $NEW_SSH_PORT ist jetzt offen${NC}"
    else
      echo -e "${RED}✗ Port $NEW_SSH_PORT konnte nicht geöffnet werden. Große Vorsicht!${NC}"
    fi
  fi
  
  echo -e "\n${YELLOW}Firewall-Status und Regeln:${NC}"
  run_command "sudo ufw status verbose"
  
  # KRITISCHER TEST: Testen der SSH-Verbindung auf dem neuen Port
  echo -e "${YELLOW}Teste SSH-Verbindung auf Port $NEW_SSH_PORT...${NC}"
  
  # Wenn SSH noch nicht auf dem neuen Port funktioniert hat
  if [ "$ssh_works_on_new_port" = false ]; then
    echo "Versuche eine Verbindung aufzubauen (bitte warten)..."
    sleep 5  # Kurze Pause für Stabilisierung
    
    # Mehrere Versuche für die neue Verbindung
    local connection_retries=0
    local max_retries=3
    
    while [ $connection_retries -lt $max_retries ]; do
      if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -p $NEW_SSH_PORT $USERNAME@$SERVER_IP "echo 'SSH-Verbindung erfolgreich'" &>/dev/null; then
        echo -e "${GREEN}✓ SSH-Verbindung auf Port $NEW_SSH_PORT erfolgreich!${NC}"
        SSH_HARDENED=true
        break
      else
        connection_retries=$((connection_retries + 1))
        echo -e "${YELLOW}Versuch $connection_retries/$max_retries: Verbindung auf Port $NEW_SSH_PORT fehlgeschlagen. Warte weitere 5 Sekunden...${NC}"
        sleep 5
      fi
    done
    
    if [ "$SSH_HARDENED" = false ]; then
      echo -e "${RED}✗ Konnte keine Verbindung auf Port $NEW_SSH_PORT herstellen nach mehreren Versuchen.${NC}"
      echo -e "${YELLOW}Das könnte daran liegen, dass SSH auf diesem Port noch nicht richtig konfiguriert ist.${NC}"
      echo -e "${YELLOW}Bitte stellen Sie sicher, dass SSH-Härtung BEVOR die Firewall konfiguriert wird.${NC}"
      
      echo -e "${YELLOW}Port 22 bleibt zugänglich, um nicht den Zugriff zu verlieren.${NC}"
      echo -e "${YELLOW}Wenn Sie fortfahren möchten, drücken Sie ENTER, sonst CTRL+C zum Abbruch.${NC}"
      read -p ""
      return 0  # Rückgabe 0, obwohl nicht vollständig erfolgreich
    fi
  else
    echo -e "${GREEN}✓ SSH auf Port $NEW_SSH_PORT ist bereits konfiguriert und funktioniert.${NC}"
  fi
  
  # Wenn SSH-Härtung abgeschlossen ist und SSH auf Port $NEW_SSH_PORT funktioniert,
  # können wir Port 22 schließen falls dieser noch offen ist
  if [ "$SSH_HARDENED" = true ]; then
    echo "Prüfe, ob Port 22 noch geöffnet ist..."
    if run_command "sudo ufw status | grep -q '22/tcp'"; then
      echo "SSH funktioniert auf Port $NEW_SSH_PORT. Schließe Port 22..."
      run_command "sudo ufw delete allow 22/tcp"
      if check_command $?; then
        echo -e "${GREEN}✓ Port 22 wurde erfolgreich geschlossen.${NC}"
      else
        echo -e "${RED}✗ Fehler beim Schließen von Port 22.${NC}"
      fi
    else
      echo -e "${GREEN}✓ Port 22 ist bereits geschlossen.${NC}"
    fi
  fi
  
  echo -e "\n${YELLOW}Aktueller Firewall-Status:${NC}"
  run_command "sudo ufw status verbose"
  
  echo -e "\n${GREEN}Firewall-Konfiguration abgeschlossen.${NC}"
  if [ "$SSH_HARDENED" = true ]; then
    echo -e "${GREEN}SSH läuft auf Port $NEW_SSH_PORT mit Key-Authentifizierung.${NC}"
  else
    echo -e "${YELLOW}SSH läuft noch auf dem Standardport 22.${NC}"
    echo -e "${YELLOW}Führen Sie die SSH-Härtung durch, bevor Sie die Firewall-Konfiguration abschließen.${NC}"
  fi
  
  pause_for_screenshot
  return 0
}

# ====================================================================
# Auftrag 2: Checkliste für Sicherheitspolicy
# ====================================================================

generate_security_checklist() {
  print_section "Auftrag 2: Checkliste für Sicherheitspolicy"
  
  # Prüfe Konnektivität
  check_server_connectivity || return 1
  
  echo -e "${YELLOW}Automatische Updates${NC}"
  echo "sudo systemctl status unattended-upgrades"
  run_command "sudo systemctl status unattended-upgrades | grep -E 'Active:|enabled;'"
  # Prüfe Dienststatus
  if run_command "sudo systemctl is-active unattended-upgrades | grep -q 'active'"; then
    echo -e "${GREEN}✓ Unattended-upgrades ist aktiv${NC}"
  else
    echo -e "${RED}✗ Unattended-upgrades scheint nicht aktiv zu sein${NC}"
  fi
  echo ""
  
  echo -e "${YELLOW}Authentifikation mit SSH${NC}"
  echo "sudo systemctl status ssh"
  run_command "sudo systemctl status ssh | grep -E 'Active:|running'"
  echo "grep Port /etc/ssh/sshd_config"
  run_command "grep 'Port' /etc/ssh/sshd_config"
  # Prüfe SSH-Port
  if run_command "grep -q 'Port $NEW_SSH_PORT' /etc/ssh/sshd_config"; then
    echo -e "${GREEN}✓ SSH läuft auf Port $NEW_SSH_PORT${NC}"
  else
    echo -e "${RED}✗ SSH-Port scheint nicht korrekt konfiguriert zu sein${NC}"
  fi
  echo ""
  
  echo -e "${YELLOW}Passwortauthentifikation sperren${NC}"
  echo "grep PasswordAuthentication /etc/ssh/sshd_config"
  run_command "grep 'PasswordAuthentication' /etc/ssh/sshd_config"
  # Prüfe Passwortauthentifizierung
  if run_command "grep -q 'PasswordAuthentication no' /etc/ssh/sshd_config"; then
    echo -e "${GREEN}✓ Passwortauthentifizierung ist deaktiviert${NC}"
  else
    echo -e "${RED}✗ Passwortauthentifizierung scheint nicht korrekt konfiguriert zu sein${NC}"
  fi
  echo ""
  
  echo -e "${YELLOW}Firewall mit Default-Deny-Regel${NC}"
  echo "sudo ufw status"
  run_command "sudo ufw status | grep -E 'Status:|Default:'"
  # Prüfe Firewall-Default-Policy
  if run_command "sudo ufw status | grep -q 'Default: deny (incoming)'"; then
    echo -e "${GREEN}✓ Default-Deny-Regel ist aktiv${NC}"
  else
    echo -e "${RED}✗ Default-Deny-Regel scheint nicht korrekt konfiguriert zu sein${NC}"
  fi
  echo ""
  
  echo -e "${YELLOW}Nur Port $NEW_SSH_PORT ist offen${NC}"
  echo "sudo ufw status numbered"
  run_command "sudo ufw status numbered"
  # Prüfe offene Ports
  num_rules=$(run_command "sudo ufw status numbered | grep -c ALLOW")
  if [ "$num_rules" = "1" ] && run_command "sudo ufw status | grep -q '$NEW_SSH_PORT/tcp'"; then
    echo -e "${GREEN}✓ Nur Port $NEW_SSH_PORT ist offen${NC}"
  else
    echo -e "${RED}✗ Es scheinen mehrere Ports offen zu sein${NC}"
  fi
  echo ""
  
  # Ergebnis zusammenfassen
  echo -e "${BLUE}==========================================================${NC}"
  echo -e "${YELLOW}Zusammenfassung der Sicherheitspolicy-Checkliste:${NC}"
  echo -e "${BLUE}==========================================================${NC}"
  run_command "echo 'Automatische Updates: ' && sudo systemctl is-active unattended-upgrades"
  run_command "echo 'SSH-Dienst: ' && sudo systemctl is-active ssh"
  run_command "echo 'SSH-Port: ' && grep 'Port' /etc/ssh/sshd_config"
  run_command "echo 'Passwortauthentifizierung: ' && grep 'PasswordAuthentication' /etc/ssh/sshd_config"
  run_command "echo 'Firewall-Status: ' && sudo ufw status | grep 'Status:'"
  run_command "echo 'Offene Ports: ' && sudo ufw status | grep ALLOW"
  
  pause_for_screenshot
}

# ====================================================================
# Auftrag 3: Individuelle Ergänzungen
# ====================================================================

setup_additional_hardening() {
  print_section "Auftrag 3: Individuelle Ergänzungen"
  
  # Prüfe Konnektivität
  check_server_connectivity || return 1
  
  echo "1. ICMP-Ping blockieren"
  echo "1.1. Backup der aktuellen Firewall-Regeln erstellen..."
  run_command "sudo cp /etc/ufw/before.rules /etc/ufw/before.rules.bak"
  check_command $?
  
  echo "1.2. Erstellen der Konfiguration..."
  cat > before.rules << EOF
# Modified before.rules with ICMP blocking
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
:ufw-before-forward - [0:0]
:ufw-not-local - [0:0]

# allow all on loopback
-A ufw-before-input -i lo -j ACCEPT
-A ufw-before-output -o lo -j ACCEPT

# quickly process packets for which we already have a connection
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# drop INVALID packets
-A ufw-before-input -m conntrack --ctstate INVALID -j DROP
-A ufw-before-output -m conntrack --ctstate INVALID -j DROP
-A ufw-before-forward -m conntrack --ctstate INVALID -j DROP

# ok icmp codes
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
-A ufw-before-input -p icmp --icmp-type source-quench -j ACCEPT
-A ufw-before-input -p icmp --icmp-type time-exceeded -j ACCEPT
-A ufw-before-input -p icmp --icmp-type parameter-problem -j ACCEPT
-A ufw-before-input -p icmp --icmp-type echo-request -j DROP

# allow dhcp client to work
-A ufw-before-input -p udp --sport 67 --dport 68 -j ACCEPT

# allow MULTICAST
-A ufw-before-input -m addrtype --dst-type MULTICAST -j ACCEPT

# allow broadcast
-A ufw-before-input -m addrtype --dst-type BROADCAST -j ACCEPT

COMMIT
EOF

  # Übertragen der Datei zum Server
  if [ "$SSH_HARDENED" = true ]; then
    scp -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT before.rules $USERNAME@$SERVER_IP:~/before.rules
  else
    sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT before.rules $USERNAME@$SERVER_IP:~/before.rules
  fi
  check_command $?
  
  # Anwenden der Regeln
  run_command "sudo mv ~/before.rules /etc/ufw/before.rules && sudo chmod 644 /etc/ufw/before.rules"
  check_command $?
  
  echo "2. IPv6 deaktivieren auf der Firewall"
  echo "2.1. Backup der UFW-Konfiguration erstellen..."
  run_command "sudo cp /etc/default/ufw /etc/default/ufw.bak"
  check_command $?
  
  echo "2.2. IPv6 in UFW deaktivieren..."
  run_command "sudo sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw"
  check_command $?
  
  echo "3. Neustart der Firewall..."
  run_command "sudo ufw reload"
  check_command $?
  
  # Prüfen, ob die Änderungen erfolgreich waren
  echo "4. Prüfe ICMP-Blockierung..."
  if run_command "grep -q 'echo-request -j DROP' /etc/ufw/before.rules"; then
    echo -e "${GREEN}✓ ICMP-Ping-Blockierung ist konfiguriert${NC}"
  else
    echo -e "${RED}✗ ICMP-Ping-Blockierung scheint nicht korrekt konfiguriert zu sein${NC}"
  fi
  
  echo "5. Prüfe IPv6-Deaktivierung..."
  if run_command "grep -q 'IPV6=no' /etc/default/ufw"; then
    echo -e "${GREEN}✓ IPv6 ist in UFW deaktiviert${NC}"
  else
    echo -e "${RED}✗ IPv6 scheint in UFW nicht deaktiviert zu sein${NC}"
  fi
  
  echo -e "\n${YELLOW}ICMP-Blockierung konfiguriert:${NC}"
  run_command "grep 'echo-request -j DROP' /etc/ufw/before.rules"
  
  echo -e "\n${YELLOW}IPv6 in UFW deaktiviert:${NC}"
  run_command "grep 'IPV6=' /etc/default/ufw"
  
  pause_for_screenshot
}

# ====================================================================
# Auftrag 4: Webdienst auf gehärtetem Server
# ====================================================================

setup_webserver() {
  print_section "Auftrag 4: Webdienst auf gehärtetem Server"
  
  # Prüfe Konnektivität
  check_server_connectivity || return 1
  
  echo "Installation von nginx..."
  run_command "sudo apt install -y nginx"
  check_command $?
  
  # Prüfe, ob nginx installiert wurde
  if run_command "dpkg -l | grep -q nginx"; then
    echo -e "${GREEN}✓ Nginx wurde erfolgreich installiert${NC}"
  else
    echo -e "${RED}✗ Nginx scheint nicht installiert zu sein${NC}"
    return 1
  fi
  
  echo "Öffnen von Port 80 in der Firewall..."
  run_command "sudo ufw allow 80/tcp && sudo ufw reload"
  check_command $?
  
  # Prüfe, ob Port 80 geöffnet ist
  if run_command "sudo ufw status | grep -q '80/tcp'"; then
    echo -e "${GREEN}✓ Port 80 ist in der Firewall geöffnet${NC}"
  else
    echo -e "${RED}✗ Port 80 scheint nicht in der Firewall geöffnet zu sein${NC}"
  fi
  
  echo "Erstellen der Startseite..."
  cat > index.html << EOF
<!DOCTYPE html>
<html>
<head>
    <title>GIBB HF INFORMATIK SKILL CHECK</title>
    <style>
        body {
            background-color: white;
            font-family: monospace;
            text-align: center;
            padding-top: 50px;
        }
        pre {
            font-size: 24px;
            line-height: 1.2;
        }
    </style>
</head>
<body>
    <pre>
 _____ ___ ____  ____     _   _ _____   ___ _   _ _____ ___  ____  __  __    _  _____ ___ _  __
|  ___|_ _| __ )|  _ \\   | | | |  ___| |_ _| \\ | |  ___/ _ \\|  _ \\|  \\/  |  / \\|_   _|_ _| |/ /
| |_   | ||  _ \\| |_) |  | |_| | |_     | ||  \\| | |_ | | | | |_) | |\\/| | / _ \\ | |  | || ' / 
|  _|  | || |_) |  _ <   |  _  |  _|    | || |\\  |  _|| |_| |  _ <| |  | |/ ___ \\| |  | || . \\ 
|_|   |___|____/|_| \\_\\  |_| |_|_|     |___|_| \\_|_|   \\___/|_| \\_\\_|  |_/_/   \\_\\_| |___|_|\\_\\
                                                                                               
 ____  _  _____ _     _     
/ ___|| |/ /_ _| |   | |    
\\___ \\| ' / | || |   | |    
 ___) | . \\ | || |___| |___ 
|____/|_|\\_\\___|_____|_____|
                            
  ____ _   _ _____ ____ _  __
 / ___| | | | ____/ ___| |/ /
| |   | |_| |  _|| |   | ' / 
| |___|  _  | |__| |___| . \\ 
 \\____|_| |_|_____\\____|_|\\_\\
                             
Never expose this VM to an untrusted network!
    </pre>
</body>
</html>
EOF

  # Übertragen der HTML-Datei zum Server
  if [ "$SSH_HARDENED" = true ]; then
    scp -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT index.html $USERNAME@$SERVER_IP:~/index.html
  else
    sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT index.html $USERNAME@$SERVER_IP:~/index.html
  fi
  check_command $?
  
  # Installieren der Webseite
  run_command "sudo mv ~/index.html /var/www/html/index.html && sudo chown www-data:www-data /var/www/html/index.html"
  check_command $?
  
  # Prüfe, ob die Webseite existiert
  if run_command "test -f /var/www/html/index.html"; then
    echo -e "${GREEN}✓ Webseite wurde erfolgreich installiert${NC}"
  else
    echo -e "${RED}✗ Webseite scheint nicht installiert zu sein${NC}"
  fi
  
  echo "Neustart des Webservers..."
  run_command "sudo systemctl restart nginx"
  check_command $?
  
  # Prüfe, ob Nginx läuft
  if run_command "sudo systemctl is-active nginx | grep -q 'active'"; then
    echo -e "${GREEN}✓ Nginx läuft${NC}"
  else
    echo -e "${RED}✗ Nginx scheint nicht zu laufen${NC}"
  fi
  
  echo -e "\n${YELLOW}Webserver-Status:${NC}"
  run_command "sudo systemctl status nginx | grep -E 'Active:|running'"
  
  echo -e "\n${YELLOW}Webseite kann jetzt im Browser unter http://$SERVER_IP aufgerufen werden${NC}"
  echo -e "Bitte rufe die Seite auf und mache einen Screenshot"
  
  # Teste, ob die Webseite erreichbar ist
  if curl -s --head --fail http://$SERVER_IP > /dev/null; then
    echo -e "${GREEN}✓ Webseite ist erreichbar${NC}"
  else
    echo -e "${RED}✗ Webseite scheint nicht erreichbar zu sein${NC}"
  fi
  
  pause_for_screenshot
}

# ====================================================================
# Auftrag DNS: DNS-Konfiguration
# ====================================================================

setup_dns_server() {
  print_section "Auftrag DNS: DNS-Server konfigurieren"
  
  # Prüfe Konnektivität
  check_server_connectivity || return 1
  
  echo "Installation von bind9..."
  run_command "sudo apt install -y bind9 bind9utils bind9-doc"
  check_command $?
  
  # Prüfe, ob bind9 installiert wurde
  if run_command "dpkg -l | grep -q 'bind9'"; then
    echo -e "${GREEN}✓ Bind9 wurde erfolgreich installiert${NC}"
  else
    echo -e "${RED}✗ Bind9 scheint nicht installiert zu sein${NC}"
    return 1
  fi
  
  echo "Öffnen der Ports für DNS in der Firewall..."
  run_command "sudo ufw allow 53/tcp && sudo ufw allow 53/udp && sudo ufw reload"
  check_command $?
  
  # Prüfe, ob die Ports geöffnet sind
  if run_command "sudo ufw status | grep -q '53/tcp' && sudo ufw status | grep -q '53/udp'"; then
    echo -e "${GREEN}✓ Ports für DNS sind in der Firewall geöffnet${NC}"
  else
    echo -e "${RED}✗ Ports für DNS scheinen nicht in der Firewall geöffnet zu sein${NC}"
  fi
  
  # Erstellen und Übertragen der Konfigurationsdateien
  echo "Backup der DNS-Konfiguration erstellen..."
  run_command "sudo cp /etc/bind/named.conf.options /etc/bind/named.conf.options.bak 2>/dev/null || true"
  run_command "sudo cp /etc/bind/named.conf.local /etc/bind/named.conf.local.bak 2>/dev/null || true"
  
  echo "Konfiguration der globalen DNS-Optionen..."
  cat > named.conf.options << EOF
options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { any; };
    allow-query { any; };
    forwarders { 1.1.1.1; 8.8.8.8; };
    recursion no;
    auth-nxdomain no;
    version none;
    dnssec-validation no;
};
EOF
  if [ "$SSH_HARDENED" = true ]; then
    scp -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT named.conf.options $USERNAME@$SERVER_IP:~/named.conf.options
  else
    sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT named.conf.options $USERNAME@$SERVER_IP:~/named.conf.options
  fi
  check_command $?
  
  run_command "sudo mv ~/named.conf.options /etc/bind/named.conf.options"
  check_command $?
  
  echo "Konfiguration der lokalen Zonen..."
  cat > named.conf.local << EOF
// Zone Definitions

// Primary Zone: Internal Network
zone "smartlearn.lan" {
    type master;
    file "/etc/bind/zones/db.smartlearn.lan";
    allow-transfer { none; };
};

// Primary Zone: DMZ Network
zone "smartlearn.dmz" {
    type master;
    file "/etc/bind/zones/db.smartlearn.dmz";
    allow-transfer { none; };
};

// Reverse Lookup Zones
zone "110.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.110.168.192";
    allow-transfer { none; };
};

zone "120.168.192.in-addr.arpa" {
    type master;
    file "/etc/bind/zones/db.120.168.192";
    allow-transfer { none; };
};
EOF
  if [ "$SSH_HARDENED" = true ]; then
    scp -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT named.conf.local $USERNAME@$SERVER_IP:~/named.conf.local
  else
    sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT named.conf.local $USERNAME@$SERVER_IP:~/named.conf.local
  fi
  check_command $?
  
  run_command "sudo mv ~/named.conf.local /etc/bind/named.conf.local"
  check_command $?
  
  echo "Erstellen des Zonendatei-Verzeichnisses..."
  run_command "sudo mkdir -p /etc/bind/zones"
  check_command $?
  
  # Erstellen und Übertragen der Zonendateien
  echo "Erstellen der Forward-Zone für smartlearn.lan..."
  cat > db.smartlearn.lan << EOF
\$TTL 86400
@ IN SOA dns.smartlearn.dmz. admin.smartlearn.dmz. (
    3 ; Serial
    604800 ; Refresh
    86400 ; Retry
    2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@ IN NS dns.smartlearn.dmz.

dns IN A 192.168.120.60
vmkl1 IN A 192.168.110.70
vmlf1 IN A 192.168.110.1
EOF
  if [ "$SSH_HARDENED" = true ]; then
    scp -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT db.smartlearn.lan $USERNAME@$SERVER_IP:~/db.smartlearn.lan
  else
    sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT db.smartlearn.lan $USERNAME@$SERVER_IP:~/db.smartlearn.lan
  fi
  check_command $?
  
  run_command "sudo mv ~/db.smartlearn.lan /etc/bind/zones/db.smartlearn.lan"
  check_command $?
  
  echo "Erstellen der Forward-Zone für smartlearn.dmz..."
  cat > db.smartlearn.dmz << EOF
\$TTL 86400
@ IN SOA dns.smartlearn.dmz. admin.smartlearn.dmz. (
    3 ; Serial
    604800 ; Refresh
    86400 ; Retry
    2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@ IN NS dns.smartlearn.dmz.

vmlm1   IN A 192.168.120.60
www     IN A 192.168.120.60
dns     IN A 192.168.120.60
vmlf1   IN A 192.168.120.1
EOF
  if [ "$SSH_HARDENED" = true ]; then
    scp -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT db.smartlearn.dmz $USERNAME@$SERVER_IP:~/db.smartlearn.dmz
  else
    sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT db.smartlearn.dmz $USERNAME@$SERVER_IP:~/db.smartlearn.dmz
  fi
  check_command $?
  
  run_command "sudo mv ~/db.smartlearn.dmz /etc/bind/zones/db.smartlearn.dmz"
  check_command $?
  
  echo "Erstellen der Reverse-Zone für 192.168.110.0/24..."
  cat > db.110.168.192 << EOF
\$TTL 86400
@ IN SOA dns.smartlearn.dmz. admin.smartlearn.dmz. (
    3 ; Serial
    604800 ; Refresh
    86400 ; Retry
    2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@ IN NS dns.smartlearn.dmz.

70 IN PTR vmkl1.smartlearn.lan.
1 IN PTR vmlf1.smartlearn.lan.
EOF
  if [ "$SSH_HARDENED" = true ]; then
    scp -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT db.110.168.192 $USERNAME@$SERVER_IP:~/db.110.168.192
  else
    sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT db.110.168.192 $USERNAME@$SERVER_IP:~/db.110.168.192
  fi
  check_command $?
  
  run_command "sudo mv ~/db.110.168.192 /etc/bind/zones/db.110.168.192"
  check_command $?
  
  echo "Erstellen der Reverse-Zone für 192.168.120.0/24..."
  cat > db.120.168.192 << EOF
\$TTL 86400
@ IN SOA dns.smartlearn.dmz. admin.smartlearn.dmz. (
    3 ; Serial
    604800 ; Refresh
    86400 ; Retry
    2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@ IN NS dns.smartlearn.dmz.

60 IN PTR vmlm1.smartlearn.dmz.
60 IN PTR www.smartlearn.dmz.
60 IN PTR dns.smartlearn.dmz.
1  IN PTR vmlf1.smartlearn.dmz.
EOF
  if [ "$SSH_HARDENED" = true ]; then
    scp -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT db.120.168.192 $USERNAME@$SERVER_IP:~/db.120.168.192
  else
    sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT db.120.168.192 $USERNAME@$SERVER_IP:~/db.120.168.192
  fi
  check_command $?
  
  run_command "sudo mv ~/db.120.168.192 /etc/bind/zones/db.120.168.192"
  check_command $?
  
  echo "Setzen der Berechtigungen für die Zonendateien..."
  run_command "sudo chown -R bind:bind /etc/bind/zones && sudo chmod -R 755 /etc/bind/zones"
  check_command $?
  
  echo "Überprüfen der Konfiguration..."
  run_command "sudo named-checkconf"
  check_command $?
  
  run_command "sudo named-checkzone smartlearn.lan /etc/bind/zones/db.smartlearn.lan"
  check_command $?
  
  run_command "sudo named-checkzone smartlearn.dmz /etc/bind/zones/db.smartlearn.dmz"
  check_command $?
  
  run_command "sudo named-checkzone 110.168.192.in-addr.arpa /etc/bind/zones/db.110.168.192"
  check_command $?
  
  run_command "sudo named-checkzone 120.168.192.in-addr.arpa /etc/bind/zones/db.120.168.192"
  check_command $?
  
  echo "Neustart des bind9-Dienstes..."
  run_command "sudo systemctl restart bind9"
  check_command $?
  
  # Prüfe, ob bind9 läuft
  if run_command "sudo systemctl is-active bind9 | grep -q 'active'"; then
    echo -e "${GREEN}✓ Bind9 läuft${NC}"
  else
    echo -e "${RED}✗ Bind9 scheint nicht zu laufen${NC}"
  fi
  
  echo -e "\n${YELLOW}DNS-Server-Status:${NC}"
  run_command "sudo systemctl status bind9 | grep -E 'Active:|running'"
  
  echo -e "\n${YELLOW}DNS-Abfragen testen:${NC}"
  run_command "nslookup vmkl1.smartlearn.lan 127.0.0.1"
  run_command "nslookup vmlm1.smartlearn.dmz 127.0.0.1"
  run_command "nslookup 192.168.110.70 127.0.0.1"
  
  # Prüfe, ob DNS-Abfragen funktionieren
  if run_command "nslookup vmkl1.smartlearn.lan 127.0.0.1 | grep -q '192.168.110.70'"; then
    echo -e "${GREEN}✓ Forward-Lookup für vmkl1.smartlearn.lan funktioniert${NC}"
  else
    echo -e "${RED}✗ Forward-Lookup für vmkl1.smartlearn.lan scheint nicht zu funktionieren${NC}"
  fi
  
  pause_for_screenshot
}

# ====================================================================
# Auftrag Netcat: Banner Grabbing
# ====================================================================

test_banner_grabbing() {
  print_section "Auftrag Netcat: Banner Grabbing"
  
  # Prüfe Konnektivität
  check_server_connectivity || return 1
  
  echo "Installation von netcat..."
  run_command "sudo apt install -y netcat"
  check_command $?
  
  # Prüfe, ob netcat installiert wurde
  if run_command "dpkg -l | grep -q 'netcat'"; then
    echo -e "${GREEN}✓ Netcat wurde erfolgreich installiert${NC}"
  else
    echo -e "${RED}✗ Netcat scheint nicht installiert zu sein${NC}"
  fi
  
  echo -e "\n${YELLOW}HTTP Banner Grabbing:${NC}"
  echo "Befehl: nc $SERVER_IP 80"
  echo -e "HEAD / HTTP/1.1\r\nHost: $SERVER_IP\r\n\r\n" | nc $SERVER_IP 80
  
  echo -e "\n${YELLOW}DNS Banner Grabbing:${NC}"
  echo "Befehl: echo -ne \"\\x00\\x1c...\" | nc -u $SERVER_IP 53"
  echo -ne "\x00\x1c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03" | nc -u $SERVER_IP 53 | xxd -g 1
  
  pause_for_screenshot
  
  echo "Banner Grabbing unterbinden..."
  
  echo "1. Backup der Nginx-Konfiguration erstellen..."
  run_command "sudo mkdir -p /etc/nginx/conf.d.bak && sudo cp -r /etc/nginx/conf.d/* /etc/nginx/conf.d.bak/ 2>/dev/null || true"
  
  echo "2. Webserver-Banner verstecken..."
  cat > security.conf << EOF
# Server information hiding
server_tokens off;
EOF
  if [ "$SSH_HARDENED" = true ]; then
    scp -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT security.conf $USERNAME@$SERVER_IP:~/security.conf
  else
    sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT security.conf $USERNAME@$SERVER_IP:~/security.conf
  fi
  check_command $?
  
  run_command "sudo mkdir -p /etc/nginx/conf.d && sudo mv ~/security.conf /etc/nginx/conf.d/security.conf && sudo systemctl reload nginx"
  check_command $?
  
  echo "3. DNS-Banner verstecken (bereits in der named.conf.options konfiguriert)..."
  
  # Warte kurz, bis die Änderungen wirksam werden
  sleep 2
  
  echo -e "\n${YELLOW}HTTP Banner nach Härtung:${NC}"
  echo "Befehl: nc $SERVER_IP 80"
  echo -e "HEAD / HTTP/1.1\r\nHost: $SERVER_IP\r\n\r\n" | nc $SERVER_IP 80
  
  # Prüfe, ob das Banner versteckt ist
  if ! echo -e "HEAD / HTTP/1.1\r\nHost: $SERVER_IP\r\n\r\n" | nc $SERVER_IP 80 | grep -q "nginx/"; then
    echo -e "${GREEN}✓ Nginx-Version wird nicht mehr angezeigt${NC}"
  else
    echo -e "${RED}✗ Nginx-Version wird immer noch angezeigt${NC}"
  fi
  
  pause_for_screenshot
}

# ====================================================================
# Hauptmenü
# ====================================================================

# Hauptmenü: Initialisierung
SSH_HARDENED=false

main_menu() {
  while true; do
    print_section "HFI_SA Server Härtung und Konfiguration - Hauptmenü (Ausführung von vmKL1)"
    
    echo "1. Automatische Updates einrichten"
    echo "2. SSH-Härtung durchführen"
    echo "3. Firewall konfigurieren"
    echo "4. Checkliste für Sicherheitspolicy generieren"
    echo "5. Erweiterte Härtungsmaßnahmen durchführen"
    echo "6. Webserver installieren"
    echo "7. DNS-Server konfigurieren"
    echo "8. Banner Grabbing testen & unterbinden"
    echo "9. Alle Aufgaben sequentiell ausführen"
    echo "10. SSH-Verbindungsdaten löschen (bei Host-Key-Problemen)"
    echo "0. Beenden"
    
    read -p "Wähle eine Option (0-10): " option
    
    case $option in
      1) setup_auto_updates ;;
      2) setup_ssh_hardening ;;
      3) setup_firewall ;;
      4) generate_security_checklist ;;
      5) setup_additional_hardening ;;
      6) setup_webserver ;;
      7) setup_dns_server ;;
      8) test_banner_grabbing ;;
      9) 
        setup_auto_updates
        # Führe SSH-Härtung und Firewall-Konfiguration in der richtigen Reihenfolge aus
        setup_ssh_hardening
        setup_firewall
        # Fortsetzen mit den restlichen Aufgaben
        generate_security_checklist
        setup_additional_hardening
        setup_webserver
        setup_dns_server
        test_banner_grabbing
        ;;
      10) clean_ssh_data ;;
      0) 
        echo -e "\n${GREEN}Script beendet. Viel Erfolg bei der Prüfung!${NC}"
        exit 0
        ;;
      *) 
        echo -e "\n${RED}Ungültige Option. Bitte erneut versuchen.${NC}"
        sleep 2
        ;;
    esac
  done
}

# Erstelle Backup-Verzeichnis
mkdir -p "$BACKUP_DIR"

# Prüfen, ob sshpass installiert ist
if ! command -v sshpass &> /dev/null; then
  echo "sshpass wird benötigt. Installation wird versucht..."
  sudo apt update && sudo apt install -y sshpass
  if [ $? -ne 0 ]; then
    echo "Fehler: sshpass konnte nicht installiert werden. Bitte installiere es manuell:"
    echo "sudo apt update && sudo apt install -y sshpass"
    exit 1
  fi
fi

# Starte das Hauptmenü
main_menu
