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

setup_ssh_hardening() {
  print_section "Aufgabe 2: SSH-Härtung (Robuste Implementation)"
  
  # Lokale Variablen für Zustandsverfolgung
  local phase="PREPARATION"
  local ssh_key_deployed=false
  local ssh_port_changed=false
  local ssh_config_hardened=false
  local original_config_backed_up=false
  local backup_timestamp=$(date +"%Y%m%d_%H%M%S")
  
  # Rollback-Funktion
  rollback_ssh_changes() {
    local error_phase=$1
    echo -e "${RED}Fehler in Phase: $error_phase${NC}"
    echo -e "${YELLOW}Führe Rollback durch...${NC}"
    
    case $error_phase in
      "PORT_CHANGE"|"CONFIG_HARDENING")
        if [ "$original_config_backed_up" = true ]; then
          echo "Stelle ursprüngliche SSH-Konfiguration wieder her..."
          run_ssh_command_with_password "sudo cp /etc/ssh/sshd_config.backup_${backup_timestamp} /etc/ssh/sshd_config"
          run_ssh_command_with_password "sudo systemctl restart ssh"
          echo -e "${GREEN}✓ SSH-Konfiguration wurde wiederhergestellt${NC}"
        fi
        ;;
      "KEY_DEPLOYMENT")
        echo "Entferne eventuell fehlerhafte SSH-Keys..."
        run_ssh_command_with_password "rm -f ~/.ssh/authorized_keys.backup_${backup_timestamp}"
        ;;
    esac
    
    echo -e "${RED}SSH-Härtung abgebrochen. System sollte im ursprünglichen Zustand sein.${NC}"
    return 1
  }
  
  # =============================================================================
  # PHASE 1: VORBEREITUNG UND VALIDIERUNG
  # =============================================================================
  
  phase="PREPARATION"
  echo -e "${BLUE}[PHASE 1]${NC} Vorbereitung und Validierung"
  
  # Grundlegende Konnektivität prüfen
  if ! check_server_connectivity; then
    echo -e "${RED}✗ Server nicht erreichbar${NC}"
    return 1
  fi
  
  # SSH-Verbindung mit Passwort testen
  echo "Teste SSH-Verbindung mit Passwort..."
  if ! run_ssh_command_with_password "echo 'SSH-Verbindung funktioniert'"; then
    echo -e "${RED}✗ SSH-Verbindung mit Passwort fehlgeschlagen${NC}"
    return 1
  fi
  echo -e "${GREEN}✓ SSH-Verbindung mit Passwort erfolgreich${NC}"
  
  # SSH-Key prüfen/generieren
  echo "Prüfe SSH-Key auf vmKL1..."
  if [ ! -f ~/.ssh/id_ed25519 ]; then
    echo "Generiere neuen ED25519 SSH-Key..."
    ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N "" -C "vmadmin@vmKL1"
    if [ $? -ne 0 ]; then
      echo -e "${RED}✗ SSH-Key-Generierung fehlgeschlagen${NC}"
      return 1
    fi
    echo -e "${GREEN}✓ SSH-Key erfolgreich generiert${NC}"
  else
    echo -e "${GREEN}✓ SSH-Key bereits vorhanden${NC}"
  fi
  
  # Backup der aktuellen SSH-Konfiguration erstellen
  echo "Erstelle Backup der SSH-Konfiguration..."
  if run_ssh_command_with_password "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup_${backup_timestamp}"; then
    original_config_backed_up=true
    echo -e "${GREEN}✓ SSH-Konfiguration gesichert${NC}"
  else
    echo -e "${RED}✗ Backup der SSH-Konfiguration fehlgeschlagen${NC}"
    return 1
  fi
  
  # =============================================================================
  # PHASE 2: SSH-KEY DEPLOYMENT (SICHER)
  # =============================================================================
  
  phase="KEY_DEPLOYMENT"
  echo -e "\n${BLUE}[PHASE 2]${NC} SSH-Key sicher deployment"
  
  # SSH-Verzeichnis auf Server vorbereiten
  echo "Bereite SSH-Verzeichnis auf vmLM1 vor..."
  if ! run_ssh_command_with_password "mkdir -p ~/.ssh && chmod 700 ~/.ssh"; then
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # Backup der existierenden authorized_keys (falls vorhanden)
  run_ssh_command_with_password "[ -f ~/.ssh/authorized_keys ] && cp ~/.ssh/authorized_keys ~/.ssh/authorized_keys.backup_${backup_timestamp} || true"
  
  # Public Key übertragen (sicher)
  echo "Übertrage SSH-Public-Key..."
  local temp_key_file=$(mktemp)
  cat ~/.ssh/id_ed25519.pub > "$temp_key_file"
  
  if sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT "$temp_key_file" $USERNAME@$SERVER_IP:~/.ssh/authorized_keys.new; then
    rm "$temp_key_file"
    echo -e "${GREEN}✓ Public Key übertragen${NC}"
  else
    rm "$temp_key_file"
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # Key auf Server installieren und Berechtigungen setzen
  if ! run_ssh_command_with_password "mv ~/.ssh/authorized_keys.new ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chown $USERNAME:$USERNAME ~/.ssh/authorized_keys"; then
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # SSH-Key-Authentifizierung testen (kritischer Test)
  echo "Teste SSH-Key-Authentifizierung auf Port $SSH_PORT..."
  local key_test_retries=3
  local key_works=false
  
  for ((i=1; i<=key_test_retries; i++)); do
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT \
           -o PasswordAuthentication=no -o PubkeyAuthentication=yes \
           -p $SSH_PORT -i ~/.ssh/id_ed25519 $USERNAME@$SERVER_IP "echo 'SSH-Key funktioniert'" &>/dev/null; then
      key_works=true
      break
    else
      echo "Versuch $i/$key_test_retries fehlgeschlagen, warte 3 Sekunden..."
      sleep 3
    fi
  done
  
  if [ "$key_works" = false ]; then
    echo -e "${RED}✗ SSH-Key-Authentifizierung funktioniert nicht${NC}"
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  ssh_key_deployed=true
  echo -e "${GREEN}✓ SSH-Key-Authentifizierung erfolgreich${NC}"
  
  # =============================================================================
  # PHASE 3: SSH-PORT ÄNDERUNG (VORSICHTIG)
  # =============================================================================
  
  phase="PORT_CHANGE"
  echo -e "\n${BLUE}[PHASE 3]${NC} SSH-Port ändern (Passwort-Auth bleibt aktiv)"
  
  # Neue SSH-Konfiguration erstellen (Port ändern, aber Passwort-Auth noch nicht deaktivieren)
  echo "Erstelle vorläufige SSH-Konfiguration (nur Port-Änderung)..."
  local temp_config=$(mktemp)
  cat > "$temp_config" << EOF
# SSH Configuration - Phase 3 (Port Change Only)
Protocol 2
Port $NEW_SSH_PORT
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key  
HostKey /etc/ssh/ssh_host_rsa_key

# Authentication (temporarily keep password auth)
PubkeyAuthentication yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
AuthorizedKeysFile .ssh/authorized_keys

# Basic Security
PermitRootLogin yes
StrictModes yes
MaxAuthTries 6
LoginGraceTime 120

# Logging
SyslogFacility AUTH
LogLevel INFO

# Basic Settings
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

  # Konfiguration übertragen
  if sshpass -p "$PASSWORD" scp -o ConnectTimeout=$SSH_TIMEOUT -P $SSH_PORT "$temp_config" $USERNAME@$SERVER_IP:~/sshd_config_phase3; then
    rm "$temp_config"
    echo -e "${GREEN}✓ Vorläufige Konfiguration übertragen${NC}"
  else
    rm "$temp_config"
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # Konfiguration anwenden
  if ! run_ssh_command_with_password "sudo mv ~/sshd_config_phase3 /etc/ssh/sshd_config && sudo chmod 644 /etc/ssh/sshd_config"; then
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # Syntax prüfen
  if ! run_ssh_command_with_password "sudo sshd -t"; then
    echo -e "${RED}✗ SSH-Konfiguration hat Syntaxfehler${NC}"
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # SSH-Dienst neu starten
  echo "Starte SSH-Dienst mit neuer Port-Konfiguration neu..."
  if ! run_ssh_command_with_password "sudo systemctl restart ssh"; then
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # Warten bis Service bereit ist
  echo "Warte 10 Sekunden für SSH-Service-Start..."
  sleep 10
  
  # Test der neuen Port-Verbindung (mit Passwort UND Key)
  echo "Teste SSH-Verbindung auf neuem Port $NEW_SSH_PORT..."
  local port_test_retries=5
  local port_works=false
  
  for ((i=1; i<=port_test_retries; i++)); do
    # Test mit SSH-Key
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT \
           -p $NEW_SSH_PORT -i ~/.ssh/id_ed25519 $USERNAME@$SERVER_IP "echo 'SSH auf Port $NEW_SSH_PORT funktioniert'" &>/dev/null; then
      port_works=true
      break
    else
      echo "Versuch $i/$port_test_retries (Key-Auth) fehlgeschlagen, warte 5 Sekunden..."
      sleep 5
    fi
  done
  
  if [ "$port_works" = false ]; then
    echo -e "${RED}✗ SSH auf Port $NEW_SSH_PORT nicht erreichbar${NC}"
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  ssh_port_changed=true
  echo -e "${GREEN}✓ SSH läuft erfolgreich auf Port $NEW_SSH_PORT${NC}"
  
  # =============================================================================
  # PHASE 4: FINALE HÄRTUNG (NUR WENN ALLES FUNKTIONIERT)
  # =============================================================================
  
  phase="CONFIG_HARDENING"
  echo -e "\n${BLUE}[PHASE 4]${NC} Finale SSH-Härtung anwenden"
  
  # Gehärtete SSH-Konfiguration erstellen
  echo "Erstelle finale gehärtete SSH-Konfiguration..."
  local temp_hardened_config=$(mktemp)
  cat > "$temp_hardened_config" << EOF
# SSH Configuration - Final Hardened Settings
# Generated by HFI_SA Hardening Script

# Protocol and Connection
Protocol 2
Port $NEW_SSH_PORT

# Host Keys
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key

# Session Management
MaxSessions 3
MaxAuthTries 3
LoginGraceTime 30
MaxStartups 2:30:10

# Authentication - HARDENED
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitRootLogin no
PermitEmptyPasswords no
AuthorizedKeysFile .ssh/authorized_keys

# Connection Security
StrictModes yes
ClientAliveInterval 300
ClientAliveCountMax 2

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Feature Restrictions - HARDENED
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no

# Banner and Environment
PrintMotd no
PrintLastLog yes
AcceptEnv LANG LC_*

# Subsystems
Subsystem sftp /usr/lib/openssh/sftp-server

# Additional Security
UseDNS no
PermitUserEnvironment no
EOF

  # Gehärtete Konfiguration übertragen
  if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT -i ~/.ssh/id_ed25519 -p $NEW_SSH_PORT $USERNAME@$SERVER_IP "cat > ~/sshd_config_hardened" < "$temp_hardened_config"; then
    rm "$temp_hardened_config"
    echo -e "${GREEN}✓ Gehärtete Konfiguration übertragen${NC}"
  else
    rm "$temp_hardened_config"
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # Syntax der gehärteten Konfiguration prüfen
  if ! run_ssh_command_with_key "sudo cp ~/sshd_config_hardened /tmp/sshd_test && sudo sshd -t -f /tmp/sshd_test"; then
    echo -e "${RED}✗ Gehärtete SSH-Konfiguration hat Syntaxfehler${NC}"
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # Gehärtete Konfiguration anwenden
  echo "Wende finale gehärtete SSH-Konfiguration an..."
  if ! run_ssh_command_with_key "sudo mv ~/sshd_config_hardened /etc/ssh/sshd_config && sudo chmod 644 /etc/ssh/sshd_config"; then
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # SSH-Dienst mit gehärteter Konfiguration neu starten
  echo "Starte SSH-Dienst mit gehärteter Konfiguration neu..."
  if ! run_ssh_command_with_key "sudo systemctl restart ssh"; then
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  # Finaler kritischer Test - warten und mehrfach testen
  echo "Warte 15 Sekunden für SSH-Service-Start mit gehärteter Konfiguration..."
  sleep 15
  
  echo "Führe finalen SSH-Verbindungstest durch..."
  local final_test_retries=5
  local final_test_success=false
  
  for ((i=1; i<=final_test_retries; i++)); do
    if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT \
           -o PasswordAuthentication=no -o PubkeyAuthentication=yes \
           -p $NEW_SSH_PORT -i ~/.ssh/id_ed25519 $USERNAME@$SERVER_IP "echo 'SSH-Härtung erfolgreich abgeschlossen'" &>/dev/null; then
      final_test_success=true
      break
    else
      echo "Finaler Test Versuch $i/$final_test_retries fehlgeschlagen, warte 5 Sekunden..."
      sleep 5
    fi
  done
  
  if [ "$final_test_success" = false ]; then
    echo -e "${RED}✗ Finale SSH-Verbindung fehlgeschlagen${NC}"
    rollback_ssh_changes "$phase"
    return 1
  fi
  
  ssh_config_hardened=true
  
  # =============================================================================
  # PHASE 5: VALIDIERUNG UND ABSCHLUSS
  # =============================================================================
  
  phase="VALIDATION"
  echo -e "\n${BLUE}[PHASE 5]${NC} Validierung und Abschluss"
  
  # Umfassende Validierung der SSH-Härtung
  echo "Validiere SSH-Härtung..."
  
  # Test 1: Key-only Authentication
  if ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=$SSH_TIMEOUT \
         -o PasswordAuthentication=no -o PubkeyAuthentication=yes \
         -p $NEW_SSH_PORT -i ~/.ssh/id_ed25519 $USERNAME@$SERVER_IP "echo 'Key-Auth: OK'" &>/dev/null; then
    echo -e "${GREEN}✓ SSH-Key-Authentifizierung funktioniert${NC}"
  else
    echo -e "${RED}✗ SSH-Key-Authentifizierung fehlgeschlagen${NC}"
    return 1
  fi
  
  # Test 2: Password Authentication disabled (sollte fehlschlagen)
  if timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
         -o PasswordAuthentication=yes -o PubkeyAuthentication=no \
         -p $NEW_SSH_PORT $USERNAME@$SERVER_IP "echo 'Password-Auth should fail'" &>/dev/null; then
    echo -e "${RED}✗ Passwort-Authentifizierung ist noch aktiv (sollte deaktiviert sein)${NC}"
    return 1
  else
    echo -e "${GREEN}✓ Passwort-Authentifizierung ist deaktiviert${NC}"
  fi
  
  # Test 3: Root Login disabled (sollte fehlschlagen)
  if timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
         -p $NEW_SSH_PORT root@$SERVER_IP "echo 'Root login should fail'" &>/dev/null; then
    echo -e "${RED}✗ Root-Login ist noch möglich (sollte deaktiviert sein)${NC}"
    return 1
  else
    echo -e "${GREEN}✓ Root-Login ist deaktiviert${NC}"
  fi
  
  # SSH-Konfiguration anzeigen
  echo -e "\n${YELLOW}Aktuelle SSH-Konfiguration (relevante Zeilen):${NC}"
  run_ssh_command_with_key "grep -E '^(Port|PasswordAuthentication|PubkeyAuthentication|PermitRootLogin)' /etc/ssh/sshd_config"
  
  # Status-Informationen
  echo -e "\n${YELLOW}SSH-Service-Status:${NC}"
  run_ssh_command_with_key "sudo systemctl status ssh --no-pager -l"
  
  # Globale Variable setzen
  SSH_HARDENED=true
  
  echo -e "\n${GREEN}===========================================${NC}"
  echo -e "${GREEN}SSH-HÄRTUNG ERFOLGREICH ABGESCHLOSSEN${NC}"
  echo -e "${GREEN}===========================================${NC}"
  echo -e "${GREEN}✓ SSH läuft auf Port: $NEW_SSH_PORT${NC}"
  echo -e "${GREEN}✓ Nur SSH-Key-Authentifizierung aktiv${NC}"
  echo -e "${GREEN}✓ Passwort-Authentifizierung deaktiviert${NC}"
  echo -e "${GREEN}✓ Root-Login deaktiviert${NC}"
  echo -e "${GREEN}✓ Erweiterte Sicherheitsmaßnahmen aktiv${NC}"
  echo ""
  echo -e "${YELLOW}Backup der ursprünglichen Konfiguration: /etc/ssh/sshd_config.backup_${backup_timestamp}${NC}"
  
  pause_for_screenshot
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
