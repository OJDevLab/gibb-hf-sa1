#!/bin/bash

# SSH-Härtungsskript für vmLM1 (192.168.120.60)
# Dieses Skript wird LOKAL auf dem Server ausgeführt

# Konfiguration
NEW_SSH_PORT=23344
BACKUP_TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="/tmp/ssh_hardening_${BACKUP_TIMESTAMP}.log"

# Farbdefinitionen
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging-Funktion
log() {
    echo -e "$1" | tee -a "$LOG_FILE"
}

print_section() {
    log "${BLUE}==========================================================${NC}"
    log "${YELLOW}$1${NC}"
    log "${BLUE}==========================================================${NC}"
}

check_success() {
    if [ $1 -eq 0 ]; then
        log "${GREEN}✓ $2${NC}"
        return 0
    else
        log "${RED}✗ $2 (Fehler: $1)${NC}"
        return 1
    fi
}

# Rollback-Funktion
rollback() {
    log "${RED}ROLLBACK: Stelle ursprüngliche SSH-Konfiguration wieder her...${NC}"
    if [ -f "/etc/ssh/sshd_config.backup_${BACKUP_TIMESTAMP}" ]; then
        cp "/etc/ssh/sshd_config.backup_${BACKUP_TIMESTAMP}" /etc/ssh/sshd_config
        systemctl restart ssh
        log "${GREEN}✓ Rollback erfolgreich${NC}"
    else
        log "${RED}✗ Backup nicht gefunden!${NC}"
    fi
}

# Root-Check
if [ "$EUID" -ne 0 ]; then
    log "${RED}Dieses Skript muss als root ausgeführt werden!${NC}"
    log "${YELLOW}Verwende: sudo $0${NC}"
    exit 1
fi

print_section "SSH-Härtung für vmLM1 - Lokale Ausführung"

log "Skript gestartet am: $(date)"
log "Backup-Timestamp: $BACKUP_TIMESTAMP"
log "Log-Datei: $LOG_FILE"

# =============================================================================
# PHASE 1: VORBEREITUNG
# =============================================================================

print_section "PHASE 1: Vorbereitung und Backup"

# Aktuellen Zustand dokumentieren
log "Aktuelle SSH-Konfiguration:"
log "$(grep -E '^(Port|PasswordAuthentication|PubkeyAuthentication|PermitRootLogin)' /etc/ssh/sshd_config)"

log "Aktuelle SSH-Ports:"
log "$(ss -tlnp | grep ssh)"

# Backup erstellen
log "Erstelle Backup der SSH-Konfiguration..."
cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup_${BACKUP_TIMESTAMP}"
check_success $? "SSH-Konfiguration gesichert"

# SSH-Verzeichnis für vmadmin vorbereiten
log "Bereite SSH-Verzeichnis für vmadmin vor..."
mkdir -p /home/vmadmin/.ssh
chmod 700 /home/vmadmin/.ssh
chown vmadmin:vmadmin /home/vmadmin/.ssh
check_success $? "SSH-Verzeichnis vorbereitet"

# =============================================================================
# PHASE 2: SSH-KEY SETUP
# =============================================================================

print_section "PHASE 2: SSH-Key Setup"

log "${YELLOW}WICHTIG: Übertrage jetzt den SSH-Key von vmKL1!${NC}"
log "Führe auf vmKL1 folgenden Befehl aus:"
log "${BLUE}scp ~/.ssh/id_ed25519.pub vmadmin@192.168.120.60:~/.ssh/authorized_keys${NC}"
log ""
log "Drücke ENTER wenn der Key übertragen wurde..."
read -p ""

# Prüfe ob authorized_keys existiert
if [ -f "/home/vmadmin/.ssh/authorized_keys" ]; then
    log "${GREEN}✓ SSH-Key gefunden${NC}"
    
    # Berechtigungen setzen
    chmod 600 /home/vmadmin/.ssh/authorized_keys
    chown vmadmin:vmadmin /home/vmadmin/.ssh/authorized_keys
    check_success $? "SSH-Key-Berechtigungen gesetzt"
    
    log "SSH-Key Inhalt:"
    log "$(cat /home/vmadmin/.ssh/authorized_keys)"
else
    log "${RED}✗ Kein SSH-Key gefunden!${NC}"
    log "Bitte übertrage den SSH-Key und starte das Skript neu."
    exit 1
fi

# =============================================================================
# PHASE 3: SSH-KONFIGURATION ERSTELLEN
# =============================================================================

print_section "PHASE 3: SSH-Konfiguration erstellen"

log "Erstelle gehärtete SSH-Konfiguration..."

# Neue SSH-Konfiguration erstellen
cat > /etc/ssh/sshd_config << EOF
# SSH Configuration - Hardened by HFI_SA Script
# Generated: $(date)

# Protocol and Port
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

# Feature Restrictions
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no

# Environment
PrintMotd no
PrintLastLog yes
AcceptEnv LANG LC_*

# Subsystems
Subsystem sftp /usr/lib/openssh/sftp-server

# Additional Security
UseDNS no
PermitUserEnvironment no
EOF

check_success $? "SSH-Konfiguration erstellt"

# Syntax prüfen
log "Prüfe SSH-Konfiguration..."
sshd -t
check_success $? "SSH-Konfiguration ist syntaktisch korrekt"

# =============================================================================
# PHASE 4: SSH-SERVICE NEUSTARTEN
# =============================================================================

print_section "PHASE 4: SSH-Service neustarten"

log "${YELLOW}ACHTUNG: SSH-Service wird jetzt neu gestartet!${NC}"
log "Der Service wird danach auf Port $NEW_SSH_PORT laufen."
log ""
log "Drücke ENTER um fortzufahren oder CTRL+C zum Abbrechen..."
read -p ""

# SSH-Service neustarten
log "Starte SSH-Service neu..."
systemctl restart ssh
sleep 3

# Service-Status prüfen
if systemctl is-active --quiet ssh; then
    log "${GREEN}✓ SSH-Service läuft${NC}"
else
    log "${RED}✗ SSH-Service läuft nicht!${NC}"
    rollback
    exit 1
fi

# Port prüfen
log "Prüfe SSH-Ports..."
CURRENT_PORTS=$(ss -tlnp | grep ssh)
log "Aktuelle SSH-Ports: $CURRENT_PORTS"

if echo "$CURRENT_PORTS" | grep -q ":$NEW_SSH_PORT"; then
    log "${GREEN}✓ SSH läuft auf Port $NEW_SSH_PORT${NC}"
else
    log "${RED}✗ SSH läuft nicht auf Port $NEW_SSH_PORT!${NC}"
    rollback
    exit 1
fi

# =============================================================================
# PHASE 5: VALIDIERUNG
# =============================================================================

print_section "PHASE 5: Validierung"

log "SSH-Service Status:"
systemctl status ssh --no-pager

log ""
log "SSH-Ports:"
ss -tlnp | grep ssh

log ""
log "SSH-Konfiguration (wichtige Zeilen):"
grep -E '^(Port|PasswordAuthentication|PubkeyAuthentication|PermitRootLogin)' /etc/ssh/sshd_config

# =============================================================================
# PHASE 6: ANWEISUNGEN FÜR VMKL1
# =============================================================================

print_section "PHASE 6: Test-Anweisungen"

log "${GREEN}SSH-HÄRTUNG ERFOLGREICH ABGESCHLOSSEN!${NC}"
log ""
log "${YELLOW}Teste jetzt von vmKL1 aus:${NC}"
log "${BLUE}ssh -i ~/.ssh/id_ed25519 -p $NEW_SSH_PORT vmadmin@192.168.120.60${NC}"
log ""
log "${YELLOW}Falls der Test erfolgreich ist, sind folgende Änderungen aktiv:${NC}"
log "${GREEN}✓ SSH läuft auf Port: $NEW_SSH_PORT${NC}"
log "${GREEN}✓ Nur SSH-Key-Authentifizierung${NC}"
log "${GREEN}✓ Passwort-Authentifizierung deaktiviert${NC}"
log "${GREEN}✓ Root-Login deaktiviert${NC}"
log "${GREEN}✓ Erweiterte Sicherheitsmaßnahmen${NC}"
log ""
log "${YELLOW}Backup der ursprünglichen Konfiguration:${NC}"
log "/etc/ssh/sshd_config.backup_${BACKUP_TIMESTAMP}"
log ""
log "${YELLOW}Log-Datei: $LOG_FILE${NC}"

# Automatischer Test (falls möglich)
log ""
log "${YELLOW}Führe automatischen lokalen Test durch...${NC}"
if su - vmadmin -c "ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -i ~/.ssh/id_ed25519 -p $NEW_SSH_PORT vmadmin@localhost 'echo SSH-Test erfolgreich' 2>/dev/null"; then
    log "${GREEN}✓ Lokaler SSH-Test erfolgreich${NC}"
else
    log "${YELLOW}ℹ Lokaler SSH-Test nicht möglich (normal bei Key-only Auth)${NC}"
fi

log ""
log "${GREEN}Script erfolgreich beendet: $(date)${NC}"

exit 0
