#!/bin/bash

# SSH Security Enhancement Script für vmLM1 (192.168.120.60)
# Ausführung direkt auf dem Server

# Farbdefinitionen
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Neue SSH-Konfiguration
NEW_SSH_PORT=23344

# Hilfsfunktion für bessere Lesbarkeit
print_section() {
  echo -e "${BLUE}==========================================================${NC}"
  echo -e "${YELLOW}$1${NC}"
  echo -e "${BLUE}==========================================================${NC}"
  echo ""
}

# Hilfsfunktion zur Überprüfung des Erfolgs
check_command() {
  if [ $1 -eq 0 ]; then
    echo -e "${GREEN}✓ Erfolgreich${NC}"
    return 0
  else
    echo -e "${RED}✗ Fehler (Exit-Code: $1)${NC}"
    return 1
  fi
}

print_section "SSH Security Enhancement - Step 2"

echo "Prüfe ob authorized_keys existiert..."
if [ -f /home/vmadmin/.ssh/authorized_keys ]; then
    echo -e "${GREEN}✓ SSH-Keys sind bereits installiert${NC}"
else
    echo -e "${RED}✗ Keine authorized_keys gefunden!${NC}"
    echo "Bitte erst die SSH-Keys installieren!"
    exit 1
fi

echo -e "\n1. Backup der SSH-Konfiguration erstellen..."
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
check_command $?

echo -e "\n2. Neue SSH-Konfiguration erstellen..."
sudo tee /etc/ssh/sshd_config > /dev/null << EOF
# SSH Configuration with Hardened Security Settings
# --------------------------------------
# General Connection Settings
Protocol 2                    # Use SSH protocol version 2 only
Port $NEW_SSH_PORT           # Non-standard port for security

# Server Authentication Keys
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key

# Session Management & Security
MaxSessions 5                 # Limit concurrent sessions
MaxAuthTries 3                # Prevent brute force attacks
LoginGraceTime 30             # Seconds to complete login
StrictModes yes               # Check file permissions
PermitRootLogin no            # Disable direct root login

# Authentication Configuration
PubkeyAuthentication yes      # Enable key-based auth
PasswordAuthentication no     # Disable password auth
AuthorizedKeysFile .ssh/authorized_keys

# Connection Monitoring
ClientAliveInterval 300       # Check client every 5 min
ClientAliveCountMax 2         # Disconnect after 2 failed checks

# Logging Options
SyslogFacility AUTH
LogLevel VERBOSE              # Detailed logs

# Feature Restrictions
X11Forwarding no              # No X11 forwarding
AllowTcpForwarding no         # No port forwarding
AllowAgentForwarding no       # No agent forwarding
PrintMotd no                  # No message of the day

# Additional Settings
AcceptEnv LANG LC_*           # Accept language settings
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

check_command $?

echo -e "\n3. SSH-Konfiguration validieren..."
sudo sshd -t
if check_command $?; then
    echo -e "${GREEN}✓ SSH-Konfiguration ist gültig${NC}"
else
    echo -e "${RED}✗ SSH-Konfiguration hat Fehler! Wiederherstellung...${NC}"
    sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    exit 1
fi

echo -e "\n4. SSH-Dienst neustarten..."
sudo systemctl restart ssh
check_command $?

echo -e "\n5. SSH-Dienst Status prüfen..."
sudo systemctl status ssh --no-pager -l
check_command $?

echo -e "\n6. Prüfung der neuen Konfiguration..."
echo "Port-Konfiguration:"
grep "Port" /etc/ssh/sshd_config

echo -e "\nPassword Authentication:"
grep "PasswordAuthentication" /etc/ssh/sshd_config

echo -e "\nRoot Login:"
grep "PermitRootLogin" /etc/ssh/sshd_config

echo -e "\n${GREEN}=========================================${NC}"
echo -e "${GREEN}SSH-Härtung abgeschlossen!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo -e "${YELLOW}Wichtige Hinweise:${NC}"
echo -e "• SSH läuft jetzt auf Port ${NEW_SSH_PORT}"
echo -e "• Nur SSH-Key Authentifizierung erlaubt"
echo -e "• Root-Login ist deaktiviert"
echo -e "• Teste die Verbindung von vmKL1:"
echo -e "  ${BLUE}ssh -i ~/.ssh/id_ed25519 -p ${NEW_SSH_PORT} vmadmin@192.168.120.60${NC}"

echo -e "\n${YELLOW}Warte 10 Sekunden für Stabilisierung...${NC}"
sleep 10

echo -e "\n7. Finale Verbindungstest..."
if ss -tlnp | grep ":${NEW_SSH_PORT}"; then
    echo -e "${GREEN}✓ SSH hört auf Port ${NEW_SSH_PORT}${NC}"
else
    echo -e "${RED}✗ SSH hört nicht auf Port ${NEW_SSH_PORT}${NC}"
fi

echo -e "\n${GREEN}Script abgeschlossen!${NC}"
