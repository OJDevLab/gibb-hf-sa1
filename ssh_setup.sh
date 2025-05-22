#!/usr/bin/env bash
set -euo pipefail

# Variablen
SSH_USER="vmadmin"
SSH_HOME="/home/${SSH_USER}"
AUTHORIZED_KEYS="${SSH_HOME}/.ssh/authorized_keys"
SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP_SUFFIX=".bak-$(date +%Y%m%d%H%M%S)"

# 1) Berechtigungen für authorized_keys setzen
echo "[*] Setze Berechtigungen für ${AUTHORIZED_KEYS}"
chmod 600 "${AUTHORIZED_KEYS}"
chown "${SSH_USER}:${SSH_USER}" "${AUTHORIZED_KEYS}"

# 2) Backup der aktuellen sshd_config
echo "[*] Backup von ${SSHD_CONFIG} nach ${SSHD_CONFIG}${BACKUP_SUFFIX}"
cp "${SSHD_CONFIG}" "${SSHD_CONFIG}${BACKUP_SUFFIX}"

# 3) Neue, gehärtete Konfiguration schreiben
echo "[*] Schreibe neue sshd_config"
cat > "${SSHD_CONFIG}" << 'EOF'
# SSH Configuration with Hardened Security Settings
# --------------------------------------

# General Connection Settings
Protocol 2                     # Nur SSHv2
Port 23344                     # Non-Standard-Port

# Server Authentication Keys
HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_rsa_key

# Session Management & Security
MaxSessions 5                  # Max. Sessions pro Verbind.
MaxAuthTries 3                 # Versuche pro Auth.
LoginGraceTime 30              # Zeit zum Einloggen (Sek.)
StrictModes yes                # Prüfe File-Perms
PermitRootLogin no             # Root-Login deaktiviert

# Authentication Configuration
PubkeyAuthentication yes       # Key-basierte Auth.
PasswordAuthentication no      # Passwort-Auth. deaktiviert
AuthorizedKeysFile .ssh/authorized_keys

# Connection Monitoring
ClientAliveInterval 300        # Alive-Check alle 5 Min.
ClientAliveCountMax 2          # 2 Fehlversuche, dann Trennen

# Logging Options
SyslogFacility AUTH
LogLevel VERBOSE               # Detaillierte Logs

# Feature Restrictions
X11Forwarding no               # X11 Forwarding deaktiviert
AllowTcpForwarding no          # TCP Forwarding deaktiviert
AllowAgentForwarding no        # Agent Forwarding deaktiviert
PrintMotd no                   # Motd nicht anzeigen
Banner /etc/issue.net          # Benutzerdefiniertes Banner

# Additional Settings
AcceptEnv LANG LC_*            # Locale-Weitergabe erlauben
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

# 4) Service neu starten und Status prüfen
echo "[*] Daemon neu laden, SSH-Service neu starten"
systemctl daemon-reload
systemctl restart ssh

echo "[*] SSH-Service Status:"
systemctl status ssh --no-pager

echo "[*] SSH-Socket Status (falls verwendet):"
systemctl status ssh.socket --no-pager

echo "[+] Fertig. Dein SSH-Daemon läuft jetzt auf Port 23344 mit gehärteter Konfiguration."
