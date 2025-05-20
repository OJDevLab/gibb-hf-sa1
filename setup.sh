#!/bin/bash

# Fernzugriff-Skript für HFI_SA Server-Härtung
# Ausführung auf vmKL1 (Kali Linux)

# Konfiguration für SSH
SERVER_IP="192.168.120.60"
USERNAME="vmadmin"
PASSWORD="sml12345"
SSH_PORT=22
NEW_SSH_PORT=23344

# Farbdefinitionen
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Hilfsfunktion für bessere Lesbarkeit
print_section() {
  clear
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

# SSH-Befehl mit Passwort (für die erste Verbindung)
run_ssh_command_with_password() {
  sshpass -p "$PASSWORD" ssh -o StrictHostKeyChecking=no -p $SSH_PORT $USERNAME@$SERVER_IP "$1"
}

# SSH-Befehl mit Key (nach der SSH-Härtung)
run_ssh_command_with_key() {
  ssh -o StrictHostKeyChecking=no -i ~/.ssh/id_ed25519 -p $NEW_SSH_PORT $USERNAME@$SERVER_IP "$1"
}

# Hilfsfunktion zum Ausführen von Befehlen je nach SSH-Status
run_command() {
  if [ "$SSH_HARDENED" = true ]; then
    run_ssh_command_with_key "$1"
  else
    run_ssh_command_with_password "$1"
  fi
}

# ====================================================================
# Auftrag 1: Server Härtung
# ====================================================================

# Aufgabe 1: Automatische Updates
setup_auto_updates() {
  print_section "Aufgabe 1: Automatische Updates einrichten"
  
  echo "Updates werden installiert..."
  run_ssh_command_with_password "sudo apt update && sudo apt upgrade -y"
  
  echo "Installation von unattended-upgrades..."
  run_ssh_command_with_password "sudo apt install -y unattended-upgrades"
  
  echo "Konfiguration von unattended-upgrades..."
  echo "HINWEIS: Bei der Konfiguration wähle 'Yes' für die automatische Installation der Updates"
  run_ssh_command_with_password "DEBIAN_FRONTEND=noninteractive sudo -E dpkg-reconfigure --priority=low unattended-upgrades"
  
  echo -e "\n${YELLOW}Status der automatischen Updates:${NC}"
  run_ssh_command_with_password "sudo systemctl status unattended-upgrades"
  
  echo -e "\n${YELLOW}Konfigurationsdatei für automatische Updates:${NC}"
  run_ssh_command_with_password "cat /etc/apt/apt.conf.d/20auto-upgrades"
  
  pause_for_screenshot
}

# Aufgabe 2: SSH-Härtung
setup_ssh_hardening() {
  print_section "Aufgabe 2: SSH-Härtung konfigurieren"
  
  echo "1. SSH-Key auf vmKL1 generieren..."
  if [ ! -f ~/.ssh/id_ed25519 ]; then
    ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""
  else
    echo "SSH-Key existiert bereits."
  fi
  
  echo "2. SSH-Key auf vmLM1 kopieren..."
  mkdir -p ~/.ssh/temp
  cat ~/.ssh/id_ed25519.pub > ~/.ssh/temp/authorized_keys
  sshpass -p "$PASSWORD" scp -P $SSH_PORT ~/.ssh/temp/authorized_keys $USERNAME@$SERVER_IP:~/.ssh/authorized_keys
  
  echo "3. Berechtigungen auf vmLM1 setzen..."
  run_ssh_command_with_password "chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
  
  echo "4. SSH-Konfiguration für Härtung erstellen..."
  cat > ssh_config_new << EOF
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

  echo "5. SSH-Konfiguration auf vmLM1 übertragen..."
  sshpass -p "$PASSWORD" scp -P $SSH_PORT ssh_config_new $USERNAME@$SERVER_IP:~/sshd_config
  
  echo "6. SSH-Konfiguration auf vmLM1 anwenden..."
  run_ssh_command_with_password "sudo mv ~/sshd_config /etc/ssh/sshd_config && sudo chmod 644 /etc/ssh/sshd_config && sudo systemctl restart ssh"
  
  # Den SSH-Status auf gehärteten Zustand setzen
  SSH_HARDENED=true
  
  echo -e "\n${YELLOW}SSH-Konfiguration:${NC}"
  run_command "grep -E '^Port|^PasswordAuthentication' /etc/ssh/sshd_config"
  
  echo -e "\n${YELLOW}SSH-Dienststatus:${NC}"
  run_command "sudo systemctl status ssh | head -15"
  
  echo -e "\n${GREEN}SSH-Härtung abgeschlossen. SSH läuft jetzt auf Port $NEW_SSH_PORT mit Key-Authentifizierung.${NC}"
  
  pause_for_screenshot
}

# Aufgabe 3: Firewall konfigurieren
setup_firewall() {
  print_section "Aufgabe 3: Firewall mit Default Deny konfigurieren"
  
  echo "Installation der UFW Firewall..."
  run_command "sudo apt install -y ufw"
  
  echo "Zurücksetzen aller vorhandenen Regeln..."
  run_command "sudo ufw --force reset"
  
  echo "Setzen der Default-Deny-Regel..."
  run_command "sudo ufw default deny incoming && sudo ufw default allow outgoing"
  
  echo "Öffnen von Port $NEW_SSH_PORT für SSH..."
  run_command "sudo ufw allow $NEW_SSH_PORT/tcp"
  
  echo "Aktivieren der Firewall..."
  run_command "sudo ufw --force enable"
  
  echo -e "\n${YELLOW}Firewall-Status und Regeln:${NC}"
  run_command "sudo ufw status verbose"
  
  pause_for_screenshot
}

# ====================================================================
# Auftrag 2: Checkliste für Sicherheitspolicy
# ====================================================================

generate_security_checklist() {
  print_section "Auftrag 2: Checkliste für Sicherheitspolicy"
  
  echo -e "${YELLOW}Automatische Updates${NC}"
  echo "sudo systemctl status unattended-upgrades"
  run_command "sudo systemctl status unattended-upgrades | grep -E 'Active:|enabled;'"
  echo ""
  
  echo -e "${YELLOW}Authentifikation mit SSH${NC}"
  echo "sudo systemctl status ssh"
  run_command "sudo systemctl status ssh | grep -E 'Active:|running'"
  echo "grep Port /etc/ssh/sshd_config"
  run_command "grep 'Port' /etc/ssh/sshd_config"
  echo ""
  
  echo -e "${YELLOW}Passwortauthentifikation sperren${NC}"
  echo "grep PasswordAuthentication /etc/ssh/sshd_config"
  run_command "grep 'PasswordAuthentication' /etc/ssh/sshd_config"
  echo ""
  
  echo -e "${YELLOW}Firewall mit Default-Deny-Regel${NC}"
  echo "sudo ufw status"
  run_command "sudo ufw status | grep -E 'Status:|Default:'"
  echo ""
  
  echo -e "${YELLOW}Nur Port $NEW_SSH_PORT ist offen${NC}"
  echo "sudo ufw status numbered"
  run_command "sudo ufw status numbered"
  echo ""
  
  pause_for_screenshot
}

# ====================================================================
# Auftrag 3: Individuelle Ergänzungen
# ====================================================================

setup_additional_hardening() {
  print_section "Auftrag 3: Individuelle Ergänzungen"
  
  echo "1. ICMP-Ping blockieren"
  echo "1.1. Erstellen der Konfiguration..."
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
  scp -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT before.rules $USERNAME@$SERVER_IP:~/before.rules
  
  # Anwenden der Regeln
  run_command "sudo mv ~/before.rules /etc/ufw/before.rules && sudo chmod 644 /etc/ufw/before.rules"
  
  echo "2. IPv6 deaktivieren auf der Firewall"
  run_command "sudo sed -i 's/IPV6=yes/IPV6=no/' /etc/default/ufw"
  
  echo "Neustart der Firewall..."
  run_command "sudo ufw reload"
  
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
  
  echo "Installation von nginx..."
  run_command "sudo apt install -y nginx"
  
  echo "Öffnen von Port 80 in der Firewall..."
  run_command "sudo ufw allow 80/tcp && sudo ufw reload"
  
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
  scp -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT index.html $USERNAME@$SERVER_IP:~/index.html
  
  # Installieren der Webseite
  run_command "sudo mv ~/index.html /var/www/html/index.html && sudo chown www-data:www-data /var/www/html/index.html"
  
  echo "Neustart des Webservers..."
  run_command "sudo systemctl restart nginx"
  
  echo -e "\n${YELLOW}Webserver-Status:${NC}"
  run_command "sudo systemctl status nginx | grep -E 'Active:|running'"
  
  echo -e "\n${YELLOW}Webseite kann jetzt im Browser unter http://$SERVER_IP aufgerufen werden${NC}"
  echo -e "Bitte rufe die Seite auf und mache einen Screenshot"
  
  pause_for_screenshot
}

# ====================================================================
# Auftrag DNS: DNS-Konfiguration
# ====================================================================

setup_dns_server() {
  print_section "Auftrag DNS: DNS-Server konfigurieren"
  
  echo "Installation von bind9..."
  run_command "sudo apt install -y bind9 bind9utils bind9-doc"
  
  echo "Öffnen der Ports für DNS in der Firewall..."
  run_command "sudo ufw allow 53/tcp && sudo ufw allow 53/udp && sudo ufw reload"
  
  # Erstellen und Übertragen der Konfigurationsdateien
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
  scp -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT named.conf.options $USERNAME@$SERVER_IP:~/named.conf.options
  run_command "sudo mv ~/named.conf.options /etc/bind/named.conf.options"
  
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
  scp -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT named.conf.local $USERNAME@$SERVER_IP:~/named.conf.local
  run_command "sudo mv ~/named.conf.local /etc/bind/named.conf.local"
  
  echo "Erstellen des Zonendatei-Verzeichnisses..."
  run_command "sudo mkdir -p /etc/bind/zones"
  
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
  scp -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT db.smartlearn.lan $USERNAME@$SERVER_IP:~/db.smartlearn.lan
  run_command "sudo mv ~/db.smartlearn.lan /etc/bind/zones/db.smartlearn.lan"
  
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
  scp -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT db.smartlearn.dmz $USERNAME@$SERVER_IP:~/db.smartlearn.dmz
  run_command "sudo mv ~/db.smartlearn.dmz /etc/bind/zones/db.smartlearn.dmz"
  
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
  scp -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT db.110.168.192 $USERNAME@$SERVER_IP:~/db.110.168.192
  run_command "sudo mv ~/db.110.168.192 /etc/bind/zones/db.110.168.192"
  
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
  scp -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT db.120.168.192 $USERNAME@$SERVER_IP:~/db.120.168.192
  run_command "sudo mv ~/db.120.168.192 /etc/bind/zones/db.120.168.192"
  
  echo "Setzen der Berechtigungen für die Zonendateien..."
  run_command "sudo chown -R bind:bind /etc/bind/zones && sudo chmod -R 755 /etc/bind/zones"
  
  echo "Überprüfen der Konfiguration..."
  run_command "sudo named-checkconf"
  run_command "sudo named-checkzone smartlearn.lan /etc/bind/zones/db.smartlearn.lan"
  run_command "sudo named-checkzone smartlearn.dmz /etc/bind/zones/db.smartlearn.dmz"
  run_command "sudo named-checkzone 110.168.192.in-addr.arpa /etc/bind/zones/db.110.168.192"
  run_command "sudo named-checkzone 120.168.192.in-addr.arpa /etc/bind/zones/db.120.168.192"
  
  echo "Neustart des bind9-Dienstes..."
  run_command "sudo systemctl restart bind9"
  
  echo -e "\n${YELLOW}DNS-Server-Status:${NC}"
  run_command "sudo systemctl status bind9 | grep -E 'Active:|running'"
  
  echo -e "\n${YELLOW}DNS-Abfragen testen:${NC}"
  run_command "nslookup vmkl1.smartlearn.lan 127.0.0.1"
  run_command "nslookup vmlm1.smartlearn.dmz 127.0.0.1"
  run_command "nslookup 192.168.110.70 127.0.0.1"
  
  pause_for_screenshot
}

# ====================================================================
# Auftrag Netcat: Banner Grabbing
# ====================================================================

test_banner_grabbing() {
  print_section "Auftrag Netcat: Banner Grabbing"
  
  echo "Installation von netcat..."
  run_command "sudo apt install -y netcat"
  
  echo -e "\n${YELLOW}HTTP Banner Grabbing:${NC}"
  echo "Befehl: nc $SERVER_IP 80"
  echo -e "HEAD / HTTP/1.1\r\nHost: $SERVER_IP\r\n\r\n" | nc $SERVER_IP 80
  
  echo -e "\n${YELLOW}DNS Banner Grabbing:${NC}"
  echo "Befehl: echo -ne \"\\x00\\x1c...\" | nc -u $SERVER_IP 53"
  echo -ne "\x00\x1c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03" | nc -u $SERVER_IP 53 | xxd -g 1
  
  pause_for_screenshot
  
  echo "Banner Grabbing unterbinden..."
  
  echo "1. Webserver-Banner verstecken..."
  cat > security.conf << EOF
# Server information hiding
server_tokens off;
EOF
  scp -i ~/.ssh/id_ed25519 -P $NEW_SSH_PORT security.conf $USERNAME@$SERVER_IP:~/security.conf
  run_command "sudo mkdir -p /etc/nginx/conf.d && sudo mv ~/security.conf /etc/nginx/conf.d/security.conf && sudo systemctl reload nginx"
  
  echo "2. DNS-Banner verstecken (bereits in der named.conf.options konfiguriert)..."
  
  echo -e "\n${YELLOW}HTTP Banner nach Härtung:${NC}"
  echo "Befehl: nc $SERVER_IP 80"
  echo -e "HEAD / HTTP/1.1\r\nHost: $SERVER_IP\r\n\r\n" | nc $SERVER_IP 80
  
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
    echo "0. Beenden"
    
    read -p "Wähle eine Option (0-9): " option
    
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
        setup_ssh_hardening
        setup_firewall
        generate_security_checklist
        setup_additional_hardening
        setup_webserver
        setup_dns_server
        test_banner_grabbing
        ;;
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
