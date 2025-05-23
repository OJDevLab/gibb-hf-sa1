# Server Hardening & DNS Configuration Guide

This comprehensive guide walks you through implementing security hardening for your server and setting up a DNS infrastructure without relying on automation scripts.

## Server Security Implementation

### Step 1: Enable Automatic Security Updates

Implementing automatic updates helps protect your server against known vulnerabilities:

```bash
sudo apt update && sudo apt upgrade
sudo apt install unattended-upgrades
sudo systemctl enable unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

Verify configuration and logs:

```bash
sudo systemctl status unattended-upgrades
sudo unattended-upgrade --dry-run --verbose
cat /etc/apt/apt.conf.d/20auto-upgrades
```
## SSH Security and Firewall Configuration

### Step 1: Generate SSH Key Pair (auf vmKL1)

Generate an Ed25519 keypair on vmKL1:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -C "vmadmin@vmKL1"
```

### Step 2: Deploy SSH Key to vmLM1

Copy the public key to vmLM1 using ssh-copy-id:
```bash
ssh-copy-id -i ~/.ssh/id_ed25519 vmadmin@192.168.120.60
```

Test the key-based authentication:
```bash
ssh -i ~/.ssh/id_ed25519 vmadmin@192.168.120.60
```

### Step 3: Harden SSH Configuration (auf vmLM1)

Connect to vmLM1 and backup the SSH configuration:
```bash
ssh vmadmin@192.168.120.60
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
```

Edit the SSH configuration:
```bash
sudo nano /etc/ssh/sshd_config
```

Modify these key settings:
```
# Change port
Port 23344

# Disable password authentication
PasswordAuthentication no
ChallengeResponseAuthentication no

# Ensure public key authentication is enabled
PubkeyAuthentication yes

# Disable root login
PermitRootLogin no

# Optional security improvements
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
```

Test the configuration for syntax errors:
```bash
sudo sshd -t
```

**IMPORTANT**: Before restarting SSH, open a NEW terminal and test the connection:
```bash
ssh -p 23344 vmadmin@192.168.120.60
```

If the test connection works, restart SSH in the original terminal:
```bash
sudo systemctl restart ssh
sudo systemctl status ssh
```
Sometime you need to restart the server with `sudo reboot`

### Step 4: Configure Firewall (auf vmLM1)

Install and configure UFW:
```bash
sudo apt update
sudo apt install -y ufw
```

Reset and configure firewall rules:
```bash
# Reset firewall
sudo ufw --force reset

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH on custom port
sudo ufw allow 23344/tcp comment 'SSH custom port'

# Allow DNS (required for DNS server)
sudo ufw allow 53/tcp comment 'DNS TCP'
sudo ufw allow 53/udp comment 'DNS UDP'

# Enable logging
sudo ufw logging on

# Enable the firewall
sudo ufw --force enable
```

Check firewall status:
```bash
sudo ufw status verbose
```

### Step 5: Additional Hardening

#### Disable ICMP Ping
```bash
sudo nano /etc/ufw/before.rules
```

Find the ICMP section and change this line:
```
# ok icmp codes for INPUT
-A ufw-before-input -p icmp --icmp-type echo-request -j DROP
```

#### Disable IPv6 in Firewall
```bash
sudo nano /etc/default/ufw
```

Change:
```
IPV6=no
```

Apply changes:
```bash
sudo ufw reload
```

### Step 6: Verification

From vmKL1, test the configuration:

```bash
# Test SSH on new port (should work)
ssh -p 23344 vmadmin@192.168.120.60

# Test password authentication (should fail)
ssh -p 23344 -o PubkeyAuthentication=no vmadmin@192.168.120.60

# Test default SSH port (should fail)
ssh vmadmin@192.168.120.60

# Test ping (should not respond)
ping -c 3 192.168.120.60

# Scan open ports
nmap 192.168.120.60
```

### Checklist

- [ ] **SSH-Schlüssel**: Key generiert und mit ssh-copy-id deployed
- [ ] **SSH Port 23344**: `sudo ss -tlnp | grep 23344`
- [ ] **Passwort-Auth deaktiviert**: `sudo sshd -T | grep passwordauthentication`
- [ ] **Firewall aktiv**: `sudo ufw status`
- [ ] **Nur Port 23344 und 53 offen**: `sudo ufw status numbered`
- [ ] **ICMP deaktiviert**: Ping timeout bei `ping 192.168.120.60`
- [ ] **IPv6 deaktiviert**: `grep IPV6 /etc/default/ufw` zeigt `IPV6=no`

### Troubleshooting

Falls SSH-Zugriff verloren:
1. Konsolen-Zugriff auf VM verwenden
2. SSH-Status prüfen: `sudo systemctl status ssh`
3. Firewall temporär deaktivieren: `sudo ufw disable`
4. SSH-Konfiguration zurücksetzen: `sudo cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config`


## DNS Server Implementation

### Step 1: Install DNS Server Software

```bash
sudo apt update
sudo apt install -y bind9 bind9utils bind9-doc
sudo ufw allow 53/tcp
sudo ufw allow 53/udp
sudo ufw reload
```

### Step 2: Configure DNS Global Options

Create a backup of your original configuration files:
```bash
sudo cp /etc/bind/named.conf.local /etc/bind/named.conf.local.original
sudo cp /etc/bind/named.conf.options /etc/bind/named.conf.options.original
```

Configure BIND options:
```bash
sudo nano /etc/bind/named.conf.options
```

Add the following configuration:

```
options {
    directory "/var/cache/bind";
    listen-on { any; };
    listen-on-v6 { none; };
    allow-query { any; };
    forwarders { 1.1.1.1; 8.8.8.8; };
    recursion yes;
    auth-nxdomain no;
    version none;
    dnssec-validation no;
};
```

### Step 3: Set Up DNS Zones

#### Configure Local Zones

```bash
sudo nano /etc/bind/named.conf.local
```

Add the following zone definitions:

```
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
```

### Step 4: Create Zone Database Files

Create `/etc/bind/zones` directory and set permissions:

```bash
sudo mkdir -p /etc/bind/zones
sudo chown -R bind:bind /etc/bind/zones
sudo chmod -R 755 /etc/bind/zones
```

#### Internal Forward Zone (`smartlearn.lan`)

```bash
sudo nano /etc/bind/zones/db.smartlearn.lan
```

```
$TTL 86400
@ IN SOA dns.smartlearn.dmz. admin.smartlearn.dmz. (
    3 ; Serial
    604800 ; Refresh
    86400 ; Retry
    2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@ IN NS dns.smartlearn.dmz.
; Hostnamen
vmkl1 IN A 192.168.110.70
vmlf1 IN A 192.168.110.1
; Maschinennamen
li232-vmKL1 IN A 192.168.110.70
if227-vmLF1 IN A 192.168.110.1
```

#### DMZ Forward Zone (`smartlearn.dmz`)

```bash
sudo nano /etc/bind/zones/db.smartlearn.dmz
```

```
$TTL 86400
@ IN SOA dns.smartlearn.dmz. admin.smartlearn.dmz. (
    3 ; Serial
    604800 ; Refresh
    86400 ; Retry
    2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@ IN NS dns.smartlearn.dmz.
; Hostnamen
vmlm1   IN A 192.168.120.60
www     IN A 192.168.120.60
dns     IN A 192.168.120.60
vmlf1   IN A 192.168.120.1
; Maschinennamen
li223-vmLM1 IN A 192.168.120.60
if227-vmLF1 IN A 192.168.120.1
```

#### Reverse Zone for `192.168.110.0/24`

```bash
sudo nano /etc/bind/zones/db.110.168.192
```

```
$TTL 86400
@ IN SOA dns.smartlearn.dmz. admin.smartlearn.dmz. (
    3 ; Serial
    604800 ; Refresh
    86400 ; Retry
    2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@ IN NS dns.smartlearn.dmz.
; PTR Records für Hostnamen und Maschinennamen
70 IN PTR vmkl1.smartlearn.lan.
70 IN PTR li232-vmKL1.smartlearn.lan.
1  IN PTR vmlf1.smartlearn.lan.
1  IN PTR if227-vmLF1.smartlearn.lan.
```

#### Reverse Zone for `192.168.120.0/24`

```bash
sudo nano /etc/bind/zones/db.120.168.192
```

```
$TTL 86400
@ IN SOA dns.smartlearn.dmz. admin.smartlearn.dmz. (
    3 ; Serial
    604800 ; Refresh
    86400 ; Retry
    2419200 ; Expire
    604800 ) ; Negative Cache TTL
;
@ IN NS dns.smartlearn.dmz.
; PTR Records für Hostnamen und Maschinennamen
60 IN PTR vmlm1.smartlearn.dmz.
60 IN PTR www.smartlearn.dmz.
60 IN PTR dns.smartlearn.dmz.
60 IN PTR li223-vmLM1.smartlearn.dmz.
1  IN PTR vmlf1.smartlearn.dmz.
1  IN PTR if227-vmLF1.smartlearn.dmz.
```

### Step 5: Verify Configuration and Restart Service

```bash
# Set correct permissions
sudo chown -R bind:bind /etc/bind/zones
sudo chmod -R 755 /etc/bind/zones

# Check configuration syntax
sudo named-checkconf

# Check each zone file
sudo named-checkzone smartlearn.lan /etc/bind/zones/db.smartlearn.lan
sudo named-checkzone smartlearn.dmz /etc/bind/zones/db.smartlearn.dmz
sudo named-checkzone 110.168.192.in-addr.arpa /etc/bind/zones/db.110.168.192
sudo named-checkzone 120.168.192.in-addr.arpa /etc/bind/zones/db.120.168.192

# Restart BIND9 service
sudo systemctl restart bind9
sudo systemctl status bind9
```

### Step 6: Test DNS Resolution

Test forward lookups for **Hostnamen**:
```bash
# smartlearn.lan Hostnamen
nslookup vmkl1.smartlearn.lan 192.168.120.60
nslookup vmlf1.smartlearn.lan 192.168.120.60

# smartlearn.dmz Hostnamen
nslookup vmlm1.smartlearn.dmz 192.168.120.60
nslookup www.smartlearn.dmz 192.168.120.60
nslookup dns.smartlearn.dmz 192.168.120.60
nslookup vmlf1.smartlearn.dmz 192.168.120.60
```

Test forward lookups for **Maschinennamen**:
```bash
# smartlearn.lan Maschinennamen
nslookup li232-vmkl1.smartlearn.lan 192.168.120.60
nslookup if227-vmlf1.smartlearn.lan 192.168.120.60

# smartlearn.dmz Maschinennamen
nslookup li223-vmlm1.smartlearn.dmz 192.168.120.60
nslookup if227-vmlf1.smartlearn.dmz 192.168.120.60
```

Test reverse lookups:
```bash
# 192.168.110.0/24 subnet
nslookup 192.168.110.70 192.168.120.60  # Sollte vmkl1.smartlearn.lan und li232-vmKL1.smartlearn.lan zurückgeben
nslookup 192.168.110.1 192.168.120.60   # Sollte vmlf1.smartlearn.lan und if227-vmLF1.smartlearn.lan zurückgeben

# 192.168.120.0/24 subnet
nslookup 192.168.120.60 192.168.120.60  # Sollte vmlm1, www, dns und li223-vmLM1.smartlearn.dmz zurückgeben
nslookup 192.168.120.1 192.168.120.60   # Sollte vmlf1.smartlearn.dmz und if227-vmLF1.smartlearn.dmz zurückgeben
```

## Service Fingerprinting

These commands allow you to identify services running on your network servers.

### HTTP Server Information

```bash
nc 192.168.110.60 80
HEAD / HTTP/1.1
```

## Banner Grabbing
```sudo nano /etc/apache2/conf-available/security.conf```

Change Apache Config
```
ServerTokens Prod
ServerSignature Off
sudo systemctl reload apache2
```

For Bind
```sudo nano /etc/bind/named.conf.options```

Change config:
```
version none;
```
Then
```sudo systemctl restart bind9```



Check with
```
curl -I http://<SERVER> | grep -i '^Server:'
dig @localhost version.bind TXT CHAOS   # sollte leer / NXDOMAIN sein
```

### DNS Server Information

```bash
echo -ne "\x00\x1c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x76\x65\x72\x73\x69\x6f\x6e\x04\x62\x69\x6e\x64\x00\x00\x10\x00\x03" | nc -u <DNS_SERVER_IP> 53 | xxd -g 1
```

## Verification Checklist

#### 1. SSH Connectivity (Port & Key-only):
```bash
ssh -i ~/.ssh/id_ed25519 -p 23344 vmadmin@192.168.120.60 echo "SSH OK"
```

#### 2. Root Login Disabled:
```bash
ssh -p 23344 root@192.168.120.60 || echo "Root login blocked"
```

#### 3. Password Authentication Disabled:
```bash
ssh -p 23344 vmadmin@192.168.120.60 || echo "Password auth disabled"
```


#### 4. Firewall Rules:
```bash
sudo ufw status | grep -E "23344/tcp.*ALLOW"
sudo ufw status | grep -E "53/udp.*ALLOW"
```

#### 5. Web Service Reachability:
```bash
curl -Is http://192.168.120.60 | head -n1
```

#### 6. DNS A Record Lookup:
```bash
dig +short vmlm1.smartlearn.dmz @192.168.120.60
```

#### 7. DNS Reverse Lookup:
```bash
dig +short -x 192.168.120.60 @192.168.120.60
```

#### 8. Idle Session Timeout:
```bash
ssh -p 23344 vmadmin@192.168.120.60 sleep 310; echo "Should be disconnected"
```

#### 9. Fail2Ban Status:
```bash
sudo fail2ban-client status sshd
```
