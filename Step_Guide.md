# Server Hardening & DNS Configuration Guide

This comprehensive guide walks you through implementing security hardening for your server and setting up a DNS infrastructure without relying on automation scripts.

## Server Security Implementation

### Step 1: Enable Automatic Security Updates

Implementing automatic updates helps protect your server against known vulnerabilities:

```bash
sudo apt update && sudo apt install unattended-upgrades
sudo systemctl enable unattended-upgrades
sudo systemctl restart unattended-upgrades
```
#### Periodenwerte täglich setzen/prüfen
```bash
sudo nano /etc/apt/apt.conf.d/20auto-upgrades
```

Add to config file
```bash
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade   "1";
```
Confirm that automatic updates are properly configured:

```bash
sudo systemctl status unattended-upgrades
sudo unattended-upgrade --dry-run --verbose
sudo tail -n 20 /var/log/unattended-upgrades/unattended-upgrades.log
sudo tail -n 20 /var/log/apt/history.log
```

### Step 2: Enhance SSH Security
Create SSH Keypair
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

Second, create a backup of your existing configuration:

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
```

Now create a more secure SSH configuration:

```bash
sudo nano /etc/ssh/sshd_config
```

Replace the content with this security-hardened configuration:

```
# SSH Configuration with Hardened Security Settings
# --------------------------------------
# General Connection Settings
Protocol 2                    # Use SSH protocol version 2 only
Port 22443                    # Non-standard port for security

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
PermitRootLogin no
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
Banner /etc/issue.net         # Custom banner message

# Additional Settings
AcceptEnv LANG LC_*           # Accept language settings
Subsystem sftp /usr/lib/openssh/sftp-server
```

Apply the new configuration:

```bash
sudo systemctl restart ssh
```

Verify the SSH service is running on the new port:

```bash
sudo systemctl status ssh
```

> **Note**: In some cases, you may need to reboot the server for the changes to take effect.

### Step 3: Configure Firewall Protection

Set up a basic firewall with UFW:

```bash
sudo apt-get install -y ufw
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22443/tcp
sudo ufw logging on
sudo ufw enable
```
#### Regeln prüfen
```bash
sudo ufw status verbose
```

## DNS Server Implementation

### Step 1: Install DNS Server Software

```bash
sudo apt-get update
sudo apt-get install -y bind9 bind9utils bind9-doc
sudo ufw allow 53/tcp
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

    // Network Security: Restrict Query Access
    allow-query {
        localhost;
        192.168.110.0/24;
        192.168.120.0/24;
    };

    // External DNS Resolution
    forwarders {
        1.1.1.1;
        8.8.8.8;
        8.8.4.4;
    };

    listen-on-v6 { any; };

    // Security Enhancements
    auth-nxdomain no;
    version none;
    dnssec-validation no;
};
```

### Step 3: Set Up DNS Zones

Configure local zones:

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

Create a directory for zone files:

```bash
sudo mkdir -p /etc/bind/zones
```

#### Internal Network Zone (smartlearn.lan)

```bash
sudo nano /etc/bind/zones/db.smartlearn.lan
```

Add the following zone data:

```
$TTL    86400
@       IN      SOA     dns.smartlearn.dmz. admin.smartlearn.dmz. (
                           2         ; Serial
                        3600         ; Refresh
                        1800         ; Retry
                       604800         ; Expire
                        86400 )      ; Negative Cache TTL

; Name Server Definition
@       IN      NS      dns.smartlearn.dmz.

; Host Records
dns      IN      A       192.168.120.60
vmkl1   IN      A       192.168.110.70
vmlf1   IN      A       192.168.110.1
```

#### DMZ Network Zone (smartlearn.dmz)

```bash
sudo nano /etc/bind/zones/db.smartlearn.dmz
```

Add the following zone data:

```
$TTL    86400
@       IN      SOA     dns.smartlearn.dmz. admin.smartlearn.dmz. (
                           2         ; Serial
                        3600         ; Refresh
                        1800         ; Retry
                       604800         ; Expire
                        86400 )      ; Negative Cache TTL

; Name Server Definition
@       IN      NS      dns.smartlearn.dmz.

; Host Records
vmlm1   IN      A       192.168.120.60
www     IN      A       192.168.120.60
dns     IN      A       192.168.110.60
vmlf1   IN      A       192.168.120.1
```

#### Reverse Zone for 192.168.110.0/24

```bash
sudo nano /etc/bind/zones/db.110.168.192
```

Add the following reverse lookup data:

```
$TTL    86400
@       IN      SOA     dns.smartlearn.dmz. admin.smartlearn.dmz. (
                           2         ; Serial
                        3600         ; Refresh
                        1800         ; Retry
                       604800         ; Expire
                        86400 )      ; Negative Cache TTL

; Name Server Definition
@       IN      NS      dns.smartlearn.dmz.

; Reverse Lookup Records
60      IN      PTR     dns.smartlearn.dmz.
70      IN      PTR     vmkl1.smartlearn.lan.
1       IN      PTR     vmlf1.smartlearn.lan.
```

#### Reverse Zone for 192.168.120.0/24

```bash
sudo nano /etc/bind/zones/db.120.168.192
```

Add the following reverse lookup data:

```
$TTL    86400
@       IN      SOA     dns.smartlearn.dmz. admin.smartlearn.dmz. (
                           2         ; Serial
                        3600         ; Refresh
                        1800         ; Retry
                       604800         ; Expire
                        86400 )      ; Negative Cache TTL

; Name Server Definition
@       IN      NS      dns.smartlearn.dmz.

; Reverse Lookup Records
60      IN      PTR     vmlm1.smartlearn.dmz.
60      IN      PTR     www.smartlearn.dmz.
60      IN      PTR     dns.smartlearn.dmz.
1       IN      PTR     vmlf1.smartlearn.dmz.
```

### Step 5: Finalize DNS Configuration

Set appropriate permissions and start the service:

```bash
sudo chown -R bind:bind /etc/bind/zones
sudo chmod -R 755 /etc/bind/zones
sudo named-checkconf /etc/bind/named.conf
sudo systemctl restart bind9
sudo systemctl enable named
sudo ufw allow 53/udp
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
