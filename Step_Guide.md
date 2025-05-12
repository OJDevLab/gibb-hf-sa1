# Server Hardening & DNS Configuration Guide

This comprehensive guide walks you through implementing security hardening for your server and setting up a DNS infrastructure without relying on automation scripts.

## Server Security Implementation

### Step 1: Enable Automatic Security Updates

Implementing automatic updates helps protect your server against known vulnerabilities:

```bash
sudo apt update && sudo apt install unattended-upgrades
sudo systemctl enable unattended-upgrades
```
#### Edit /etc/apt/apt.conf.d/20auto-upgrades to enforce daily checks:
```bash
sudo nano /etc/apt/apt.conf.d/20auto-upgrades
```

Add to config file
```bash
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade   "1";
```
Verify configuration and logs:

```bash
sudo systemctl status unattended-upgrades
sudo unattended-upgrade --dry-run --verbose
sudo tail -n 20 /var/log/unattended-upgrades/unattended-upgrades.log
sudo tail -n 20 /var/log/apt/history.log
```

### Step 2: Enhance SSH Security
#### Key Generation & Deployment
Generate an Ed25519 keypair if not already present:
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

Create and secure the target user’s SSH directory:
```bash
sudo mkdir -p /home/vmadmin/.ssh
sudo chmod 700 /home/vmadmin/.ssh
sudo chown vmadmin:vmadmin /home/vmadmin/.ssh
```
Copy the public key and set strict permissions:
```bash
scp ~/.ssh/id_ed25519.pub vmadmin@192.168.120.60:/home/vmadmin/.ssh/authorized_keys
sudo chmod 600 /home/vmadmin/.ssh/authorized_keys
sudo chown vmadmin:vmadmin /home/vmadmin/.ssh/authorized_keys
```
#### SSH Daemon Configuration
Now create a more secure SSH configuration.

Back up the existing config:
```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
```
Edit /etc/ssh/sshd_config to include:

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

Restart the service and confirm:

```bash
sudo systemctl restart sshd
sudo systemctl status sshd
```

> **Note**: In some cases, you may need to reboot the server for the changes to take effect.

### Step 3: Configure Firewall Protection

Use UFW to restrict incoming connections:
```bash
sudo apt install -y ufw
sudo ufw --force reset
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 23344/tcp
sudo ufw allow 23344/udp
sudo ufw allow 80/tcp        # for web service
sudo ufw allow 53/tcp
sudo ufw allow 53/udp
sudo ufw logging on
sudo ufw enable
```

Check active rules:
```bash
sudo ufw status verbose
```

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
    listen-on-v6 { any; };
    allow-query { any; };
    forwarders { 1.1.1.1; 8.8.8.8; };
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

Create /etc/bind/zones and set permissions:
```bash
sudo mkdir -p /etc/bind/zones
sudo chown -R bind:bind /etc/bind/zones
sudo chmod -R 755 /etc/bind/zones
```

#### Internal Forward Zone (smartlearn.lan)

```bash
sudo nano /etc/bind/zones/db.smartlearn.lan
```

Add the following zone data:

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
dns IN A 192.168.120.60
vmkl1 IN A 192.168.110.70
vmlf1 IN A 192.168.110.1
```

#### DMZ Forward Zone (smartlearn.dmz)

```bash
sudo nano /etc/bind/zones/db.smartlearn.dmz
```

Add the following zone data:

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
vmlm1 IN A 192.168.120.60
www IN A 192.168.120.60
```

#### Reverse Zone for 192.168.110.0/24

```bash
sudo nano /etc/bind/zones/db.110.168.192
```

Add the following reverse lookup data:

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
60 IN PTR dns.smartlearn.dmz.
70 IN PTR vmkl1.smartlearn.lan.
1 IN PTR vmlf1.smartlearn.lan.
```

#### Reverse Zone for 192.168.120.0/24

```bash
sudo nano /etc/bind/zones/db.120.168.192
```

Add the following reverse lookup data:

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
60 IN PTR vmlm1.smartlearn.dmz.
60 IN PTR www.smartlearn.dmz.
```

#### Reload named and confirm syntax:
```bash
sudo chown -R bind:bind /etc/bind/zones
sudo chmod -R 755 /etc/bind/zones
sudo named-checkconf /etc/bind/named.conf
sudo systemctl restart bind9
sudo systemctl enable named
sudo systemctl enable --now bind9
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
