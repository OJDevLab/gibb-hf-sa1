# gibb-hf-sa1
Setup Guide für GIBB SA1 LB1

## Server hardening

**Ziel**  
Proaktiver Schutz des Ubuntu/Debian-Servers durch Härtungsmassnahmen.

### Voraussetzungen
- SSH-Zugang mit sudo-Rechten  
- Internetverbindung für Paket-Updates  
- Testumgebung mit li232-vmKL1, li223-vmLM1 und if227-vmLF1

### Ausführung

#### Generate Ed25519 keypair on vmKL1
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519
```

#### Create and secure the target user’s SSH directory
```bash
sudo mkdir -p /home/vmadmin/.ssh
sudo chmod 700 /home/vmadmin/.ssh
sudo chown vmadmin:vmadmin /home/vmadmin/.ssh
```

#### Copy the public key on vmLM1 and set strict permissions:
```bash
scp ~/.ssh/id_ed25519.pub vmadmin@192.168.120.60:/home/vmadmin/.ssh/authorized_keys
```

```bash
wget https://raw.githubusercontent.com/OJDevLab/gibb-hf-sa1/refs/heads/main/ssh_setup.sh
```

```bash
chmod +x ssh_setup.sh 
```










#### 1. Skript herunterladen
```bash
wget https://raw.githubusercontent.com/OJDevLab/gibb-hf-sa1/refs/heads/main/setup.sh -O remote_hardening.sh
```

```bash
wget https://raw.githubusercontent.com/OJDevLab/gibb-hf-sa1/refs/heads/main/ssh_setup.sh -O remote_hardening.sh
```

#### 2. Ausführungsrechte setzen
```bash
chmod +x remote_hardening.sh
```
#### 3. Abhängigkeiten installieren
```bash
sudo apt update && sudo apt install -y sshpass
```
#### 4. Härtungsskript starten
```bash
./remote_hardening.sh
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
