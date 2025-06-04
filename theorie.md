# Server Hardening & DNS – Theoretischer Background

> *„Wer nur Befehle kopiert, versteht nicht, wie Sicherheit entsteht.“*  
Dieses Dokument erklärt **warum** bestimmte Hardening‑Massnahmen nötig sind und **welche Prinzipien** dahinterstehen.

---

## 1  Sicherheitsprinzipien (Foundation Layer)

| Prinzip | Kurzbeschreibung | Relevanz für Server‑Hardening |
|---------|------------------|------------------------------|
| **CIA‑Triad** | *Confidentiality, Integrity, Availability* | Jede Massnahme sollte mindestens einen Aspekt stärken, ohne die anderen drastisch zu schwächen. |
| **Defense in Depth** | Mehrere, sich überlappende Schutzschichten | Versagt z. B. SSH‑Key‑Auth, verhindert Firewall + Fail2Ban sofortigen Schaden. |
| **Least Privilege** | Jede Komponente erhält nur Mindest‑Rechte | Dienste laufen als unpriv. User; Root‑Login via SSH deaktiviert. |
| **Attack Surface Reduction** | Entfernen unnötiger Komponenten | Weniger Laufzeitprozesse, weniger CVE‑Einfallstore. |
| **Fail Secure** | Fehlerzustand = sicherer Zustand | Firewall default *deny*, Service crash → kein Daten‑Leak. |

---

## 2  Betriebssystem‑Hardening (OS Layer)

### 2.1  Patch Management Theory
* **Vulnerability Window** – Zeitspanne zwischen CVE‑Publikation und angewendetem Patch.  
* Automatisierte Security‑Updates verkürzen dieses Fenster drastisch.  
* Risiko: inkompatible Updates → deshalb **only‑security pockets** + Logging zur schnellen Rollback‑Analyse.

> 💡 **Unattended‑Upgrades** identifiziert Pakete im *jammy‑security* Repo und installiert sie non‑interactive. Damit bleibt **Integrity** erhalten, ohne ständig manuell einzugreifen.

### 2.2  Kernel & Sysctl
* Kernel Parameter (z. B. `net.ipv4.conf.all.rp_filter`) beeinflussen *Low‑Level* Network Security.  
* Linux‑Security‑Module (AppArmor/SELinux) erzwingen Mandatory Access Control und isolieren Kompromisse.

### 2.3  Service Minimisation
* Jeder Dämon ist ein „Foothold‑Kandidat“. Entferne: *print‑daemon*, *avahi*, *rpcbind*…  
* Tools: `systemctl list-unit-files`, `apt list --installed`.

---

## 3  Secure Remote Access (SSH Layer)

### 3.1  Kryptografische Basics
* **Asymmetric Crypto**: Public Key (auf Server) ↔ Private Key (auf Client).  
* **Ed25519** nutzt elliptische Kurven → kürzere Schlüssel, schnelleres Auth und widerstandsfähig gegen viele Seitenkanal‑Angriffe.

### 3.2  Authentisierung vs Autorisierung
* *Authentication* bestätigt **wer** du bist (Key‑Pair).  
* *Authorization* entscheidet **was** du darfst (Unix‑/sudo‑Rechte, SELinux Context).

### 3.3  Hardening‑Parameter Explained
| Directive | Theorie | Risiko ohne Massnahme |
|-----------|---------|----------------------|
| `PermitRootLogin no` | Root besitzt UID 0 → kompromittiert = Full‑Takeover | Credential‑Stuffing oder gestohlene Keys geben sofort vollen Zugriff |
| `PasswordAuthentication no` | Eliminierung von Brute‑Force auf schwache Passwörter | Dictionaries & Credential Dumps wirken sonst rund um die Uhr |
| `MaxAuthTries 3` | Rate‑Limiting auf Protokoll‑Ebene | Unlimitiertes Raten ↑ Erfolgschance beim Guessing |
| `ClientAliveInterval/CountMax` | Idle Session Timeout | Hijacked Terminal behält sonst dauerhaften Zugang |

Port Obfuscation (`Port 23344`) **senkt** Rauschen (Scanner), **ersetzt aber keine** echte Sicherheitsschicht.

---

## 4  Netzwerk‑Perimeter (Firewall Layer)

### 4.1  Stateful Packet Filtering
* **Connection Tracking** merkt sich *5‑Tuple* und erlaubt Rückverkehr.  
* Default‑Deny inbound + Default‑Allow outbound → Minimale Angriffsfläche bei überschaubarem Admin‑Aufwand.

### 4.2  ICMP & Visibility
* ICMP echo‑reply nicht beantworten = „Security by Obscurity Lite“.  
* Vorsicht: Tools wie `traceroute` oder PMTU Discovery benötigen einzelne ICMP‑Typen.

### 4.3  IPv6 Considerations
* Viele Admins deaktivieren IPv6, vergessen aber Public Cloud/ISP Dual‑Stack –> Blind Spot!  
* Besser: Regelwerke **inkl. IPv6** definieren oder Interface wirklich abschalten.

---

## 5  DNS‑Konzept (Application Layer)

DNS ist das **Telefonbuch des Internets** – wenn Namen nicht aufgelöst werden können, ist jede weitere Kommunikation zwecklos. Dieses Kapitel vertieft die Theorie hinter Records, Zonen und Sicherheits‑Mechanismen.

### 5.1  Hierarchisches Namespace
* *Root* (.) → *Top‑Level Domain* (z. B. .com, .lan) → *Second Level* (smartlearn) → *Subdomain* (www).  
* Jede Ebene delegiert Autorität mittels **NS‑Records** + optionaler **Glue‑A/AAAA‑Records**.

### 5.2  Wichtige DNS‑Begriffe
| Term | Erklärung |
|------|-----------|
| **FQDN** | *Fully Qualified Domain Name* – endet mit einem Punkt, z. B. `vmkl1.smartlearn.lan.` |
| **Zone** | Verwaltungseinheit, Teilbaum des Namensraums, für den ein Nameserver autoritativ ist |
| **RR‑Set** | Alle Resource‑Records gleichen Namens, Typs & Klasse; Signatur‑Grundlage bei DNSSEC |
| **Bailiwick** | Zuständigkeitsbereich eines Resolvers; relevant für Cache Poisoning Abwehr |

### 5.3  Record‑Typen im Alltag
| Type | Zweck | Häufige Stolperfallen |
|------|-------|----------------------|
| `A` / `AAAA` | Name → IPv4 / IPv6 | Vergiss nicht *PTR* Gegenstück! |
| `CNAME` | Alias → Kanonischer Name | Darf **nicht** neben anderen Records für gleichen Namen existieren |
| `MX` | Mail Exchange | Priorität kleiner Wert = höhere Präferenz |
| `TXT` | Freitext (SPF, DKIM, ACME) | SPF‑Strings dürfen 255‑Byte‑Chunks nicht überschreiten |
| `SRV` | Dienst‑Locator (Port, Gewichtung) | Client muss SRV‑Lookup überhaupt unterstützen |
| `PTR` | Reverse Lookup IP → Name | Muss auf **kanonischen** Host zeigen, keine CNAMEs |

> **Leitsatz:** Jede IP in einer Forward‑Zone braucht genau **eine** PTR‑Zuordnung in der korrespondierenden Reverse‑Zone.

### 5.4  Zonenaufbau & Direktiven
```
$ORIGIN smartlearn.lan.
$TTL 3600         ; Default TTL
@  IN SOA dns.smartlearn.dmz. admin.smartlearn.dmz. (
   2025060401     ; Serial YYYYMMDDnn
   1d             ; Refresh
   2h             ; Retry
   4w             ; Expire
   1h )           ; Negative Cache TTL

; Name Server
@     IN NS dns.smartlearn.dmz.

; Hosts
vmkl1 IN A 192.168.110.70
```

**Serial‑Strategien**  
*Datum* (`YYYYMMDDnn`) ist menschlich lesbar, limitiert aber auf 99 Änderungen/Tag.  
*Epoch* (`UNIX‑Zeit`) garantiert Monotonie.  
Wichtig ist allein: **inkrementieren**, sobald Records geändert werden.

### 5.5  Reverse Lookup & PTR‑Zonen
Reverse‑Zones folgen dem Muster `<octet>.<octet>.<octet>.in-addr.arpa`. Für 192.168.110.0/24 also `110.168.192.in-addr.arpa`.

```
$ORIGIN 110.168.192.in-addr.arpa.
$TTL 3600
@ IN SOA dns.smartlearn.dmz. admin.smartlearn.dmz. (
   2025060401 1d 2h 4w 1h )
@ IN NS dns.smartlearn.dmz.

70 IN PTR vmkl1.smartlearn.lan.
```

### 5.6  Zone‑Transfer & Replizierung
* **AXFR** – Volltransfer (TCP 53), simpel aber Traffic‑intensiv.  
* **IXFR** – *Incremental Transfer*, sendet nur Diffs: Skalierbarer für grosse Zonen.  
* **TSIG** – HMAC‑basierte Signatur, sichert Authentizität + Integrität zwischen Primary & Secondary.

> Sekundäre Nameserver verhindern SPOF (Single Point of Failure) und bieten Lastverteilung.

### 5.7  Caching & TTL‑Tuning
Kurze TTL (≤300 s) → schnelle Propagation, mehr Traffic.  
Lange TTL (≥86400 s) → weniger Queries, langsamere Updates.  
**Best Practice:** Produktion ≥3600 s, Migrationen temporär 300 s.

### 5.8  DNSSEC – Chain of Trust (erweitert)
| Schlüssel | Aufgabe | Roll‑Over Praxis |
|-----------|---------|------------------|
| **KSK** | Signiert DNSKEY‑RR‑Set | Wechsel selten (1‑2× pro Jahr), erfordert DS‑Update im Parent |
| **ZSK** | Signiert alle übrigen RR‑Sets | Wechsel häufiger (60‑90 Tage) |

Roll‑Over erfolgt per *Pre‑Publish/Double‑Signature*: Neuer Schlüssel wird hinzugefügt und beide gleichzeitig signieren, bevor der alte entfernt wird.

### 5.9  Monitoring & Troubleshooting
* **`dig +trace <name>`** – verfolgt Delegationsweg bis zur Autorität.  
* **`rndc status`** – Zustand des BIND‑Servers.  
* **`dnstap`** – Echtzeit‑Query‑Telemetry für forensische Auswertungen.

---

## 6  Banner & Fingerprinting (Information Disclosure)
  Banner & Fingerprinting (Information Disclosure)

### 6.1  Warum Banner gefährlich sind
* Version Strings liefern Angreifern präzise Exploit‑Suchbegriffe.  
* Weniger Metadaten = weniger automatisierte Angriffs­entscheidungen.

### 6.2  Defense Techniques
* **ServerTokens/ServerSignature** bei Apache, **`version none;`** bei BIND.  
* Opportunistischer Schutz: Kein Hard‑Stop, aber senkt Script‑Kiddy‑Noise.

---

## 7  Verification & Monitoring (Assurance Layer)

### 7.1  Checklisten‑Mentalität
* Automatisierte Checks → *Compliance as Code* (z. B. Ansible‑Audit).  
* Manueller Quick‑Audit – Fokus auf Port‑Exposure, Auth‑Mechanismen, Log‑Anomalien.

### 7.2  Logging Hierarchy
1. **Systemd‑Journal** – Kernel & Service‑Stacks  
2. **Application Logs** – BIND Querylog, Apache Access  
3. **Network Flow** – Firewall Counters, NetFlow/IPFIX

Korrelation ≙ Erkennung; ohne Zentralisierung (ELK/Grafana Loki) bleibt vieles unentdeckt.

---

## 8  Fazit
Theorie liefert das **Warum** hinter jedem Befehl. Verinnerliche diese Prinzipien, bevor du Skripte kopierst – sie helfen dir, künftige Technologien eigenständig zu beurteilen und robuste Security‑Architekturen zu entwerfen.

---
