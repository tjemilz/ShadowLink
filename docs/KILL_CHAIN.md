# 🎯 Kill Chain - Guide Complet

> **Documentation éducative** : Comprendre les phases d'une cyberattaque pour mieux s'en défendre.

---

## 📋 Table des matières

### Partie 1 : Synthèse
1. [Vue d'ensemble](#-vue-densemble)
2. [Les 7 phases de la Kill Chain](#-les-7-phases)
3. [Mapping MITRE ATT&CK](#-mapping-mitre-attck)
4. [Techniques par phase (résumé)](#-techniques-par-phase-résumé)

### Partie 2 : Détails Techniques
5. [Phase 1 : Reconnaissance](#-phase-1--reconnaissance-détails)
6. [Phase 2 : Weaponization](#-phase-2--weaponization-détails)
7. [Phase 3 : Delivery](#-phase-3--delivery-détails)
8. [Phase 4 : Exploitation](#-phase-4--exploitation-détails)
9. [Phase 5 : Installation](#-phase-5--installation-détails)
10. [Phase 6 : Command & Control](#-phase-6--command--control-détails)
11. [Phase 7 : Actions on Objectives](#-phase-7--actions-on-objectives-détails)

### Annexes
12. [Détection par phase](#-détection-par-phase)
13. [Outils par phase](#-outils-par-phase)
14. [Références](#-références)

---

# PARTIE 1 : SYNTHÈSE

---

## 🔄 Vue d'ensemble

### Cyber Kill Chain (Lockheed Martin)

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CYBER KILL CHAIN                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐                 │
│  │    1     │   │    2     │   │    3     │   │    4     │                 │
│  │  RECON   │──►│ WEAPON-  │──►│ DELIVERY │──►│ EXPLOIT- │                 │
│  │          │   │ IZATION  │   │          │   │  ATION   │                 │
│  └──────────┘   └──────────┘   └──────────┘   └──────────┘                 │
│       │                                             │                       │
│       │                                             ▼                       │
│       │         ┌──────────┐   ┌──────────┐   ┌──────────┐                 │
│       │         │    7     │   │    6     │   │    5     │                 │
│       │         │ ACTIONS  │◄──│   C2     │◄──│ INSTALL- │                 │
│       │         │          │   │          │   │  ATION   │                 │
│       │         └──────────┘   └──────────┘   └──────────┘                 │
│       │                             │                                       │
│       └─────────────────────────────┴── Feedback loop ──────────────────►  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Principe clé

> **"L'attaquant doit réussir toutes les phases. Le défenseur n'a besoin de bloquer qu'une seule phase pour stopper l'attaque."**

---

## 📊 Les 7 Phases

| # | Phase | Description | Durée typique |
|---|-------|-------------|---------------|
| 1 | **Reconnaissance** | Collecte d'informations sur la cible | Jours → Mois |
| 2 | **Weaponization** | Création du payload malveillant | Heures → Jours |
| 3 | **Delivery** | Transmission du payload à la cible | Secondes → Jours |
| 4 | **Exploitation** | Exécution du code via une vulnérabilité | Millisecondes |
| 5 | **Installation** | Établissement de la persistance | Secondes → Minutes |
| 6 | **Command & Control** | Communication avec l'infrastructure attaquant | Continu |
| 7 | **Actions on Objectives** | Réalisation de l'objectif final | Heures → Mois |

---

## 🗺️ Mapping MITRE ATT&CK

```
Kill Chain Phase          │  MITRE ATT&CK Tactics
──────────────────────────┼───────────────────────────────────
1. Reconnaissance         │  TA0043 - Reconnaissance
2. Weaponization          │  TA0042 - Resource Development
3. Delivery               │  TA0001 - Initial Access
4. Exploitation           │  TA0002 - Execution
5. Installation           │  TA0003 - Persistence
                          │  TA0004 - Privilege Escalation
                          │  TA0005 - Defense Evasion
6. Command & Control      │  TA0011 - Command and Control
7. Actions on Objectives  │  TA0006 - Credential Access
                          │  TA0007 - Discovery
                          │  TA0008 - Lateral Movement
                          │  TA0009 - Collection
                          │  TA0010 - Exfiltration
                          │  TA0040 - Impact
```

---

## 📝 Techniques par Phase (Résumé)

### Phase 1 : Reconnaissance

| Catégorie | Techniques |
|-----------|------------|
| **OSINT** | Google Dorks, Shodan, Censys, theHarvester |
| **Social** | LinkedIn, réseaux sociaux, organigrammes |
| **Technique** | DNS enumeration, port scanning, fingerprinting |
| **Active** | Vulnerability scanning, web crawling |

### Phase 2 : Weaponization

| Catégorie | Techniques |
|-----------|------------|
| **Documents** | Macro Office, OLE, DDE, PDF exploits |
| **Exécutables** | Droppers, packers, crypters |
| **Scripts** | PowerShell, VBS, HTA, JS |
| **Exploits** | Zero-days, N-days, exploit kits |

### Phase 3 : Delivery

| Catégorie | Techniques |
|-----------|------------|
| **Email** | Phishing, spear-phishing, attachments, links |
| **Web** | Drive-by download, watering hole, malvertising |
| **Physique** | USB drop, supply chain, insider |
| **Réseau** | Exploitation directe, MitM |

### Phase 4 : Exploitation

| Catégorie | Techniques |
|-----------|------------|
| **Client-side** | Browser exploits, document exploits |
| **Server-side** | RCE, SQLi, deserialization |
| **Local** | Privilege escalation, kernel exploits |
| **Social** | Credential phishing, MFA bypass |

### Phase 5 : Installation

| Catégorie | Techniques |
|-----------|------------|
| **Registry** | Run keys, Services, COM hijacking |
| **Filesystem** | Startup folder, DLL hijacking |
| **Scheduled** | Tâches planifiées, WMI subscriptions |
| **Avancé** | Bootkit, rootkit, firmware implant |

### Phase 6 : Command & Control

| Catégorie | Techniques |
|-----------|------------|
| **Protocoles** | HTTP/S, DNS, ICMP, WebSocket |
| **Évasion** | Domain fronting, CDN, fast-flux |
| **Chiffrement** | TLS, custom encryption |
| **Canaux alternatifs** | Réseaux sociaux, cloud storage, email |

### Phase 7 : Actions on Objectives

| Catégorie | Techniques |
|-----------|------------|
| **Credentials** | Mimikatz, LSASS dump, Kerberoasting |
| **Lateral Movement** | PsExec, WMI, RDP, Pass-the-Hash |
| **Collection** | Keylogger, screenshot, file exfil |
| **Impact** | Ransomware, wiper, cryptominer |

---

# PARTIE 2 : DÉTAILS TECHNIQUES

---

## 🔍 Phase 1 : Reconnaissance (Détails)

### 1.1 Reconnaissance Passive

#### OSINT (Open Source Intelligence)

```
┌─────────────────────────────────────────────────────────────┐
│                    OSINT SOURCES                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  INFRASTRUCTURE:                                            │
│  ├── Shodan, Censys, ZoomEye (devices exposés)              │
│  ├── DNS records (MX, TXT, SPF, DKIM)                       │
│  ├── Certificate Transparency logs                          │
│  ├── BGP/ASN information                                    │
│  ├── WHOIS (domaines, IP)                                   │
│  └── Wayback Machine (historique)                           │
│                                                             │
│  PERSONNES:                                                 │
│  ├── LinkedIn (employés, technologies, organigramme)        │
│  ├── GitHub (code, credentials leakés)                      │
│  ├── Social media (Facebook, Twitter, Instagram)            │
│  ├── Data breaches (HaveIBeenPwned)                         │
│  └── Publications, conférences                              │
│                                                             │
│  ENTREPRISE:                                                │
│  ├── Job postings (stack technologique)                     │
│  ├── Press releases                                         │
│  ├── Documents publics (SEC filings, etc.)                  │
│  └── Reviews (Glassdoor → culture interne)                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Outils OSINT

| Outil | Usage |
|-------|-------|
| **theHarvester** | Emails, sous-domaines, IPs |
| **Maltego** | Visualisation de relations |
| **Recon-ng** | Framework OSINT modulaire |
| **SpiderFoot** | OSINT automatisé |
| **Amass** | Énumération DNS avancée |
| **Shodan** | Devices et services exposés |

### 1.2 Reconnaissance Active

```bash
# Énumération DNS
dig axfr @ns1.target.com target.com
dnsrecon -d target.com -t axfr
subfinder -d target.com

# Port scanning
nmap -sS -sV -O -p- target.com
masscan -p1-65535 --rate=1000 target.com

# Web enumeration
gobuster dir -u https://target.com -w wordlist.txt
nikto -h https://target.com
wpscan --url https://target.com

# Vulnerability scanning
nessus, OpenVAS, Nuclei
```

---

## 🔧 Phase 2 : Weaponization (Détails)

### 2.1 Types de Payloads

```
┌─────────────────────────────────────────────────────────────┐
│                    PAYLOAD TYPES                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  DOCUMENTS MALVEILLANTS:                                    │
│  ├── Office Macros (VBA)                                    │
│  │   └── Auto-exécution via AutoOpen, Document_Open         │
│  ├── OLE Objects (embedded executables)                     │
│  ├── DDE (Dynamic Data Exchange)                            │
│  ├── Template Injection (.dotm remote)                      │
│  └── PDF (JavaScript, embedded files)                       │
│                                                             │
│  EXÉCUTABLES:                                               │
│  ├── EXE/DLL (natif Windows)                                │
│  ├── Shellcode (position-independent)                       │
│  ├── .NET assemblies                                        │
│  └── Packed/Crypted (UPX, custom)                           │
│                                                             │
│  SCRIPTS:                                                   │
│  ├── PowerShell (.ps1, encoded)                             │
│  ├── VBScript (.vbs)                                        │
│  ├── JScript (.js)                                          │
│  ├── HTA (.hta - HTML Application)                          │
│  └── Batch (.bat, .cmd)                                     │
│                                                             │
│  WEB:                                                       │
│  ├── Exploit kits (RIG, Magnitude)                          │
│  ├── Browser exploits (Chrome, Firefox, IE)                 │
│  └── Malicious JavaScript                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Frameworks de génération

| Framework | Type | Payloads |
|-----------|------|----------|
| **Metasploit** | Open source | Shellcode, exe, scripts |
| **Cobalt Strike** | Commercial | Beacon, stageless |
| **Sliver** | Open source | Implants Go |
| **Havoc** | Open source | Demon agent |
| **Covenant** | Open source | .NET Grunt |
| **msfvenom** | CLI | Multi-format |

### 2.3 Techniques d'évasion

```
OBFUSCATION:
├── String encoding (Base64, XOR, AES)
├── Code morphing (variable renaming)
├── Dead code insertion
├── Control flow obfuscation
└── Packing/Crypting

ANTI-ANALYSIS:
├── Anti-debugging (IsDebuggerPresent, timing)
├── Anti-VM (registry, processes, hardware)
├── Anti-sandbox (sleep, user interaction)
├── Environment checks
└── Delayed execution

SIGNATURE EVASION:
├── Polymorphism (unique per target)
├── Metamorphism (code rewriting)
├── Fileless execution
└── Living-off-the-land (LOLBins)
```

---

## 📬 Phase 3 : Delivery (Détails)

### 3.1 Vecteurs de livraison

```
┌─────────────────────────────────────────────────────────────┐
│                  DELIVERY VECTORS                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  EMAIL (le plus courant ~90%):                              │
│  ├── Spear-phishing (ciblé, personnalisé)                   │
│  ├── Phishing de masse                                      │
│  ├── Business Email Compromise (BEC)                        │
│  ├── Attachments (Office, PDF, ZIP, ISO)                    │
│  └── Links (credential harvesting, drive-by)                │
│                                                             │
│  WEB:                                                       │
│  ├── Drive-by download (exploit browser)                    │
│  ├── Watering hole (site fréquenté par cibles)              │
│  ├── Malvertising (pubs malveillantes)                      │
│  ├── Typosquatting (domaines similaires)                    │
│  └── SEO poisoning (résultats de recherche)                 │
│                                                             │
│  SUPPLY CHAIN:                                              │
│  ├── Software compromise (SolarWinds, 3CX)                  │
│  ├── Update mechanism hijack                                │
│  ├── Dependency confusion                                   │
│  └── Hardware implants                                      │
│                                                             │
│  PHYSIQUE:                                                  │
│  ├── USB drop (parking, reception)                          │
│  ├── Evil maid (accès physique)                             │
│  ├── Insider threat                                         │
│  └── Social engineering physique                            │
│                                                             │
│  RÉSEAU:                                                    │
│  ├── Exploitation directe (services exposés)                │
│  ├── VPN vulnerabilities                                    │
│  ├── RDP exposed                                            │
│  └── MitM (réseau local, WiFi)                              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Statistiques de succès

| Vecteur | Taux de succès | Difficulté défense |
|---------|---------------|-------------------|
| Spear-phishing | 30-50% | Difficile |
| USB drop | 20-40% | Moyen |
| Watering hole | Variable | Difficile |
| Direct exploit | 5-20% | Moyen |
| Supply chain | Rare mais dévastateur | Très difficile |

---

## 💥 Phase 4 : Exploitation (Détails)

### 4.1 Types d'exploitation

```
┌─────────────────────────────────────────────────────────────┐
│                  EXPLOITATION TYPES                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  CLIENT-SIDE:                                               │
│  ├── Browser exploits (memory corruption)                   │
│  ├── Document exploits (Office, PDF)                        │
│  ├── Media exploits (images, videos)                        │
│  └── Application exploits (readers, players)                │
│                                                             │
│  SERVER-SIDE:                                               │
│  ├── Remote Code Execution (RCE)                            │
│  ├── SQL Injection → command execution                      │
│  ├── Deserialization attacks                                │
│  ├── Server-Side Request Forgery (SSRF)                     │
│  ├── File upload → webshell                                 │
│  └── Template injection                                     │
│                                                             │
│  LOCAL PRIVILEGE ESCALATION:                                │
│  ├── Kernel exploits                                        │
│  ├── Service misconfigurations                              │
│  ├── DLL hijacking                                          │
│  ├── Token manipulation                                     │
│  └── UAC bypass                                             │
│                                                             │
│  AUTHENTICATION BYPASS:                                     │
│  ├── Credential stuffing                                    │
│  ├── Password spraying                                      │
│  ├── MFA bypass techniques                                  │
│  └── Session hijacking                                      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 4.2 Vulnérabilités couramment exploitées

| CVE | Produit | Type | Impact |
|-----|---------|------|--------|
| Log4Shell | Log4j | RCE | Critique |
| ProxyLogon/Shell | Exchange | RCE | Critique |
| EternalBlue | Windows SMB | RCE | Critique |
| PrintNightmare | Windows Print | RCE/LPE | Critique |
| Zerologon | Windows Netlogon | Auth bypass | Critique |
| Follina | Office/MSDT | RCE | Élevé |

---

## 🔒 Phase 5 : Installation (Détails)

### 5.1 Mécanismes de persistance

```
┌─────────────────────────────────────────────────────────────┐
│               PERSISTENCE MECHANISMS                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  REGISTRY:                                                  │
│  ├── HKCU\Software\Microsoft\Windows\CurrentVersion\Run     │
│  ├── HKLM\Software\Microsoft\Windows\CurrentVersion\Run     │
│  ├── HKCU\...\RunOnce                                       │
│  ├── Winlogon (Shell, Userinit)                             │
│  └── AppInit_DLLs                                           │
│                                                             │
│  FILESYSTEM:                                                │
│  ├── Startup folder                                         │
│  ├── DLL Search Order Hijacking                             │
│  ├── DLL Side-Loading                                       │
│  └── Phantom DLL loading                                    │
│                                                             │
│  SERVICES:                                                  │
│  ├── New service creation                                   │
│  ├── Service binary replacement                             │
│  └── Service failure recovery                               │
│                                                             │
│  SCHEDULED TASKS:                                           │
│  ├── schtasks.exe                                           │
│  ├── at.exe (legacy)                                        │
│  └── WMI Event Subscriptions                                │
│                                                             │
│  AVANCÉ:                                                    │
│  ├── COM Object Hijacking                                   │
│  ├── BITS Jobs                                              │
│  ├── Office Add-ins                                         │
│  ├── Browser extensions                                     │
│  ├── Bootkit/Rootkit                                        │
│  └── Firmware implants                                      │
│                                                             │
│  ACTIVE DIRECTORY:                                          │
│  ├── Golden Ticket                                          │
│  ├── Silver Ticket                                          │
│  ├── Skeleton Key                                           │
│  ├── DSRM Password                                          │
│  ├── AdminSDHolder                                          │
│  └── DCSync                                                 │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 5.2 Privilege Escalation

| Catégorie | Techniques |
|-----------|------------|
| **Misconfigurations** | Unquoted paths, weak permissions, AlwaysInstallElevated |
| **Credentials** | Stored creds, cached creds, autologon |
| **Token abuse** | SeImpersonate, SeBackup, SeLoadDriver |
| **Exploits** | Potato attacks, kernel exploits |
| **UAC Bypass** | fodhelper, eventvwr, cmstp |

### 5.3 Defense Evasion

| Catégorie | Techniques |
|-----------|------------|
| **Désactivation** | Kill AV, AMSI bypass, ETW patching |
| **Contournement** | Direct syscalls, unhooking, BYOVD |
| **Dissimulation** | Process injection, hollowing, masquerading |
| **Suppression traces** | Log clearing, timestomping |

---

## 📡 Phase 6 : Command & Control (Détails)

### 6.1 Architectures C2

```
┌─────────────────────────────────────────────────────────────┐
│                    C2 ARCHITECTURES                          │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  DIRECT:                                                    │
│  Agent ──────────────────────────────────────► C2 Server    │
│  • Simple mais facilement identifiable                      │
│                                                             │
│  REDIRECTORS:                                               │
│  Agent ────► Redirector ────► Redirector ────► C2 Server   │
│  • Protège le vrai C2                                       │
│  • Apache mod_rewrite, socat, iptables                      │
│                                                             │
│  DOMAIN FRONTING:                                           │
│  Agent ────► CDN (Cloudflare/Azure) ────► C2 Server        │
│  • Traffic semble aller vers CDN légitime                   │
│  • Difficile à bloquer sans casser services légitimes       │
│                                                             │
│  P2P:                                                       │
│  Agent ◄───► Agent ◄───► Agent ◄───► C2 Server             │
│  • Résilience, pas de point central                         │
│                                                             │
│  HIERARCHIQUE:                                              │
│  Agent ────► Pivot ────► Pivot ────► C2 Server             │
│  • Compromis entre contrôle et résilience                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Protocoles C2

| Protocole | Avantages | Inconvénients |
|-----------|-----------|---------------|
| **HTTP/S** | Passe firewalls, légitime | Inspecté par proxies |
| **DNS** | Rarement bloqué | Lent, petits payloads |
| **ICMP** | Souvent autorisé | Limité, détectable |
| **WebSocket** | Bidirectionnel, performant | Moins commun |
| **DoH** | Chiffré, discret | Complexe |
| **Email** | Légitime | Très lent |
| **Social Media** | Difficile à bloquer | Rate limits |
| **Cloud Storage** | Légitime | APIs trackées |

### 6.3 Techniques d'évasion C2

```
CHIFFREMENT:
├── TLS avec certificats légitimes
├── Custom encryption (AES, ChaCha20)
├── JA3 fingerprint randomization
└── Certificate pinning

TRAFFIC BLENDING:
├── Malleable C2 profiles (Cobalt Strike)
├── User-Agent rotation
├── Request/Response timing jitter
└── Mimicking legitimate applications

INFRASTRUCTURE:
├── Fast-flux DNS
├── Domain generation algorithms (DGA)
├── Expired domain reuse
└── Bulletproof hosting
```

---

## 🎯 Phase 7 : Actions on Objectives (Détails)

### 7.1 Credential Access

```
┌─────────────────────────────────────────────────────────────┐
│                  CREDENTIAL ACCESS                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  MÉMOIRE:                                                   │
│  ├── LSASS dump (Mimikatz, ProcDump, comsvcs.dll)           │
│  ├── SAM/SYSTEM/SECURITY hive extraction                    │
│  └── DCSync (si droits suffisants)                          │
│                                                             │
│  KERBEROS:                                                  │
│  ├── Kerberoasting (SPN accounts)                           │
│  ├── AS-REP Roasting (no preauth)                           │
│  ├── Pass-the-Ticket                                        │
│  └── Golden/Silver Tickets                                  │
│                                                             │
│  APPLICATIONS:                                              │
│  ├── Browser credentials (Chrome, Firefox, Edge)            │
│  ├── Email clients                                          │
│  ├── Password managers                                      │
│  └── SSH keys, certificates                                 │
│                                                             │
│  RÉSEAU:                                                    │
│  ├── LLMNR/NBT-NS poisoning                                 │
│  ├── NTLM relay                                             │
│  └── Traffic sniffing                                       │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### 7.2 Lateral Movement

| Technique | Port | Prérequis | Détection |
|-----------|------|-----------|-----------|
| **PsExec** | 445 | Admin + SMB | Event 7045 |
| **WMI** | 135+ | Admin + WMI | Event 4688 |
| **WinRM** | 5985/5986 | Admin + WinRM | PowerShell logs |
| **RDP** | 3389 | RDP access | Event 4624 type 10 |
| **DCOM** | 135+ | Admin + DCOM | Event 4688 |
| **SSH** | 22 | SSH access | SSH logs |
| **Pass-the-Hash** | Variable | NTLM hash | Event 4624 type 9 |

### 7.3 Collection

| Type | Techniques |
|------|------------|
| **Input Capture** | Keylogger, clipboard monitor |
| **Screen Capture** | Screenshots, screen recording |
| **Audio/Video** | Microphone, webcam |
| **Data Staging** | Compression, encryption, staging |
| **File Discovery** | Recherche documents sensibles |

### 7.4 Exfiltration

| Méthode | Description |
|---------|-------------|
| **C2 Channel** | Via le canal C2 existant |
| **Alternative Protocol** | DNS, ICMP, HTTPS différent |
| **Cloud Storage** | Dropbox, Google Drive, OneDrive |
| **Physical** | USB, impression |
| **Scheduled** | En dehors des heures de bureau |

### 7.5 Impact

| Type | Objectif |
|------|----------|
| **Ransomware** | Chiffrement + extorsion |
| **Wiper** | Destruction de données |
| **Cryptominer** | Ressources pour mining |
| **DDoS** | Perturbation de service |
| **Defacement** | Atteinte à la réputation |
| **Data manipulation** | Intégrité compromise |

---

## 🔍 Détection par Phase

| Phase | Indicateurs | Outils |
|-------|-------------|--------|
| **Reconnaissance** | Scans, requêtes DNS inhabituelles | IDS, DNS logs, WAF |
| **Weaponization** | N/A (externe) | Threat Intelligence |
| **Delivery** | Emails suspects, téléchargements | Email gateway, Proxy |
| **Exploitation** | Crashes, comportements anormaux | EDR, HIDS |
| **Installation** | Registry changes, new services | Sysmon, EDR |
| **C2** | Beaconing, DNS tunneling | NDR, proxy logs |
| **Actions** | Lateral movement, data access | SIEM, UEBA |

---

## 🛠️ Outils par Phase

| Phase | Offensive | Défensive |
|-------|-----------|-----------|
| **Recon** | Shodan, Maltego, Nmap | Threat Intel platforms |
| **Weaponization** | Metasploit, Cobalt Strike | Sandbox analysis |
| **Delivery** | Gophish, Social Engineering | Email security, Proxy |
| **Exploitation** | Exploit-DB, custom | EDR, patching |
| **Installation** | Custom malware | Sysmon, HIDS |
| **C2** | Cobalt Strike, Sliver | NDR, DNS monitoring |
| **Actions** | Mimikatz, BloodHound | SIEM, UEBA |

---

## 📚 Références

- [Lockheed Martin Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Unified Kill Chain](https://www.unifiedkillchain.com/)
- [SANS Incident Response](https://www.sans.org/blog/incident-response-steps/)

---

*Document créé pour ShadowLink - Projet éducatif uniquement*
