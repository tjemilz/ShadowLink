# 🔗 ShadowLink C2 Framework

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows-blue?style=flat-square&logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/Language-C%20%7C%20Python-green?style=flat-square" alt="Language">
  <img src="https://img.shields.io/badge/Purpose-Educational-red?style=flat-square" alt="Purpose">
  <img src="https://img.shields.io/badge/Phase-11-purple?style=flat-square" alt="Phase">
</p>

---

## ⚠️ AVERTISSEMENT LÉGAL

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                         USAGE ÉDUCATIF UNIQUEMENT                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Ce logiciel est développé EXCLUSIVEMENT à des fins éducatives pour          ║
║  comprendre les techniques offensives et mieux s'en protéger.                ║
║                                                                              ║
║  ❌ NE PAS utiliser sur des systèmes sans autorisation écrite explicite      ║
║  ❌ NE PAS utiliser pour des activités malveillantes ou illégales            ║
║  ❌ NE PAS distribuer à des fins malveillantes                               ║
║                                                                              ║
║  L'auteur décline toute responsabilité pour toute utilisation abusive.       ║
║  Articles applicables : 323-1 à 323-8 du Code pénal français                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 📋 Table des matières

1. [Vue d'ensemble](#-vue-densemble)
2. [Architecture](#-architecture)
3. [Phases de développement](#-phases-de-développement)
4. [Techniques implémentées](#-techniques-implémentées)
5. [Installation](#-installation)
6. [Utilisation](#-utilisation)
7. [Commandes](#-commandes)
8. [MITRE ATT&CK Mapping](#-mitre-attck-mapping)

---

## 🎯 Vue d'ensemble

ShadowLink est un framework C2 (Command & Control) éducatif développé progressivement en **11 phases**. Chaque phase introduit de nouvelles techniques offensives avec des explications détaillées sur leur fonctionnement et leur détection.

### Objectif pédagogique

| Domaine | Apprentissage |
|---------|---------------|
| **Programmation système** | API Windows, mémoire, handles, PEB/TEB |
| **Programmation réseau** | Sockets TCP, HTTPS, WinHTTP |
| **Cryptographie** | AES-256, XOR, RC4 |
| **Offensive Security** | Évasion, persistance, injection, syscalls |
| **Defensive Security** | Détection, IOCs, réponse à incident |

### Composants

```
┌─────────────────────────────────────────────────────────────────┐
│                        SHADOWLINK                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐       │
│  │   STAGER    │────▶│   AGENT     │◀───▶│   SERVER    │       │
│  │   (~10KB)   │     │   (Full)    │     │   (Python)  │       │
│  │     C       │     │     C       │     │             │       │
│  └─────────────┘     └─────────────┘     └─────────────┘       │
│        │                   │                   │                │
│        ▼                   ▼                   ▼                │
│  • Reflective PE     • HTTPS C2          • Multi-agents        │
│  • RC4 decrypt       • Sleep obfusc      • Chiffrement AES     │
│  • Fileless          • Direct syscalls   • CLI interactive     │
│                      • Persistence                              │
│                      • Credential dump                          │
│                      • Process injection                        │
│                      • Privilege escalation                     │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🏗️ Architecture

### Communication C2

```
┌──────────────┐                                    ┌──────────────┐
│    AGENT     │                                    │    SERVER    │
│              │                                    │              │
│  ┌────────┐  │     HTTPS (Port 443)              │  ┌────────┐  │
│  │WinHTTP │──┼───────────────────────────────────┼──│ Flask  │  │
│  └────────┘  │     TLS Encrypted                 │  └────────┘  │
│      │       │                                    │      │       │
│      ▼       │     Endpoints REST:               │      ▼       │
│  ┌────────┐  │     /api/v1/health/status (beacon)│  ┌────────┐  │
│  │ AES256 │  │     /api/v1/config/update (data)  │  │ AES256 │  │
│  └────────┘  │                                    │  └────────┘  │
│              │                                    │              │
└──────────────┘                                    └──────────────┘
```

### Flux d'exécution Agent

```
DÉMARRAGE
    │
    ▼
┌─────────────────────────────────┐
│ 1. Process Masquerading         │  ← Modifier PEB pour ressembler à svchost.exe
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│ 2. Delayed Execution (10s)      │  ← Éviter les sandbox avec timeout court
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│ 3. Evasion Checks               │  ← Détecter VM, debugger, sandbox
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│ 4. Anti-EDR (AMSI/ETW patch)    │  ← Désactiver la télémétrie Windows
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│ 5. Init Syscalls (Hell's Gate)  │  ← Résoudre numéros syscall dynamiquement
└─────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────┐
│ 6. Main Loop                    │
│   ├── Beacon HTTPS              │
│   ├── Execute Command           │
│   ├── Sleep Obfuscation (Ekko)  │  ← Chiffrer mémoire pendant sleep
│   └── Repeat                    │
└─────────────────────────────────┘
```

---

## 📈 Phases de développement

| Phase | Nom | Techniques introduites |
|-------|-----|------------------------|
| 1 | Connexion basique | Socket TCP, Winsock2 |
| 2 | Shell interactif | CreateProcess, pipes anonymes |
| 3 | Chiffrement | AES-256-CBC, PKCS7 padding |
| 4 | Reconnaissance | Énumération système/réseau/user |
| 5 | Persistance | Registry Run, Task Scheduler |
| 6 | Multi-agents | Gestion sessions, sélection |
| 7 | Évasion basique | Anti-debug, Anti-VM, Anti-sandbox |
| 8 | Anti-EDR | AMSI bypass, ETW patch, Unhooking |
| 9 | Credentials | WiFi, Browser, Vault |
| 10 | Privilege Escalation | UAC bypass, BYOVD, Tokens |
| **11** | **Advanced Stealth** | **HTTPS, Sleep obfusc, Direct Syscalls** |

---

## 🛡️ Techniques implémentées

### 1. ÉVASION - Contournement des défenses

#### 1.1 Anti-Debug
```
Objectif : Détecter si l'agent est analysé dans un debugger
Technique : Vérification de IsDebuggerPresent, NtGlobalFlag, timing checks
Fichier  : agent.c → perform_evasion_checks()
```

#### 1.2 Anti-VM
```
Objectif : Détecter les environnements virtualisés (analyse sandbox)
Technique : Recherche de processus VM (vmtoolsd, VBoxService), 
            clés registre VMware/VirtualBox, instructions CPUID
Fichier  : agent.c → detect_vm(), detect_sandbox_artifacts()
```

#### 1.3 Anti-Sandbox (Delayed Execution)
```
Objectif : Éviter l'analyse automatisée qui a un timeout court
Technique : Sleep de 10 secondes au démarrage avec vérification
            que le temps n'est pas accéléré
Fichier  : agent.c → delayed_execution()
```

#### 1.4 Process Masquerading
```
Objectif : Se faire passer pour un processus Windows légitime
Technique : Modification du PEB (Process Environment Block) pour
            changer ImagePathName et CommandLine visibles
Fichier  : agent.c → masquerade_process()
Impact   : Apparaît comme "svchost.exe" dans Task Manager
```

#### 1.5 String Encryption (XOR)
```
Objectif : Cacher les strings suspectes de l'analyse statique
Technique : Chiffrement XOR avec clé 0x5A, déchiffrement au runtime
Fichier  : agent.c → xor_decrypt(), encrypted_ip[]
```

---

### 2. ANTI-EDR - Désactivation des protections

#### 2.1 AMSI Bypass
```
Objectif : Désactiver l'Antimalware Scan Interface
Technique : Patcher amsi.dll!AmsiScanBuffer pour retourner 
            AMSI_RESULT_CLEAN immédiatement
Fichier  : agent.c → bypass_amsi()
Code     : mov eax, 0x80070057; ret (retourne E_INVALIDARG)
Impact   : PowerShell et scripts ne sont plus scannés
```

#### 2.2 ETW Patching
```
Objectif : Désactiver Event Tracing for Windows (télémétrie)
Technique : Patcher ntdll!EtwEventWrite pour retourner immédiatement
Fichier  : agent.c → patch_etw()
Impact   : Plus de logs ETW générés par le processus
```

#### 2.3 NTDLL Unhooking
```
Objectif : Supprimer les hooks EDR dans ntdll.dll
Technique : Remapper une copie propre de ntdll.dll depuis le disque
            par-dessus la version hookée en mémoire
Fichier  : agent.c → unhook_ntdll()
Impact   : Restaure les fonctions originales sans hooks EDR
```

---

### 3. DIRECT SYSCALLS - Contournement hooks usermode

#### 3.1 Hell's Gate
```
Objectif : Appeler les syscalls directement sans passer par ntdll hookée
Technique : 
  1. Lire ntdll.dll propre depuis C:\Windows\System32\
  2. Parser les exports, trouver les fonctions Nt*
  3. Extraire le numéro syscall (mov eax, <number>)
  4. Appeler syscall directement avec ce numéro
Fichier  : syscalls.c → init_syscall_table_hellsgate()
Impact   : Bypass complet des hooks usermode EDR
```

```c
// Pattern recherché dans ntdll pour extraire syscall number
mov r10, rcx        // 4C 8B D1
mov eax, <syscall>  // B8 XX XX 00 00  ← On extrait XX XX
syscall             // 0F 05
ret                 // C3
```

#### 3.2 APIs Bypassées
| API | Usage |
|-----|-------|
| `NtAllocateVirtualMemory` | Allocation mémoire (shellcode) |
| `NtProtectVirtualMemory` | Changer permissions (RWX) |
| `NtWriteVirtualMemory` | Écrire dans autre process |
| `NtCreateThreadEx` | Créer thread remote |
| `NtOpenProcess` | Ouvrir handle sur process |
| `NtClose` | Fermer handles |

---

### 4. SLEEP OBFUSCATION - Évasion mémoire

#### 4.1 Technique Ekko
```
Objectif : Rendre l'agent invisible aux memory scanners pendant le sleep
Technique :
  1. Avant sleep: chiffrer sections .text et .data avec XOR
  2. Créer ROP chain: VirtualProtect → SystemFunction032 → NtContinue
  3. Utiliser CreateTimerQueueTimer pour programmer le réveil
  4. Le timer callback exécute le ROP qui déchiffre et restaure
Fichier  : sleep_obfuscation.c → ekko_sleep()
Impact   : Code chiffré en mémoire = pas de signatures détectables
```

```
┌────────────────────────────────────────────────────────────┐
│                  SLEEP OBFUSCATION                         │
├────────────────────────────────────────────────────────────┤
│  AVANT SLEEP          PENDANT SLEEP        APRÈS SLEEP    │
│  ────────────         ─────────────        ───────────    │
│  .text: CODE  ──XOR─▶ .text: %#@!&* ──XOR─▶ .text: CODE   │
│  .data: DATA  ──XOR─▶ .data: $@#%^& ──XOR─▶ .data: DATA   │
│  [Détectable]         [Illisible]          [Restauré]     │
└────────────────────────────────────────────────────────────┘
```

---

### 5. COMMUNICATION C2

#### 5.1 HTTPS Transport
```
Objectif : Éviter la détection réseau (port 4444 = suspect)
Technique : WinHTTP API, TLS sur port 443, endpoints REST déguisés
Fichier  : https_transport.c → https_init(), https_beacon()
Endpoints:
  - GET  /api/v1/health/status  → Beacon (semble être health check)
  - POST /api/v1/config/update  → Upload données
Impact   : Traffic indistinguable d'une API web légitime
```

#### 5.2 Chiffrement AES-256
```
Objectif : Confidentialité des communications
Technique : AES-256-CBC avec IV aléatoire, padding PKCS7
Fichier  : aes.c (tiny-AES-c)
Note     : Double chiffrement - TLS (transport) + AES (application)
```

---

### 6. PERSISTENCE - Survie au reboot

#### 6.1 Registry Run Key
```
Objectif : Exécution automatique au démarrage de session
Technique : Écriture dans HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Fichier  : agent.c → install_persistence()
Clé      : "WindowsSecurityHealth" (nom légitime)
```

#### 6.2 Scheduled Task
```
Objectif : Persistance alternative plus discrète
Technique : Création de tâche planifiée via schtasks.exe
Trigger  : Au logon de l'utilisateur
```

---

### 7. PRIVILEGE ESCALATION

#### 7.1 UAC Bypass (fodhelper)
```
Objectif : Élever les privilèges sans prompt UAC
Technique : Manipulation de clés registre pour fodhelper.exe
  1. Écrire dans HKCU\Software\Classes\ms-settings\Shell\Open\command
  2. Lancer fodhelper.exe (auto-elevate, vérifie ms-settings)
  3. fodhelper exécute notre payload avec privilèges élevés
Fichier  : agent.c → uac_bypass_fodhelper()
```

#### 7.2 BYOVD (Bring Your Own Vulnerable Driver)
```
Objectif : Obtenir exécution kernel pour désactiver protections
Technique : 
  1. Charger un driver signé mais vulnérable
  2. Exploiter la vuln pour exécuter code en kernel
  3. Killer les processus EDR depuis le kernel
Fichier  : agent.c → byovd_load_driver()
Impact   : Peut tuer n'importe quel processus, même protected
```

---

### 8. CREDENTIAL ACCESS

#### 8.1 WiFi Passwords
```
Objectif : Récupérer les mots de passe WiFi enregistrés
Technique : netsh wlan show profile key=clear
Fichier  : agent.c → dump_wifi_passwords()
```

#### 8.2 Windows Credential Manager
```
Objectif : Accéder aux credentials stockées dans le Vault
Technique : API CredEnumerate + CredRead
Fichier  : agent.c → dump_credential_manager()
```

#### 8.3 Browser Credentials
```
Objectif : Localiser les fichiers de credentials navigateurs
Technique : Énumérer les paths Chrome/Firefox/Edge Login Data
Fichier  : agent.c → dump_browser_paths()
```

---

### 9. STAGER - Livraison initiale

#### 9.1 Reflective PE Loading
```
Objectif : Charger l'agent complet en mémoire sans toucher le disque
Technique :
  1. Télécharger payload chiffré via HTTPS
  2. Déchiffrer avec RC4
  3. Parser headers PE en mémoire
  4. Allouer mémoire, copier sections
  5. Résoudre imports, appliquer relocations
  6. Appeler EntryPoint
Fichier  : stager/stager.c → reflective_load_pe()
Impact   : Fileless execution - rien sur disque
```

---

## 🛠️ Installation

### Prérequis

```bash
# Windows - Agent (cross-compilation depuis Linux)
sudo apt install mingw-w64

# Serveur
Python 3.8+
pip install flask pycryptodome
```

### Compilation

```bash
# Agent complet (debug, avec console)
make agent

# Agent stealth (sans console)
make agent-stealth

# Stager minimal (~10KB)
make stager

# Génération certificats SSL
make certs
```

---

## 🚀 Utilisation

### 1. Démarrer le serveur

```bash
# HTTPS (recommandé - Phase 11)
python server/server_https.py

# TCP legacy
python server/server.py
```

### 2. Déployer l'agent

```cmd
agent.exe
```

### 3. Interagir

```
ShadowLink> list
[*] Connected agents:
    [0] DESKTOP-ABC123 - 192.168.1.50 - Admin

ShadowLink> select 0
DESKTOP-ABC123> recon
DESKTOP-ABC123> creds
DESKTOP-ABC123> persist
```

---

## 💻 Commandes

| Commande | Description | Phase |
|----------|-------------|-------|
| `<cmd>` | Exécuter commande shell | 2 |
| `exit` | Déconnecter (reconnexion auto) | 2 |
| `die` | Terminer définitivement | 7 |
| `recon` | Reconnaissance système | 4 |
| `ps` | Lister processus | 7 |
| `kill <pid>` | Terminer processus | 7 |
| `download <path>` | Télécharger fichier | 7 |
| `upload <path>` | Envoyer fichier | 7 |
| `persist` | Installer persistance | 5 |
| `unpersist` | Supprimer persistance | 5 |
| `creds` | Dump credentials | 9 |
| `wifi` | Dump WiFi passwords | 9 |
| `sleep <ms>` | Changer intervalle beacon | 11 |
| `inject <pid>` | Injection processus | 9 |
| `elevate` | Élévation privilèges | 10 |
| `selfdestruct` | Auto-destruction | 7 |

---

## 🎯 MITRE ATT&CK Mapping

| ID | Technique | Implémentation |
|----|-----------|----------------|
| T1055 | Process Injection | `inject_shellcode_into_process()` |
| T1055.012 | Process Hollowing | Stager reflective loading |
| T1547.001 | Registry Run Keys | `install_persistence()` |
| T1053.005 | Scheduled Task | Tâche planifiée backup |
| T1562.001 | Disable Security Tools | AMSI/ETW bypass |
| T1027 | Obfuscated Files | XOR strings, AES comms |
| T1497 | Sandbox Evasion | Anti-VM, Anti-sandbox |
| T1106 | Native API | Direct syscalls |
| T1548.002 | UAC Bypass | fodhelper exploit |
| T1068 | Exploitation for Priv Esc | BYOVD |
| T1003 | Credential Dumping | WiFi, Vault, Browser |
| T1071.001 | Web Protocols | HTTPS C2 |
| T1573.001 | Encrypted Channel | AES-256 |

---

## 📊 Évaluation de la menace

```
╔═══════════════════════════════════════════════════════════╗
║              THREAT ASSESSMENT - Phase 11                 ║
╠═══════════════════════════════════════════════════════════╣
║  Sophistication:        ███████░░░  7/10                  ║
║  Évasion AV/EDR:        ██████░░░░  6/10                  ║
║  Furtivité réseau:      ███████░░░  7/10                  ║
║  Fonctionnalités:       ████████░░  8/10                  ║
╠═══════════════════════════════════════════════════════════╣
║  RISQUE GLOBAL:         ██████░░░░  6/10                  ║
╚═══════════════════════════════════════════════════════════╝
```

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [phase11_guide.md](docs/phase11_guide.md) | Guide Phase 11 détaillé |
| [kill_chain_analysis.md](docs/kill_chain_analysis.md) | Analyse techniques avancées |

---

## 🙏 Remerciements

- [tiny-AES-c](https://github.com/kokke/tiny-AES-c) - Implémentation AES
- [MITRE ATT&CK](https://attack.mitre.org/) - Framework de référence

---

<p align="center">
  <i>« Comprendre l'attaque pour mieux défendre »</i>
  <br><br>
  <b>⚠️ Usage éducatif uniquement ⚠️</b>
</p>


