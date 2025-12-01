/*
 * ShadowLink C2 Agent
 * Phase 1: TCP Client - Se connecter au serveur C2
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

// Configuration
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4444  // ← INT, pas string !

#endif

