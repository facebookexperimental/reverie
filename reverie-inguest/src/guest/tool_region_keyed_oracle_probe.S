/* Native fixture only: the target MOV labels are the fault identity oracle. */
.text
.p2align 4
.global reverie_keyed_oracle_load
.type reverie_keyed_oracle_load,@function
reverie_keyed_oracle_load:
    mov r8, rdx
    xor ecx, ecx
    rdpkru
    mov r9d, eax
    mov eax, esi
    xor edx, edx
    wrpkru
    lfence
    xor esi, esi
.global reverie_keyed_oracle_load_mov
reverie_keyed_oracle_load_mov:
    mov sil, byte ptr [rdi]
    mov eax, r9d
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
    rdpkru
    mov dword ptr [r8], eax
    movzx eax, sil
    ret
.size reverie_keyed_oracle_load, .-reverie_keyed_oracle_load

.p2align 4
.global reverie_keyed_oracle_store
.type reverie_keyed_oracle_store,@function
reverie_keyed_oracle_store:
    mov r8, rcx
    mov r10d, edx
    xor ecx, ecx
    rdpkru
    mov r9d, eax
    mov eax, esi
    xor edx, edx
    wrpkru
    lfence
.global reverie_keyed_oracle_store_mov
reverie_keyed_oracle_store_mov:
    mov byte ptr [rdi], r10b
    mov eax, r9d
    xor ecx, ecx
    xor edx, edx
    wrpkru
    lfence
    rdpkru
    mov dword ptr [r8], eax
    ret
.size reverie_keyed_oracle_store, .-reverie_keyed_oracle_store

.p2align 4
.global reverie_keyed_oracle_sigreturn
.type reverie_keyed_oracle_sigreturn,@function
reverie_keyed_oracle_sigreturn:
    mov eax, 15
    syscall
    ud2
.size reverie_keyed_oracle_sigreturn, .-reverie_keyed_oracle_sigreturn
.section .note.GNU-stack,"",@progbits
