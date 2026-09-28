    .section .text.start
    .arm
    .global _start
_start:
    ldr sp, =0x02300000
    ldr r0, =__bss_start
    ldr r1, =__bss_end
    mov r2, #0
1:  cmp r0, r1
    strlo r2, [r0], #4
    blo 1b
    bl game_main
    b .
