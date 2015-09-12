.global _start
.global hook_context

.extern hook_main

_start:
jmp hook_main
.byte 0, 0, 0

hook_context:
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
.quad 0
