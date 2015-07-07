.global _start

.extern hook_main

_start:
jmp hook_main
