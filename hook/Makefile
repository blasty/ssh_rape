LDFLAGS=-Wl,--build-id=none -Thook.ld -nostartfiles -nodefaultlibs
CFLAGS=-nostdlib -fno-builtin -fPIC -ffreestanding -fno-exceptions

all:
	gcc $(LDFLAGS) $(CFLAGS) -o passlog.elf hook_crt0.s passlog.c
	strip -s passlog.elf
	objcopy -O binary passlog.elf passlog.bin
	gcc $(LDFLAGS) $(CFLAGS) -o pubkey.elf hook_crt0.s pubkey.c
	strip -s pubkey.elf
	objcopy -O binary pubkey.elf pubkey.bin
	gcc $(LDFLAGS) $(CFLAGS) -o menu.elf hook_crt0.s menu.c
	strip -s menu.elf
	objcopy -O binary menu.elf menu.bin


clean:
	rm -rf passlog.elf passlog.bin
	rm -rf pubkey.elf pubkey.bin
	rm -rf menu.elf menu.bin
