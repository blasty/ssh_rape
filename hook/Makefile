LDFLAGS=-Wl,--build-id=none -Thook.ld -nostartfiles -nodefaultlibs
CFLAGS=-nostdlib -nostdinc -fno-builtin -fPIC -ffreestanding -fno-exceptions

all:
	gcc $(LDFLAGS) $(CFLAGS) -o passlog.elf hook_crt0.s passlog.c
	strip -s passlog.elf
	objcopy -O binary passlog.elf passlog.bin
	gcc $(LDFLAGS) $(CFLAGS) -o pubkey.elf hook_crt0.s pubkey.c
	strip -s pubkey.elf
	objcopy -O binary pubkey.elf pubkey.bin

clean:
	rm -rf passlog.elf passlog.bin
	rm -rf pubkey.elf pubkey.bin
