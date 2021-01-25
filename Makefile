all:
	gcc kbsetup.c manhattan.c -o /usr/sbin/kbsetup -lpam -lpam_misc -lm