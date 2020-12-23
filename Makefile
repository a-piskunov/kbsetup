all:
	gcc keystroke_helper.c -o keystroke_helper
	gcc kbsetup.c manhattan.c -o /sbin/kbsetup -lpam -lpam_misc -lm