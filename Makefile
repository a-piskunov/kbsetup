all:
	gcc keystroke_helper.c -o keystroke_helper
	gcc kbsetup.c -o /sbin/kbsetup -lpam -lpam_misc