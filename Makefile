all:
	gcc keystroke_helper.c -o keystroke_helper
	gcc main.c -o check_id -lpam -lpam_misc
