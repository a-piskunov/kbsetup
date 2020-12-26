#include <dirent.h>
#include <stdio.h>

int main(void) {
    DIR *d;
    struct dirent *dir;
    d = opendir("/etc/keystroke-pam");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            printf("%s\n", dir->d_name);
            if (dir->d_type == DT_REG)
            {
                printf("%s\n", dir->d_name);
            }

        }
        closedir(d);
    }
    return(0);
}