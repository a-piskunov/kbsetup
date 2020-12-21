#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, const char *argv[])
{
    if (mkdir("/etc/keystroke-pam",0777)&& errno != EEXIST) {
//        perror(argv[0]);
        printf("RERROR");
        exit(EXIT_FAILURE);
    }

    return 0;
}

//if(mkdir(path, 0777) && errno != EEXIST)
//printf("error while trying to create '%s'\n%m\n", path);