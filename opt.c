//
// Created by alexey on 21.12.2020.
//

#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]){
    char *b;
    int rez;

//	opterr=0;
    while ( (rez = getopt(argc,argv,"ca:u:d:l")) != -1){
        switch (rez){
            /* check keyboard */
            case 'c':
                printf("found argument \"c\".\n");
                break;
            /* add user */
            case 'a':
                printf("found argument \"a = %s\".\n",optarg);
                break;
            /* update user */
            case 'u':
                printf("found argument \"u = %s\".\n",optarg);
                break;
            case 'd':
                printf("found argument \"d = %s\".\n",optarg);
                break;
            /* list users */
            case 'l':
                printf("found argument \"l\"\n");
                break;
            /* other */
            case '?':
                printf("Error found !\n");
                break;
        };
    };

};