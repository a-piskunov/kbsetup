#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <syslog.h>
#include <signal.h>
#include <sys/wait.h>
#include <errno.h>
#include <linux/input.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>

#define KEYSTROKE_HELPER "/home/alexey/Documents/kbsetup/keystroke_helper"
#define CONFIG_KEYBOARD "/etc/keyboard-config"
const struct pam_conv conv = {
        misc_conv,
        NULL
};

int main(int argc, char *argv[]) {
    /* check if user is root */
    if (getuid() != 0) {
        printf("Для запуска kbsetup необходимы права суперпользователя\n");
        return EXIT_FAILURE;
    }
    if(argc > 3) {
        printf("Используется лишь одна из опций -c, -a, -u, -d, -l\n");
        return EXIT_FAILURE;
    }
    char *arg_username = NULL;
    int keyboard_setup = 0;
    char *keyboard_path = NULL;
    int check_keyboard = 0;
    int add_user = 0;
    int update_user = 0;
    int delete_user = 0;
    int list_users = 0;
    int rez;
    int argument_error = 0;
//    opterr = 0;
    while ( (rez = getopt(argc,argv,"k:ca:u:d:l")) != -1){
        switch (rez){
            /* keyboard setup */
            case 'k':
                keyboard_setup = 1;
                keyboard_path = optarg;
                printf("found argument \"c\".\n");
                break;
                /* add user */
            /* check keyboard */
            case 'c':
                check_keyboard = 1;
                printf("found argument \"c\".\n");
                break;
            /* add user */
            case 'a':
                add_user = 1;
                arg_username = optarg;
                printf("found argument \"a = %s\".\n",optarg);
                break;
                /* update user */
            case 'u':
                update_user = 1;
                arg_username = optarg;
                printf("found argument \"u = %s\".\n",optarg);
                break;
                /* delete user */
            case 'd':
                delete_user = 1;
                arg_username = optarg;
                printf("found argument \"d = %s\".\n",optarg);
                break;
                /* list users */
            case 'l':
                list_users = 1;
                printf("found argument \"l\"\n");
                break;
                /* other */
            case '?':
                argument_error = 1;
                printf("Error found !\n");
                break;
        };
    };
    if (optind < argc) {
        printf("Используется лишь одна из опций -c, -a, -u, -d, -l\n");
        return EXIT_FAILURE;
    }
//    for (int index = optind; index < argc; index++)
//        printf ("Non-option argument %s\n", argv[index]);
//    return 0;
    if (argument_error||(keyboard_setup + check_keyboard + add_user + update_user + delete_user + list_users != 1)) {
        printf("Используется лишь одна из опций -c, -a, -u, -d, -l\n");
        return EXIT_FAILURE;
    }
    if (keyboard_setup) {
        int fd = open(CONFIG_KEYBOARD, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
        printf("keyboard_path %s\n", keyboard_path);
        int written_bytes = write(fd, keyboard_path, strlen(keyboard_path));
        printf("written bytes %d\n", written_bytes);
        if (written_bytes == -1) {
            printf("Ошибка записи пути в файл");
        }
        close(fd);
        return EXIT_SUCCESS;
    }
    if (check_keyboard) {
        FILE *fp;
        char *keyboard_file = NULL;
        size_t len = 0;

        fp = fopen(CONFIG_KEYBOARD, "r");
        if (fp == NULL) {
            printf("Невозможно открыть файл конфигурации");
            exit(EXIT_FAILURE);
        };
        if ((getline(&keyboard_file, &len, fp)) == -1) {
            printf("Невозможно прочитать файл конфигурации");
            exit(EXIT_FAILURE);
        }
        printf("read string: %s\n", keyboard_file);

        int retval;

        /* create pipe for sending password received signal to helper */
        int fd_to_helper[2];
        if (pipe(fd_to_helper) != 0) {
            syslog(LOG_DEBUG, "could not make pipe");
            return PAM_AUTH_ERR;
        }

        /* create pipe for receiving ready message from helper */
        int fd_from_helper[2];
        if (pipe(fd_from_helper) != 0) {
            syslog(LOG_DEBUG, "could not make pipe");
            return PAM_AUTH_ERR;
        }

        pid_t pid;

        /* fork */
        pid = fork();
        if (pid == (pid_t) 0) {
            syslog(LOG_DEBUG, "fork: child");
            static char *envp[] = {NULL};
            const char *args[] = {NULL, NULL, NULL, NULL};
            /* This is the child process.
              Close other end first. */
            close(fd_to_helper[1]);

            if (dup2(fd_to_helper[0], STDIN_FILENO) != STDIN_FILENO) {
                syslog(LOG_ERR, "dup2 of %s failed: %m", "stdin");
                _exit(PAM_AUTHINFO_UNAVAIL);
            }

            close(fd_from_helper[0]);

            if (dup2(fd_from_helper[1], STDOUT_FILENO) != STDOUT_FILENO) {
                syslog(LOG_ERR, "dup2 of %s failed: %m", "stdout");
                _exit(PAM_AUTHINFO_UNAVAIL);
            }
            /* exec binary helper */
            args[0] = KEYSTROKE_HELPER;
            args[1] = keyboard_file;

            syslog(LOG_DEBUG, "run binary");
            execve(KEYSTROKE_HELPER, (char *const *) args, envp);

            /* should not get here: exit with error */
            syslog(LOG_DEBUG, "helper binary is not available");
            _exit(PAM_AUTHINFO_UNAVAIL);
        } else if (pid < (pid_t) 0) {
            /* The fork failed. */
            D(("fork failed"));
            close(fd_to_helper[0]);
            close(fd_to_helper[1]);
            close(fd_from_helper[0]);
            close(fd_from_helper[1]);
            retval = PAM_AUTH_ERR;
        } else {
            /* This is the parent process.
               Close other end first. */
            syslog(LOG_DEBUG, "Fork: parent");

            close(fd_to_helper[0]); // close read end
            close(fd_from_helper[1]); // close write end


            char message_from_helper[10];
            if (read(fd_from_helper[0], message_from_helper, sizeof(message_from_helper)) == -1) {
                syslog(LOG_DEBUG, "Cannot receive message from helper");
                retval = PAM_AUTH_ERR;
            } else {
                syslog(LOG_DEBUG, "message from helper: %s", message_from_helper);
                printf("message_from_helper: %s\n", message_from_helper);
            }
//        close(fd_from_helper[0]);
//            printf("Your keystroke dynamics will be checked while password input!\n");

            int rc = 0;
            char string [20];
            printf("Введите несколько сиволов: ");
            scanf("%19s", string);
//            char *password;
//            char *prompt = "password";
//            password = getpass(prompt);

            char *mess_to_h = "password_sent";
            if (write(fd_to_helper[1], mess_to_h, (strlen(mess_to_h)+1)) == -1) {
                syslog(LOG_DEBUG, "Cannot send finish to helper");
                retval = PAM_AUTH_ERR;
            }
//        printf("mess_to_h sent\n");
            printf("finish written\n");
            /* receive number of keys */
            int keys_number;
            read(fd_from_helper[0], &keys_number, sizeof(keys_number));
//        printf("keys number: %d\n", keys_number);
            struct input_event array_of_actions[100];
            read(fd_from_helper[0], array_of_actions, keys_number * sizeof(struct input_event));

            close(fd_to_helper[1]);

            for (int i=0; i<keys_number; i++) {
                printf("Event: time %ld.%06ld, %d (%d)\n", array_of_actions[i].time.tv_sec,
                       array_of_actions[i].time.tv_usec, array_of_actions[i].value, array_of_actions[i].code);
            }

            while ((rc = waitpid(pid, &retval, 0)) < 0 && errno == EINTR);
            if (rc < 0) {
                syslog(LOG_DEBUG, "unix_chkpwd waitpid returned ");
                retval = PAM_AUTH_ERR;
            } else if (!WIFEXITED(retval)) {
                syslog(LOG_DEBUG, "unix_chkpwd abnormal exit:");
                retval = PAM_AUTH_ERR;
            } else {
                retval = WEXITSTATUS(retval);
            }
            printf("retval %d\n", retval);
//            return retval;
        }

        free(keyboard_file);
        exit(EXIT_SUCCESS);
    }
    if (add_user) {
        if (mkdir("/etc/keystroke-pam",0777)&& errno != EEXIST) {
//        perror(argv[0]);
            printf("Ошибка создания директории keystroke-pam");
            exit(EXIT_FAILURE);
        }
        char user_file_path[100] = "/etc/keystroke-pam/";
        strcat(user_file_path, arg_username);
        printf("user_file_path %s\n", user_file_path);
        int fd;
        if (fd = open(user_file_path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR) < 0) {
            if (errno == EEXIST) {
                printf("Эталон уже существует, для обновления воспользуйтесь опцией -u\n");
            } else {
                printf("При создании файла с параметрами эталона возникла ошибка\n");
            }
        };
        FILE *fp;
        char *keyboard_file = NULL;
        size_t len = 0;

        fp = fopen(CONFIG_KEYBOARD, "r");
        if (fp == NULL) {
            printf("Невозможно открыть файл конфигурации");
            exit(EXIT_FAILURE);
        };
        if ((getline(&keyboard_file, &len, fp)) == -1) {
            printf("Невозможно прочитать файл конфигурации");
            exit(EXIT_FAILURE);
        }
        printf("read string: %s\n", keyboard_file);


        return EXIT_SUCCESS;
    }
    const char* user;
    user = argv[1];
    pam_handle_t* pamh = NULL;
    int retval;
    retval = pam_start("kbsetup", user, &conv, &pamh);
    printf("kbsetup\n");
//    PAM_DISALLOW_NULL_AUTHTOK
    if (retval != PAM_SUCCESS) {
        printf("pam_start error");
        return EXIT_FAILURE;
    }

    /* create pipe for sending password received signal to helper */
    int fd_to_helper[2];
    if (pipe(fd_to_helper) != 0) {
        syslog(LOG_DEBUG, "could not make pipe");
        return PAM_AUTH_ERR;
    }

    /* create pipe for receiving ready message from helper */
    int fd_from_helper[2];
    if (pipe(fd_from_helper) != 0) {
        syslog(LOG_DEBUG, "could not make pipe");
        return PAM_AUTH_ERR;
    }

    struct sigaction newsa, oldsa;

//    if (off(UNIX_NOREAP, ctrl))
    if (1) {
        /*
         * This code arranges that the demise of the child does not cause
         * the application to receive a signal it is not expecting - which
         * may kill the application or worse.
         *
         * The "noreap" module argument is provided so that the admin can
         * override this behavior.
         */
        memset(&newsa, '\0', sizeof(newsa));
        newsa.sa_handler = SIG_DFL;
        sigaction(SIGCHLD, &newsa, &oldsa);
    }

    pid_t pid;

    /* fork */
    pid = fork();
    if (pid == (pid_t) 0) {
        syslog(LOG_DEBUG, "fork: child");
        static char *envp[] = {NULL};
        const char *args[] = {NULL, NULL, NULL, NULL};
        /* This is the child process.
          Close other end first. */
        close(fd_to_helper[1]);

        if (dup2(fd_to_helper[0], STDIN_FILENO) != STDIN_FILENO) {
            syslog(LOG_ERR, "dup2 of %s failed: %m", "stdin");
            _exit(PAM_AUTHINFO_UNAVAIL);
        }

        close(fd_from_helper[0]);

        if (dup2(fd_from_helper[1], STDOUT_FILENO) != STDOUT_FILENO) {
            syslog(LOG_ERR, "dup2 of %s failed: %m", "stdout");
            _exit(PAM_AUTHINFO_UNAVAIL);
        }
        /* exec binary helper */
        args[0] = KEYSTROKE_HELPER;

        syslog(LOG_DEBUG, "run binary");
        execve(KEYSTROKE_HELPER, (char *const *) args, envp);

        /* should not get here: exit with error */
        syslog(LOG_DEBUG, "helper binary is not available");
        _exit(PAM_AUTHINFO_UNAVAIL);
    } else if (pid < (pid_t) 0) {
        /* The fork failed. */
        D(("fork failed"));
        close(fd_to_helper[0]);
        close(fd_to_helper[1]);
        close(fd_from_helper[0]);
        close(fd_from_helper[1]);
        retval = PAM_AUTH_ERR;
    } else {
        /* This is the parent process.
           Close other end first. */
        syslog(LOG_DEBUG, "Fork: parent");

        close(fd_to_helper[0]); // close read end
        close(fd_from_helper[1]); // close write end


        char message_from_helper[10];
        if (read(fd_from_helper[0], message_from_helper, sizeof(message_from_helper)) == -1) {
            syslog(LOG_DEBUG, "Cannot receive message from helper");
            retval = PAM_AUTH_ERR;
        } else {
            syslog(LOG_DEBUG, "message from helper: %s", message_from_helper);
            printf("message_from_helper: %s\n", message_from_helper);
        }
//        close(fd_from_helper[0]);
        printf("Your keystroke dynamics will be checked while password input!\n");

        int rc = 0;

        retval = pam_authenticate(pamh, 0);
        char *mess_to_h = "password_sent";
        if (write(fd_to_helper[1], mess_to_h, (strlen(mess_to_h)+1)) == -1) {
            syslog(LOG_DEBUG, "Cannot send finish to helper");
            retval = PAM_AUTH_ERR;
        }
//        printf("mess_to_h sent\n");
        syslog(LOG_DEBUG, "finish written\n");
        /* receive number of keys */
        int keys_number;
        read(fd_from_helper[0], &keys_number, sizeof(keys_number));
//        printf("keys number: %d\n", keys_number);
        struct input_event array_of_actions[100];
        read(fd_from_helper[0], array_of_actions, keys_number * sizeof(struct input_event));

        close(fd_to_helper[1]);

        for (int i=0; i<keys_number; i++) {
            printf("Event: time %ld.%06ld, %d (%d)\n", array_of_actions[i].time.tv_sec,
                   array_of_actions[i].time.tv_usec, array_of_actions[i].value, array_of_actions[i].code);
        }
        long int last_press_time_sec = 0;
        long int last_press_time_usec = 0;
        double time_features[100];
        int features_num = 0;
        for (int i = 0; i<keys_number; i++) {
//            printf("for i: %d \n", i);
            if (array_of_actions[i].value == 1) {
                bool not_found_up = true;
                int j = i + 1;
//                printf("code %d\n", array_of_actions[i].code);
                while(not_found_up) {
//                    printf("while\n");
//                    printf("j: %d", j);
//                    printf("code %d", array_of_actions[j].code);
                    if ((array_of_actions[i].code == array_of_actions[j].code) && (array_of_actions[j].value == 0)) {
                        /* hold time */
//                        printf("equal\n");
                        double hold = (array_of_actions[j].time.tv_sec - array_of_actions[i].time.tv_sec)*1000 +
                                (double)(array_of_actions[j].time.tv_usec - array_of_actions[i].time.tv_usec) / 1000;
                        time_features[features_num] = hold;
                        features_num++;
                        not_found_up = false;
                    }
                    j++;
                }
                if (last_press_time_sec > 0) {
                    /* flight */
                    double flight = (array_of_actions[i].time.tv_sec - last_press_time_sec)*1000 + (double)(array_of_actions[i].time.tv_usec - last_press_time_usec) / 1000;
                    time_features[features_num] = flight;
                    features_num++;
                }
                last_press_time_sec = array_of_actions[i].time.tv_sec;
                last_press_time_usec = array_of_actions[i].time.tv_usec;

            }
        }
        for (int i = 0; i<features_num; i++) {
            printf("%f ", time_features[i]);
        }

        while ((rc = waitpid(pid, &retval, 0)) < 0 && errno == EINTR);
        if (rc < 0) {
            syslog(LOG_DEBUG, "unix_chkpwd waitpid returned ");
            retval = PAM_AUTH_ERR;
        } else if (!WIFEXITED(retval)) {
            syslog(LOG_DEBUG, "unix_chkpwd abnormal exit:");
            retval = PAM_AUTH_ERR;
        } else {
            retval = WEXITSTATUS(retval);
        }
        printf("retval %d", retval);
        return retval;
    }



    if (retval != PAM_SUCCESS) {
        printf("pam_authenticate fail\n");
        return EXIT_FAILURE;
    }

    return 0;
}
