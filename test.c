
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

#define KEYSTROKE_HELPER "/home/alexey/Documents/kbsetup/keystroke_helper"

int main() {
    for (int i =0; i<20;i++) {

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
            char *string;
            scanf("%s", string);
            char *password;
            char *prompt = "password";
            password = getpass(prompt);
            printf("%s", password);

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
//            return retval;
        }

    }
}