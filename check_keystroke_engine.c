// This is a personal academic project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++, C#, and Java: http://www.viva64.com

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <syslog.h>
#include <sys/wait.h>
#include <errno.h>
#include <linux/input.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <poll.h>

#include "key_input.h"

#define KEYSTROKE_HELPER "/home/alexey/Documents/kbsetup/keystroke_helper"
#define CONFIG_KEYBOARD "/etc/keyboard-config"
#define PASSWORD_NUMBER 20
#define PROGRAM_NAME "kbsetup"

/* conversation function for PAM module */
const struct pam_conv conv = {
        misc_conv,
        NULL
};

int pam_auth(char *username, int interaction_num) {
    pam_handle_t* pamh = NULL;
    int retval = pam_start(PROGRAM_NAME, username, &conv, &pamh);
    if (retval != PAM_SUCCESS) {
        printf("pam_start error\n");
        return 0;
    }
    retval = pam_authenticate(pamh, 0);
    if (retval != PAM_SUCCESS) {
        printf("Некорректный пароль\n");
        return 0;
    } else {
        return 1;
    }
}

int check_keyboard(char *username, int interaction_num) {
    int rc = 0;
    char string [20];
    printf("Введите несколько сиволов: ");
    if(scanf("%19s", string) > 0) {
        return 1;
    } else {
        return 0;
    }
}

int password_retry(char *username, int interaction_num) {
    char *password;
    char prompt[15];
    sprintf(prompt, "password #%d:", interaction_num);
    password = getpass(prompt);
    // set by zeros
    return 1;
}

//char *const evval[3] = {
//        "RELEASED",
//        "PRESSED ",
//        "REPEATED"
//};

struct features_collection {
    int success_interaction;
    int time_features_num;
    double *time_features;
    int pressed_keycodes_num;
    int *pressed_keycodes;
};

void keyboard_events_engine(char *keyboard_file, int (*interaction_func) (char *, int),
                            char *username, int interaction_num, struct features_collection *collected_features) {
    /* create pipe for sending password received signal to helper */
    int fd_to_helper[2];
    if (pipe(fd_to_helper) != 0) {
        printf("could not make pipe\n");
        _exit(EXIT_FAILURE);
    }
    /* create pipe for receiving ready message from helper */
    int fd_from_helper[2];
    if (pipe(fd_from_helper) != 0) {
        printf("could not make pipe\n");
        _exit(EXIT_FAILURE);
    }
    /* fork */
    pid_t pid = fork();
    if (pid < (pid_t) 0) {
        /* The fork failed. */
        printf("fork failed\n");
        close(fd_to_helper[0]);
        close(fd_to_helper[1]);
        close(fd_from_helper[0]);
        close(fd_from_helper[1]);
        _exit(EXIT_FAILURE);
    } else if (pid == (pid_t) 0) {
        printf("fork: child\n");
        close(fd_to_helper[1]);
        close(fd_from_helper[0]);
        char pass[PAM_MAX_RESP_SIZE + 1];
        char *option;
        int npass, nullok;
        int blankpass = 0;
        int retval = PAM_AUTH_ERR;
        char *user;
        char *passwords[] = { pass };
        struct input_event ev[300];
        int fd;
        fd = open(keyboard_file, O_RDONLY);
        /* report to parent */
        int helper_message;
        if (fd == -1) {
            helper_message = 1;
            write(fd_from_helper[1], &helper_message, sizeof(helper_message));
            printf("cannot open keyboard file\n");
            _exit(EXIT_FAILURE);
        } else {
            helper_message = 0;
            if (write(fd_from_helper[1], &helper_message, sizeof(helper_message)) == -1) {
                printf("cannot send message from child\n");
                _exit(EXIT_FAILURE);
            }
        }
        struct pollfd stdin_poll = { .fd = fd_to_helper[0], .events = POLLIN | POLLRDBAND | POLLRDNORM | POLLPRI };
        int ev_offset = 0;
        bool entering_password = true;
        while (entering_password) {
            /* check password receiving from parent */
            if (poll(&stdin_poll, 1, 0) == 1) {
                int to_helper_message;
                if (read(fd_to_helper[0], &to_helper_message, sizeof(to_helper_message)) == -1) {
                    printf("cannot read message from parent\n");
                    _exit(EXIT_FAILURE);
                }
                entering_password = false;
            }
            /* read current available events */
            struct timeval timeout;
            fd_set set;
            FD_ZERO(&set);
            FD_SET(fd,&set);
            timeout.tv_sec = 0;
            timeout.tv_usec = 150000;
            int rv = select(fd + 1, &set, NULL, NULL, &timeout);
            if (rv == -1)
                printf("helper: select error\n"); /* an error accured */
            else if (rv > 0) {
                /* there was data to read */
                int n = read(fd, ev + ev_offset, sizeof(ev));
                if (n == -1) {
                    printf("-1 while reading events\n");
                    _exit(EXIT_FAILURE);
                } else {
                    ev_offset += n / sizeof(struct input_event);
                }
            }
        }
        struct input_event array_of_actions[100];
        int num_actions = 0;
        int i = 1;
        /* check enter */
        while (ev[i].code == KEY_ENTER) {
            i++;
        }
        for (; i < ev_offset; i++) {
            if (ev[i].type == EV_KEY && ev[i].value >= 0 && ev[i].value <= 1) {
                if (ev[i].code != KEY_ENTER) {
                    array_of_actions[num_actions] = ev[i];
                    num_actions += 1;
                }
            }
        }
        if (write(fd_from_helper[1], &num_actions, sizeof(num_actions)) == -1) {
            printf("helper: cannot send keys number from helper\n");
            _exit(EXIT_FAILURE);
        }
        if (write(fd_from_helper[1], array_of_actions, num_actions * sizeof(struct input_event)) == -1) {
            printf("helper: cannot send keys number from helper\n");
            _exit(EXIT_FAILURE);
        }
        close(fd);
        printf("child return\n");
        _exit(EXIT_SUCCESS);
    } else if (pid > 0) {
        /* This is the parent process. */
        printf("parent\n");
        close(fd_to_helper[0]); // close read end
        close(fd_from_helper[1]); // close write end
        int message_from_helper;
        if (read(fd_from_helper[0], &message_from_helper, sizeof(message_from_helper)) == -1) {
            printf("Cannot receive message from helper\n");
            _exit(EXIT_FAILURE);
        } else {
            printf("message_from_helper: %d\n", message_from_helper);
        }
        /* pam: correct or not */
        collected_features->success_interaction = interaction_func(username, interaction_num);
        /* pam */
        int mess_to_h = 0;
        if (write(fd_to_helper[1], &mess_to_h, sizeof(mess_to_h)) == -1) {
            printf("Cannot send finish to helper\n");
            _exit(EXIT_FAILURE);
        }
        close(fd_to_helper[1]);
        /* receive number of keys */
        double *time_features;
        int *correct_keycodes;
        int features_num = 0;
        int keycodes_num = 0;
        int correct_keys_number;
        read(fd_from_helper[0], &correct_keys_number, sizeof(correct_keys_number));
        printf("keys number: %d\n", correct_keys_number);
        struct input_event array_of_actions[300];
        read(fd_from_helper[0], array_of_actions, correct_keys_number * sizeof(struct input_event));
        close(fd_from_helper[0]);
        for (int i = 0; i < correct_keys_number; i++) {
            printf("Event: time %ld.%06ld, %d (%d)\n", array_of_actions[i].time.tv_sec,
                   array_of_actions[i].time.tv_usec, array_of_actions[i].value, array_of_actions[i].code);
        }
        long int last_press_time_sec = 0;
        long int last_press_time_usec = 0;
        time_features = malloc(correct_keys_number * sizeof(*time_features));
        correct_keycodes = malloc(correct_keys_number * sizeof(*correct_keycodes));
        for (int i = 0; i < correct_keys_number; i++) {
            printf("i: %d\n", i);
            if (array_of_actions[i].value == 1) {
                correct_keycodes[keycodes_num] = array_of_actions[i].code;
                keycodes_num++;
                if (last_press_time_sec > 0) {
                    /* flight */
                    double flight = (array_of_actions[i].time.tv_sec - last_press_time_sec) * 1000 +
                                    (double) (array_of_actions[i].time.tv_usec - last_press_time_usec) / 1000;
                    if ((correct_keys_number - 1) < features_num) {
                        printf("При выделении параметров произошла ошибка\n");
                        _exit(EXIT_FAILURE);
                    }
                    time_features[features_num] = flight;
                    features_num++;
                    printf("flight %f", flight);
                }
                bool not_found_up = true;
                int j = i + 1;
                printf("code value=1 %d\n", array_of_actions[i].code);
                while (not_found_up && (j < correct_keys_number)) {
                    printf("j %d\n", j);
                    if ((array_of_actions[i].code == array_of_actions[j].code) &&
                        (array_of_actions[j].value == 0)) {
                        /* hold time */
                        double hold =
                                (array_of_actions[j].time.tv_sec - array_of_actions[i].time.tv_sec) * 1000 +
                                (double) (array_of_actions[j].time.tv_usec - array_of_actions[i].time.tv_usec) /
                                1000;
                        if ((correct_keys_number - 1) < features_num) {
                            printf("При выделении параметров произошла ошибка\n");
                            _exit(EXIT_FAILURE);
                        }
                        time_features[features_num] = hold;
                        features_num++;
                        not_found_up = false;
                        printf("hold %f\n", hold);
                    }
                    j++;
                }
                printf("last_press_time_sec: %ld last_press_time_usec: %ld\n", last_press_time_sec, last_press_time_usec);
                last_press_time_sec = array_of_actions[i].time.tv_sec;
                last_press_time_usec = array_of_actions[i].time.tv_usec;
            }
        }
        printf("assigned: features_num %d, pressed_keycodes_num: %d\n", features_num, keycodes_num);
        collected_features->time_features_num = features_num;
        collected_features->time_features = time_features;
        collected_features->pressed_keycodes_num = keycodes_num;
        collected_features->pressed_keycodes = correct_keycodes;
        int rc;
        int retval;
        while ((rc = waitpid(pid, &retval, 0)) < 0 && errno == EINTR);
        if (rc < 0) {
            printf("rc < 0\n");
            _exit(EXIT_FAILURE);
        } else if (!WIFEXITED(retval)) {
            printf("helper abnormal exit: %d\n", retval);
            _exit(EXIT_FAILURE);
        } else {
            retval = WEXITSTATUS(retval);
            printf("retval %d\n", retval);
        }
    }
    return;
}

void free_collection(struct features_collection *collected_features) {
    free(collected_features->time_features);
    free(collected_features->pressed_keycodes);
}

int main(int argc, char *argv[]) {
    struct features_collection returned_collection;
    keyboard_events_engine("/dev/input/event3", pam_auth, "alexey", 1, &returned_collection);
    printf("success_interaction: %d\n", returned_collection.success_interaction);
    printf("time_features_num: %d\n", returned_collection.time_features_num);
    printf("pressed_keycodes_num: %d\n", returned_collection.pressed_keycodes_num);
    for (int i = 0; i < returned_collection.time_features_num; i++) {
        printf("%lf ", returned_collection.time_features[i]);
    }
    printf("\n");
    for (int i = 0; i < returned_collection.pressed_keycodes_num; i++) {
        printf("%d ", returned_collection.pressed_keycodes[i]);
    }
    free_collection(&returned_collection);
    struct features_collection returned_collection1;
    keyboard_events_engine("/dev/input/event3", password_retry, "alexey", 1, &returned_collection1);
    free_collection(&returned_collection1);
    struct features_collection returned_collection2;
    keyboard_events_engine("/dev/input/event3", check_keyboard, "alexey", 1, &returned_collection2);
    free_collection(&returned_collection2);
}
