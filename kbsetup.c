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

#include "manhattan.h"
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

int check_keyboard_func(char *username, int interaction_num) {
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
    /* check if user is root */
    if (getuid() != 0) {
        printf("Для запуска kbsetup необходимы права суперпользователя\n");
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
    opterr = 0;
    /* getopt processing */
    while ((rez = getopt(argc,argv,"k:ca:u:d:l")) != -1){
        switch (rez) {
            /* keyboard setup */
            case 'k':
                keyboard_setup = 1;
                keyboard_path = optarg;
                break;
            /* check keyboard */
            case 'c':
                check_keyboard = 1;
                break;
            /* add user */
            case 'a':
                add_user = 1;
                arg_username = optarg;
                break;
            /* update user */
            case 'u':
                update_user = 1;
                arg_username = optarg;
                break;
            /* delete user */
            case 'd':
                delete_user = 1;
                arg_username = optarg;
                break;
            /* list users */
            case 'l':
                list_users = 1;
                break;
            /* other */
            case '?':
                argument_error = 1;
                break;
        };
    };
    /* options error check */
    if ((optind < argc) || argument_error ||
        ((keyboard_setup + check_keyboard + add_user + update_user + delete_user + list_users) != 1)) {
        printf("Используется лишь одна из опций:\n"
               " -k (keyboard setup) [путь файла]       : установка пути файла устройства клавиатуры\n"
               " -c (check keyboard)                    : проверка считывания клавиатурных событий\n"
               " -a (add user)       [имя пользователя] : добавление эталона пользователя\n"
               " -u (update user)    [имя пользователя] : обновление эталона пользователя\n"
               " -d (delete user)    [имя пользователя] : удаление эталона пользователя\n"
               " -l (list users)                        : кол-во эталонных вводов паролей у пользователей\n");
        return EXIT_FAILURE;
    }
    if (keyboard_setup) {
        int fd = open(CONFIG_KEYBOARD, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
        printf("keyboard_path %s\n", keyboard_path);
        int written_bytes = write(fd, keyboard_path, strlen(keyboard_path));
        printf("written bytes %d\n", written_bytes);
        if (written_bytes == -1) {
            printf("Ошибка записи пути в файл\n");
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
        struct features_collection returned_collection;
        keyboard_events_engine(keyboard_file, check_keyboard_func, NULL, 1, &returned_collection);
        free(keyboard_file);
        for (int i = 0; i < returned_collection.pressed_keycodes_num; i++) {
            printf("%s ", keys[returned_collection.pressed_keycodes[i]]);
        }
        printf("\n");
        free_collection(&returned_collection);
        exit(EXIT_SUCCESS);
    }
    if (add_user) {
        if (mkdir("/etc/keystroke-pam", 0777) && errno != EEXIST) {
            printf("Ошибка создания директории keystroke-pam");
            exit(EXIT_FAILURE);
        }
        char user_file_path[100] = "/etc/keystroke-pam/";
        strcat(user_file_path, arg_username);
        printf("user_file_path %s\n", user_file_path);

        if (access(user_file_path, F_OK) == 0) {
            printf("Эталон уже существует, для обновления воспользуйтесь опцией -u\n");
            exit(EXIT_FAILURE);
        }
        FILE *fp;
        char *keyboard_file;
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
        fclose(fp);
        printf("read string: %s\n", keyboard_file);

        bool no_password = true;
        struct features_collection returned_collection_pam;
        while (no_password) {
            keyboard_events_engine("/dev/input/event3", pam_auth, arg_username, 1, &returned_collection_pam);
            if (returned_collection_pam.success_interaction) {
                no_password = false;
            }
        }
        double *passwords_features = malloc(PASSWORD_NUMBER *
                                            returned_collection_pam.time_features_num * sizeof(double));
        for (int i = 0; i < returned_collection_pam.time_features_num; i++) {
            passwords_features[i] = returned_collection_pam.time_features[i];
        }
        int input_number = 2;
        int features_num = returned_collection_pam.time_features_num;
        struct features_collection returned_collection_retry;
        while (input_number <= PASSWORD_NUMBER) {
            keyboard_events_engine("/dev/input/event3", password_retry,
                                   arg_username, input_number, &returned_collection_retry);
            bool correct_sequence = true;
            if (returned_collection_retry.pressed_keycodes_num != returned_collection_pam.pressed_keycodes_num) {
                correct_sequence = false;
            } else {
                for (int i = 0; i < returned_collection_pam.pressed_keycodes_num; i++) {
                    if (returned_collection_pam.pressed_keycodes[i] !=
                        returned_collection_retry.pressed_keycodes[i]) {
                        correct_sequence = false;
                        break;
                    }
                }
            }
            if (!correct_sequence) {
                printf("Несоответствие последовательности клавиш при наборе пароля\n");
                continue;
            } else {
                for (int i = 0; i < features_num; i++) {
                    passwords_features[(input_number - 1) * features_num + i] =
                            returned_collection_retry.time_features[i];
                }
                input_number++;
            }
            free_collection(&returned_collection_retry);
        }
        free_collection(&returned_collection_pam);
        int fd = open(user_file_path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
        if (fd < 0) {
            if (errno == EEXIST) {
                printf("Эталон уже существует, для обновления воспользуйтесь опцией -u\n");
            } else {
                printf("При создании файла с параметрами эталона возникла ошибка\n");
            }
            exit(EXIT_FAILURE);
        };
        double *validation_scores = malloc(PASSWORD_NUMBER * sizeof(double));
        double *validation_features = malloc(features_num * (PASSWORD_NUMBER - 1) * sizeof(double));
        for (int score_number = 0; score_number < PASSWORD_NUMBER; score_number++) {
            int validation_vec_num = 0;
            for (int i = 0; i < PASSWORD_NUMBER; i++) {
                if (i == score_number) {
                    printf("validation cont i = %d\n", i);
                    continue;
                }
                for (int j = 0; j < features_num; j++) {
                    validation_features[validation_vec_num * features_num + j] = passwords_features[i * features_num + j];
                }
                printf("increment validation_vec_num: %d at i = %d\n", validation_vec_num++, i);
            }
            printf("validation_features created\n");
            double norm_score = -1;
            double *target = malloc(features_num * sizeof(double));
            for (int i = 0; i < features_num; i++) {
                target[i] = passwords_features[score_number * features_num + i];
            }
            printf("target created\n");
            validation_scores[score_number] = score_keystrokes(validation_features, PASSWORD_NUMBER - 1,
                               features_num, target, &norm_score);
            printf("validation_scores[score_number] assigned\n");
            free(target);
        }
        free(validation_features);
        printf("validation_scores: ");
        int bigger_thresh = 0;
        for (int i = 0; i < PASSWORD_NUMBER; i++) {
            printf("%5.2f ", validation_scores[i]);
            if (validation_scores[i] < -1.2) {
                bigger_thresh+= 1;
            }
        }
        free(validation_scores);
        double *passwords_features_copy = malloc(features_num * PASSWORD_NUMBER * sizeof(double));
        for (int i = 0; i < PASSWORD_NUMBER; i++) {
            for (int j = 0; j < features_num; j++) {
                passwords_features_copy[i * features_num + j] = passwords_features[i * features_num + j];
            }
        }
        double *target_vector = calloc(features_num, sizeof(double));
        double norm_score = -1;
        score_keystrokes(passwords_features, PASSWORD_NUMBER, features_num, target_vector, &norm_score);
        free(passwords_features);
        free(target_vector);
        dprintf(fd, "%f\n%d %d\n", norm_score, PASSWORD_NUMBER, features_num);
        for (int i = 0; i < PASSWORD_NUMBER; i++) {
            for (int j = 0; j < features_num; j++) {
                dprintf(fd, "%.3f ", passwords_features_copy[i * features_num + j]);
            }
            dprintf(fd, "\n");
        }
        free(passwords_features_copy);
        close(fd);
        printf("Кол-во вводов, не совпадающих с эталоном на валидации: %d\n", bigger_thresh);
        return EXIT_SUCCESS;
    }
    if (update_user) {

    }
    if (delete_user) {
        char user_file_path[100] = "/etc/keystroke-pam/";
        strcat(user_file_path, arg_username);
        printf("user_file_path %s\n", user_file_path);
        if (remove(user_file_path) < 0) {
            if (errno == ENOENT) {
                printf("Эталона почерка пользователя %s не существует\n", arg_username);
                return EXIT_FAILURE;
            } else {
                printf("При удалении эталона почерка пользователя %s возникла ошибка\n", arg_username);
            }
        }
        printf("Эталон почерка пользователя %s удален\n", arg_username);
        return EXIT_SUCCESS;
    }
    if (list_users) {

    }

    return 0;
}
