#include "manhattan.h"
#include <stdlib.h>
#include <math.h>
#include <stdio.h>

void compute_std_mean(double* fit_vectors, int fit_vectors_num, int features_number,
                      double *flight_mean, double *flight_std, double *hold_mean, double *hold_std)
{
    int i, j;
    double *sum;
    sum = calloc(features_number, sizeof(*sum));
    for (i=0; i<fit_vectors_num; i++)
    {
        for (j=0; j<features_number; j++)
        {
            sum[j] += fit_vectors[i * fit_vectors_num + j];
        }
    }
    *hold_mean = 0;
    *flight_mean = 0;
    for (i=0; i<features_number; i++)
    {
        if (i % 2 == 0) {
            *hold_mean += fit_vectors_num;
        } else {
            *flight_mean += fit_vectors_num;
        }
    }

    int hold_number = ((features_number + 1) / 2) * fit_vectors_num;
    int flight_number = ((features_number - 1) / 2) * fit_vectors_num;
    *hold_mean /= hold_number;
    *flight_mean /= flight_number;

    *hold_std = 0;
    *flight_std = 0;

    for (i=0; i<fit_vectors_num; i++)
    {
        for (j=0; j<features_number; j++)
        {
            if (j % 2 == 0) {
                *hold_std += pow(fit_vectors[i * fit_vectors_num + j] - *hold_mean, 2);
            } else {
                *flight_std += pow(fit_vectors[i * fit_vectors_num + j] - *flight_mean, 2);
            }
        }
    }
    *hold_std = sqrt(*hold_std / hold_number);
    *flight_std = sqrt(*flight_std / flight_number);
}

void normalize_line(double *line, int features_number, double *flight_mean,
                    double *flight_std, double *hold_mean, double *hold_std) {
    double left_border_hold = *hold_mean - *hold_std;
    double right_border_hold = *hold_mean + *hold_std;
    double left_border_flight = *flight_mean - *flight_std;
    double right_border_flight = *flight_mean + *flight_std;
    for (int i=0; i<features_number; i++){
        if (i % 2 == 0) {
            // hold features
            line[i] = (line[i] - left_border_hold) / (right_border_hold - left_border_hold);
        } else {
            // flight features
            line[i] = (line[i] - left_border_flight) / (right_border_flight - left_border_flight);
        }
        if (line[i] > 1) {
            line[i] = 1;
        } else if (line[i] < 0) {
            line[i] = 0;
        }
    }
}

void normalize_vectors(double *fit_vectors, int fit_vectors_num, int features_number,
                       double *flight_mean, double *flight_std, double *hold_mean, double *hold_std)
{
    for (int i=0; i<fit_vectors_num; i++)
    {
        normalize_line(fit_vectors + i * features_number, features_number, flight_mean,
                        flight_std, hold_mean, hold_std);
    }
}

void fit_classifier(double *fit_vectors, int fit_vectors_num, int features_number, double *mean_vector) {
    for (int i=0; i<fit_vectors_num; i++) {
        for (int j=0; j<features_number; j++) {
            mean_vector[j] += fit_vectors[i * fit_vectors_num + j];
        }
    }
    for (int i=0; i<features_number; i++) {
        mean_vector[i] /= fit_vectors_num;
    }
}

double score_vector(int features_number, double *mean_vector, double *score_vector) {
    double score = 0;
    for (int i = 0; i<features_number; i++) {
        score += fabs(mean_vector[i] - score_vector[i]);
        printf("%.2f\n", fabs(mean_vector[i] - score_vector[i]));
    }
    return score;
}

void print_array(double *array, int rows, int cols) {
    for (int i=0; i<rows; i++) {
        for (int j = 0; j<cols; j++) {
            printf("%5.2f ", array[i*cols+j]);
        }
        printf("\n");
    }
}

double score_keystrokes(double *fit_vectors, int fit_vectors_num, int features_number, double *target_vector)
{
    double flight_mean, flight_std, hold_mean, hold_std;
    compute_std_mean(fit_vectors, fit_vectors_num, features_number, &flight_mean, &flight_std, &hold_mean, &hold_std);
    printf("flight_mean: %.2f\nflight_std: %.2f\nhold_mean: %.2f\nhold_std: %.2f\n",
           flight_mean, flight_std, hold_mean, hold_std);
    normalize_vectors(fit_vectors, fit_vectors_num, features_number, &flight_mean, &flight_std, &hold_mean, &hold_std);
    print_array(fit_vectors, fit_vectors_num, features_number);
    double *mean_vector;
    mean_vector = calloc(features_number, sizeof(*mean_vector));
    fit_classifier(fit_vectors, fit_vectors_num, features_number, mean_vector);
    printf("mean_vector :\n");
    for (int i = 0; i<features_number; i++) {
        printf("%5.2f ", mean_vector[i]);
    }
    printf("\n");
    normalize_line(target_vector, features_number, &flight_mean, &flight_std, &hold_mean, &hold_std);

    printf("target_norm_vector :\n");
    for (int i = 0; i<features_number; i++) {
        printf("%5.2f ", target_vector[i]);
    }
    printf("\n");

    return score_vector(features_number, mean_vector, target_vector);
}