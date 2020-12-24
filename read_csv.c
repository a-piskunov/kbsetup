//
// Created by alexey on 23.12.2020.
//

#include <stdio.h>
#include <stdlib.h>

int main() {
    FILE *f = fopen("/etc/keystroke-pam/alexey","r");
    if ( !f ) {
        fprintf(stderr, "Error: Unable to open input file.\n");
        exit(EXIT_FAILURE);
    }
    int rows, cols;
    double norm_score;
    if ( fscanf(f,"%lf%d%d", &norm_score, &rows, &cols) != 3 ) {
        fprintf(stderr, "Error: wrong file format.\n");
        exit(EXIT_FAILURE);
    }
    printf("norm: %lf\n", norm_score);
    printf("rows, cols %d, %d\n", rows, cols);
    double *passwords_features;
    passwords_features = malloc(rows * cols * sizeof(double));
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            fscanf(f,"%lf", &passwords_features[i * cols + j]);
        }
    }
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            printf("%7.2f ", passwords_features[i * cols + j]);
        }
        printf("\n");
    }
    free(passwords_features);
}