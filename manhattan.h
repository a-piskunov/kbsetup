#ifndef MANHATTAN_H
#define MANHATTAN_H

double score_keystrokes(double *fit_vectors, int fit_vectors_num, int features_number,
                        double *target_vector, double *norm_score);
double score_vector(int features_number, double *mean_vector, double *score_vector, double norm_score);
void fit_classifier(double *fit_vectors, int fit_vectors_num,
                    int features_number, double *mean_vector, double *norm_score);
void normalize_vectors(double *fit_vectors, int fit_vectors_num, int features_number,
                       double *flight_mean, double *flight_std, double *hold_mean, double *hold_std);
void normalize_line(double *line, int features_number, double *flight_mean,
                    double *flight_std, double *hold_mean, double *hold_std);
void compute_std_mean(double* fit_vectors, int fit_vectors_num, int features_number,
                      double *flight_mean, double *flight_std, double *hold_mean, double *hold_std);


void print_array(double *array, int rows, int cols);

#endif /* MANHATTAN_H */