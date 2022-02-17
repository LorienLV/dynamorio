#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define LINUX
#define X86_64

#include <dr_api.h>

int main(int argc, char const *argv[]) {
    int which = atoi(argv[1]);

    dr_app_setup();
    assert(!dr_app_running_under_dynamorio());

    dr_app_start();
    assert(dr_app_running_under_dynamorio());

    switch(which) {
        case 0: {
            printf("SCALAR INTEGER\n");
            int size = 1000000;
            int a = 2;
            int b = 2;
            for (int i = 0; i < size; ++i) {
                a *= a + b;
            }
            printf("%d\n", a);
            break;
        }
        case 1: {
            printf("SIMD INTEGER\n");
            int size = 1000000;
            int *a = aligned_alloc(64, size * sizeof(*a));
            int *b = aligned_alloc(64, size * sizeof(*b));
            int *c = aligned_alloc(64, size * sizeof(*c));
            for (int i = 0; i < size; ++i) {
                c[i] = b[i] + a[i];
            }
            printf("%d\n", c[2]);
            break;
        }
        case 2: {
            printf("SCALAR FLOAT\n");
            int size = 1000000;
            float a = 2;
            float b = 2;
            for (int i = 0; i < size; ++i) {
                a *= a + b;
            }
            printf("%f\n", a);
            break;
        }
        case 3: {
            printf("SIMD FLOAT\n");
            int size = 1000000;
            float *a = aligned_alloc(64, size * sizeof(*a));
            float *b = aligned_alloc(64, size * sizeof(*b));
            float *c = aligned_alloc(64, size * sizeof(*c));
            for (int i = 0; i < size; ++i) {
                c[i] = b[i] + a[i];
            }
            printf("%f\n", c[2]);
            break;
        }
    }

    dr_app_stop_and_cleanup();
    assert(!dr_app_running_under_dynamorio());

    return 0;
}
