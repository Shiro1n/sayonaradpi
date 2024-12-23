#include "utils.h"
#include <stdio.h>

void print_hex(const u_char *data, int length) {
    printf("Payload (first %d bytes): ", length);
    for (int i = 0; i < length; i++) {
        printf("%02x ", data[i]);
    }
    printf("\n");
}