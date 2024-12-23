#ifndef UTILS_H
#define UTILS_H

#include <pcap.h> // Ensure pcap.h is included for u_char definition

void print_hex(const u_char *data, int length);

#endif // UTILS_H