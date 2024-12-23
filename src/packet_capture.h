#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <pcap.h>

// Function declarations
void list_devices();
void start_capture(const char *device_name);

#endif // PACKET_CAPTURE_H