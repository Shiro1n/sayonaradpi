#include "packet_capture.h"
#include "packet_mod.h"
#include <stdio.h>

// List all available devices
void list_devices() {
    pcap_if_t *alldevs, *device_ptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }

    int i = 1;
    for (device_ptr = alldevs; device_ptr != NULL; device_ptr = device_ptr->next, i++) {
        printf("[%d] Name: %s\n", i, device_ptr->name);
        printf("    Description: %s\n", device_ptr->description ? device_ptr->description : "(No description)");
    }
    pcap_freealldevs(alldevs);
}

// Start packet capture on the specified device
void start_capture(const char *device_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device_name, 1518, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device_name, errbuf);
        return;
    }
    printf("Listening on device: %s\n", device_name);

    // Infinite loop for real-time packet capture
    pcap_loop(handle, -1, packet_handler, NULL);

    // Cleanup
    pcap_close(handle);
}