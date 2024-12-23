#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include "packet_capture.h"

// Function to list all available network devices
void list_all_devices() {
    pcap_if_t *alldevs, *device_ptr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }

    printf("Available devices:\n");
    for (device_ptr = alldevs; device_ptr != NULL; device_ptr = device_ptr->next) {
        printf("Device: %s\n", device_ptr->name);
        if (device_ptr->description) {
            printf("Description: %s\n", device_ptr->description);
        } else {
            printf("Description: (No description)\n");
        }
    }
    pcap_freealldevs(alldevs);
}

// Function to select the active Wi-Fi or Ethernet adapter
char* select_active_device() {
    pcap_if_t *alldevs, *device_ptr;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device_name = NULL;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return NULL;
    }

    for (device_ptr = alldevs; device_ptr != NULL; device_ptr = device_ptr->next) {
        // Prioritize Wi-Fi adapters
        if (device_ptr->description && strstr(device_ptr->description, "Wi-Fi")) {
            device_name = device_ptr->name;
            printf("Using Wi-Fi device: %s (%s)\n", device_name, device_ptr->description);
            break;
        }
    }

    // If no Wi-Fi adapter is found, fallback to any other device
    if (device_name == NULL) {
        fprintf(stderr, "No Wi-Fi adapter found. Falling back to another device.\n");
        for (device_ptr = alldevs; device_ptr != NULL; device_ptr = device_ptr->next) {
            if (device_ptr->description) {
                device_name = device_ptr->name;
                printf("Using fallback device: %s (%s)\n", device_name, device_ptr->description);
                break;
            }
        }
    }

    if (device_name == NULL) {
        fprintf(stderr, "No suitable device found.\n");
    }

    pcap_freealldevs(alldevs);
    return device_name;
}

int main() {
    char *device_name;

    printf("Listing all available devices...\n");
    list_all_devices();

    printf("\nSelecting an active network device...\n");
    device_name = select_active_device();

    if (device_name == NULL) {
        fprintf(stderr, "Failed to select a network device.\n");
        return 1;
    }

    // Start capturing packets
    start_capture(device_name);

    return 0;
}