#ifdef _WIN32
#include <winsock2.h> // For Windows socket functions
#include <windows.h>
#include <pcap.h>
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "ws2_32.lib") // Link Winsock library

// Manually define TCP header structure
struct tcphdr {
    unsigned short source;  // Source port
    unsigned short dest;    // Destination port
    unsigned int seq;       // Sequence number
    unsigned int ack_seq;   // Acknowledgement number
    unsigned short res1_doff_flags;
    unsigned short window;  // Window size
    unsigned short check;   // Checksum
    unsigned short urg_ptr; // Urgent pointer
};

// Manually define UDP header structure
struct udphdr {
    unsigned short source; // Source port
    unsigned short dest;   // Destination port
    unsigned short len;    // Length
    unsigned short check;  // Checksum
};

#else
#include <pcap.h>
#include <netinet/ip.h>  // For IP header (Linux)
#include <netinet/tcp.h> // For TCP header (Linux)
#include <netinet/udp.h> // For UDP header (Linux)
#include <arpa/inet.h>   // For inet_ntoa (Linux)
#endif

#include <stdio.h>
#include <stdlib.h>

#define SNAP_LEN 1518  // Max packet length to capture
#define PROMISCUOUS_MODE 1

// Windows-compatible IP header
typedef struct ip_header {
    unsigned char  ip_header_length : 4;
    unsigned char  ip_version : 4;
    unsigned char  ip_tos;
    unsigned short ip_total_length;
    unsigned short ip_id;
    unsigned short ip_offset;
    unsigned char  ip_ttl;
    unsigned char  ip_protocol;
    unsigned short ip_checksum;
    struct in_addr ip_src; // Source IP
    struct in_addr ip_dst; // Destination IP
} IP_HEADER;

// Callback function to process captured packets
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Captured packet: %u bytes\n", header->len);

    // Skip Ethernet header (14 bytes)
    IP_HEADER *ip_header = (IP_HEADER *)(packet + 14);

    printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));

    // Determine protocol
    switch (ip_header->ip_protocol) {
        case IPPROTO_TCP: {
            printf("Protocol: TCP\n");
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_header_length * 4);
            printf("Source Port: %u\n", ntohs(tcp_header->source));
            printf("Destination Port: %u\n", ntohs(tcp_header->dest));
            break;
        }
        case IPPROTO_UDP: {
            printf("Protocol: UDP\n");
            struct udphdr *udp_header = (struct udphdr *)(packet + 14 + ip_header->ip_header_length * 4);
            printf("Source Port: %u\n", ntohs(udp_header->source));
            printf("Destination Port: %u\n", ntohs(udp_header->dest));
            break;
        }
        case IPPROTO_ICMP:
            printf("Protocol: ICMP\n");
            break;
        default:
            printf("Protocol: Other (%d)\n", ip_header->ip_protocol);
    }

    // Print the first 10 bytes of the payload
    const u_char *payload = packet + 14 + ip_header->ip_header_length * 4;
    printf("Payload (first 10 bytes): ");
    for (int i = 0; i < 10 && i < header->len; i++) {
        printf("%02x ", payload[i]);
    }
    printf("\n\n");
}

int main() {
    pcap_if_t *alldevs, *device_ptr; // List of devices
    char errbuf[PCAP_ERRBUF_SIZE];   // Error buffer
    pcap_t *handle;                  // Packet capture handle
    char *device_name = NULL;

    // Initialize Winsock (required on Windows)
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup failed.\n");
        return 1;
    }
#endif

    // Step 1: Find all devices
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }

    // Step 2: Print all devices
    printf("Available devices:\n");
    int i = 1;
    for (device_ptr = alldevs; device_ptr != NULL; device_ptr = device_ptr->next, i++) {
        printf("[%d] Name: %s\n", i, device_ptr->name);
        if (device_ptr->description) {
            printf("    Description: %s\n", device_ptr->description);
        } else {
            printf("    Description: (No description available)\n");
        }
    }

    // Step 3: User selects a device
    int choice = 0;
    printf("\nSelect a device to capture packets (Enter the number): ");
    if (scanf("%d", &choice) != 1 || choice < 1) {
        fprintf(stderr, "Invalid selection.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Traverse to the selected device
    device_ptr = alldevs;
    for (i = 1; i < choice && device_ptr != NULL; i++) {
        device_ptr = device_ptr->next;
    }

    if (device_ptr == NULL) {
        fprintf(stderr, "Invalid selection. Device not found.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    device_name = device_ptr->name;
    printf("\nCapturing on device: %s\n", device_name);
    if (device_ptr->description) {
        printf("Description: %s\n", device_ptr->description);
    }

    // Step 4: Open the device for packet capture
    handle = pcap_open_live(device_name, SNAP_LEN, PROMISCUOUS_MODE, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device_name, errbuf);
        pcap_freealldevs(alldevs);
        return 2;
    }

    // Step 5: Apply a filter (e.g., TCP port 80)
    struct bpf_program filter;
    char filter_exp[] = "tcp port 80"; // Example: Capture only HTTP traffic
    if (pcap_compile(handle, &filter, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 2;
    }

    printf("Listening for packets...\n");

    // Step 6: Capture packets and process them
    pcap_loop(handle, 10, packet_handler, NULL); // Capture 10 packets

    // Step 7: Cleanup
    pcap_close(handle);
    pcap_freealldevs(alldevs);

#ifdef _WIN32
    WSACleanup(); // Cleanup Winsock
#endif

    printf("Capture complete.\n");
    return 0;
}