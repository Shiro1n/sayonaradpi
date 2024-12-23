#include "packet_mod.h"
#include "packet_encrypt.h"
#include <stdio.h>
#include <winsock2.h> // For IP and TCP-related structures
#include <windows.h>

// Custom IP Header for Windows
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

// Custom TCP Header for Windows
typedef struct tcp_header {
    unsigned short source;   // Source port
    unsigned short dest;     // Destination port
    unsigned int seq;        // Sequence number
    unsigned int ack_seq;    // Acknowledgment number
    unsigned short flags;    // Flags (includes data offset)
    unsigned short window;   // Window size
    unsigned short checksum; // Checksum
    unsigned short urg_ptr;  // Urgent pointer
} TCP_HEADER;

void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("Captured packet: %u bytes\n", header->len);

    const u_char key[] = {0x55, 0xAA, 0x5A, 0xA5}; // Example key array
    int key_len = sizeof(key) / sizeof(key[0]);

    // Extract IP header
    struct libnet_ipv4_hdr *ip_header = (struct libnet_ipv4_hdr *)(packet + 14);

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct libnet_tcp_hdr *tcp_header = (struct libnet_tcp_hdr *)(packet + 14 + ip_header->ip_hl * 4);
        int tcp_offset = (tcp_header->th_off >> 4) * 4; // Extract TCP header size
        u_char *payload = (u_char *)tcp_header + tcp_offset;

        int payload_len = ntohs(ip_header->ip_len) -
                          (ip_header->ip_hl * 4 + tcp_offset);

        if (payload_len > 0) {
            printf("Encrypting payload of length: %d\n", payload_len);

            // Encrypt the payload using the key array
            encrypt_payload(payload, payload_len, key, key_len);

            // Forward the modified packet
            modify_and_forward_packet(packet, header->len);
        }
    }
}





