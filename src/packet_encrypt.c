#include <stdio.h>
#include <libnet.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include "packet_encrypt.h"

// Define Ethernet header length
#define ETHERNET_HEADER_LENGTH 14

void encrypt_payload(u_char *payload, int len, const u_char *key, int key_len) {
    if (!payload || len <= 0 || !key || key_len <= 0) {
        fprintf(stderr, "Invalid payload, key, or key length.\n");
        return;
    }

    const int DEBUG = 0; // Debugging flag
    const char *http_methods[] = {"GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "CONNECT", "TRACE", "PATCH"};
    size_t num_methods = sizeof(http_methods) / sizeof(http_methods[0]);

    // Check for HTTP methods
    for (size_t i = 0; i < num_methods; i++) {
        size_t method_len = strlen(http_methods[i]);
        if (len > method_len && memcmp(payload, http_methods[i], method_len) == 0) {
            if (DEBUG) {
                printf("HTTP method found: %s\n", http_methods[i]);
            }

            // Corrupt the HTTP method
            payload[1] = ' ';

            // XOR part of the payload with the key
            for (int j = method_len; j < len && j < method_len + 10; j++) {
                payload[j] ^= key[j % key_len]; // Use multi-byte key
            }
            return;
        }
    }

    // Fallback: XOR encrypt the entire payload with the key
    for (int i = 0; i < len; i++) {
        payload[i] ^= key[i % key_len]; // Use multi-byte key
    }

    // Add random padding to the payload
    int padding_size = rand() % 16 + 1; // Random padding size (1-16 bytes)
    for (int i = len; i < len + padding_size; i++) {
        payload[i] = rand() % 256;
    }
}


void modify_and_forward_packet(const u_char *packet, int len) {
    libnet_t *ln; // Libnet context
    char errbuf[LIBNET_ERRBUF_SIZE];

    // Initialize Libnet
    ln = libnet_init(LIBNET_LINK_ADV, NULL, errbuf);
    if (ln == NULL) {
        fprintf(stderr, "Libnet initialization failed: %s\n", errbuf);
        return;
    }

    // Extract the Ethernet header
    const u_char *eth_header = packet;

    // Extract the IP header
    struct libnet_ipv4_hdr *ip_header = (struct libnet_ipv4_hdr *)(packet + ETHERNET_HEADER_LENGTH);
    if (len < ETHERNET_HEADER_LENGTH + sizeof(struct libnet_ipv4_hdr)) {
        fprintf(stderr, "Packet too short for IP header.\n");
        libnet_destroy(ln);
        return;
    }

    int ip_header_length = ip_header->ip_hl * 4;

    // Check if the protocol is TCP or UDP
    if (ip_header->ip_p != IPPROTO_TCP && ip_header->ip_p != IPPROTO_UDP) {
        fprintf(stderr, "Only TCP and UDP packets are supported.\n");
        libnet_destroy(ln);
        return;
    }

    // Extract TCP or UDP header
    u_char *transport_header = (u_char *)(packet + ETHERNET_HEADER_LENGTH + ip_header_length);
    int transport_header_length = (ip_header->ip_p == IPPROTO_TCP)
                                       ? (((struct libnet_tcp_hdr *)transport_header)->th_off * 4)
                                       : sizeof(struct libnet_udp_hdr);

    if (len < ETHERNET_HEADER_LENGTH + ip_header_length + transport_header_length) {
        fprintf(stderr, "Packet too short for transport header.\n");
        libnet_destroy(ln);
        return;
    }

    // Calculate payload offset and length
    u_char *payload = (u_char *)(packet + ETHERNET_HEADER_LENGTH + ip_header_length + transport_header_length);
    int payload_length = ntohs(ip_header->ip_len) - ip_header_length - transport_header_length;

    if (payload_length > 0) {
        // Define a key array
        const u_char key[] = {0x55, 0xAA, 0x5A, 0xA5}; // Example key array
        int key_len = sizeof(key) / sizeof(key[0]);

        // Encrypt the payload using the key array
        encrypt_payload(payload, payload_length, key, key_len);

        // Rebuild the packet using Libnet
        if (libnet_build_ipv4(
                ntohs(ip_header->ip_len), ip_header->ip_tos, ntohs(ip_header->ip_id),
                ntohs(ip_header->ip_off), ip_header->ip_ttl, ip_header->ip_p, 0,
                ip_header->ip_src.s_addr, ip_header->ip_dst.s_addr, payload, payload_length, ln, 0) == -1) {
            fprintf(stderr, "Failed to rebuild IP header: %s\n", libnet_geterror(ln));
            libnet_destroy(ln);
            return;
        }

        // Rebuild Ethernet header
        if (libnet_build_ethernet(
                eth_header + 6, eth_header, ntohs(*(uint16_t *)(eth_header + 12)),
                NULL, 0, ln, 0) == -1) {
            fprintf(stderr, "Failed to rebuild Ethernet header: %s\n", libnet_geterror(ln));
            libnet_destroy(ln);
            return;
        }

        // Write the packet to the network
        if (libnet_write(ln) == -1) {
            fprintf(stderr, "Failed to send packet: %s\n", libnet_geterror(ln));
        } else {
            printf("Modified packet sent successfully.\n");
        }
    } else {
        fprintf(stderr, "No payload to encrypt.\n");
    }

    // Clean up Libnet context
    libnet_destroy(ln);
}