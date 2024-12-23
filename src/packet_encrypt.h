#ifndef PACKET_ENCRYPT_H
#define PACKET_ENCRYPT_H

#include <libnet.h>
#include <pcap.h>

// Encrypt packet payload with DPI-evasion techniques
void encrypt_payload(u_char *payload, int len, const u_char *key, int key_len);

// Modify and forward the packet using Libnet
void modify_and_forward_packet(const u_char *packet, int len);

#endif // PACKET_ENCRYPT_H
