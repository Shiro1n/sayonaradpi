#ifndef PACKET_MOD_H
#define PACKET_MOD_H

#include <pcap.h>

// Callback function for packet capture
void packet_handler(u_char *user, const struct pcap_pkthdr *header, const u_char *packet);

#endif // PACKET_MOD_H