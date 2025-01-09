#include "packet_capture.h"
#include <stdio.h>
#include <stdlib.h>

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    printf("Packet captured: Length %d\n", header->len);
    // Parse packet details (e.g., IP, port, protocol)
    // Call detection module here, if needed
}

void start_packet_capture(const char *interface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Starting packet capture on interface %s...\n", interface);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
}
