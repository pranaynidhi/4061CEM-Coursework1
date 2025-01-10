#ifndef __USE_MISC
#define __USE_MISC
#endif // __USE_MISC

#include <netinet/ip.h>
#include <stdio.h>
#include <string.h>

void analyze_packet(const unsigned char *packet, int length)
{
    static int packet_count = 0;
    packet_count++;

    if (packet_count % 10 == 0)
    {
        printf("Packet count reached %d.\n", packet_count);
    }

    // Example: Flag packets larger than a threshold
    if (length > 1200)
    {
        log_event("Large packet detected!");
        printf("Large packet detected and logged.\n");
    }
}
