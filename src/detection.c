#include "detection.h"
#include <stdio.h>

void analyze_packet(const unsigned char *packet, int length)
{
    // Example: Simple detection logic for unusual packet length
    if (length > 1500)
    {
        printf("Suspicious packet detected: Length %d\n", length);
        // Log or alert
    }
}
