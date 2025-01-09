#include "packet_capture.h"
#include <stdio.h>

int main()
{
    const char *interface = "wlan0"; // Replace with your network interface
    start_packet_capture(interface);
    return 0;
}
