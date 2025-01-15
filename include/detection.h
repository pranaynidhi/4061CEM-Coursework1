#ifndef DETECTION_H
#define DETECTION_H

#include <time.h>
#include <arpa/inet.h>

#define PORT_SCAN_THRESHOLD 10
#define TIME_WINDOW 10 // seconds
#define MAX_ENTRIES 100

typedef struct
{
    char src_ip[INET_ADDRSTRLEN];
    int port_attempts;
    time_t last_attempt;
} PortScanEntry;

// Function prototypes
void analyze_packet(const unsigned char *packet, int length, const char *src_ip, const char *dst_ip, int src_port, int dst_port);
void add_to_whitelist(const char *ip);
void add_to_blacklist(const char *ip);

#endif
