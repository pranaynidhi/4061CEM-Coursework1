#include "packet_capture.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#ifndef __USE_MISC
#define __USE_MISC
#endif                     // __USE_MISC
#include <netinet/ip.h>    // For IP header
#include <netinet/tcp.h>   // For TCP header
#include <netinet/udp.h>   // For UDP header
#include <netinet/ether.h> // For Ethernet header

#include <unistd.h>  // For read() and select()
#include <termios.h> // For terminal settings

#include <time.h> // For timestamp generation

static volatile int keep_running = 1;

void handle_signal(int signal)
{
    keep_running = 0;
}

void enable_raw_mode()
{
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~(ICANON | ECHO); // Disable canonical mode and echo
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

void disable_raw_mode()
{
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag |= (ICANON | ECHO); // Enable canonical mode and echo
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    struct ether_header *eth_header = (struct ether_header *)packet;
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);

        printf("Captured IP Packet: Src: %s, Dst: %s\n", src_ip, dst_ip);

        char log_entry[256];
        snprintf(log_entry, sizeof(log_entry), "Packet captured: Src IP: %s, Dst IP: %s, Length: %d", src_ip, dst_ip, header->len);
        log_event(log_entry);

        if (ip_header->ip_p == IPPROTO_TCP)
        {
            printf("Protocol: TCP\n");
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            printf("Src Port: %d, Dst Port: %d\n", ntohs(tcp_header->source), ntohs(tcp_header->dest));
        }
        else if (ip_header->ip_p == IPPROTO_UDP)
        {
            printf("Protocol: UDP\n");
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            printf("Src Port: %d, Dst Port: %d\n", ntohs(udp_header->source), ntohs(udp_header->dest));
        }
        else
        {
            printf("Protocol: Other\n");
        }
    }
}

void start_packet_capture(const char *interface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    fd_set readfds;

    setup_log_file(); // Call the setup_log_file from logging.c

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Starting packet capture on interface %s... Press 'q' to stop.\n", interface);

    enable_raw_mode(); // Enable raw mode for keyboard input
    while (keep_running)
    {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);  // Monitor standard input
        struct timeval timeout = {1, 0}; // 1-second timeout

        int result = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &timeout);
        if (result > 0 && FD_ISSET(STDIN_FILENO, &readfds))
        {
            char c;
            read(STDIN_FILENO, &c, 1);
            if (c == 'q')
            {
                printf("Stopping packet capture...\n");
                break;
            }
        }

        pcap_dispatch(handle, 1, packet_handler, NULL); // Process one packet
    }
    disable_raw_mode(); // Restore terminal settings
    pcap_close(handle);
    printf("Packet capture stopped.\n");
}