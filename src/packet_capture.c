#include "packet_capture.h"
#include "logging.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#ifndef __USE_MISC
#define __USE_MISC
#endif                     // __USE_MISC
#include <arpa/inet.h>     // For INET_ADDRSTRLEN and inet_ntop
#include <netinet/ip.h>    // For IP header
#include <netinet/tcp.h>   // For TCP header
#include <netinet/udp.h>   // For UDP header
#include <netinet/ether.h> // For Ethernet header
#include <unistd.h>        // For read() and select()
#include <termios.h>       // For terminal settings
#include <string.h>        // For strncmp()

static volatile int keep_running = 1;

void handle_signal(int signal)
{
    keep_running = 0;
}

void enable_raw_mode()
{
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &term);
}

void disable_raw_mode()
{
    struct termios term;
    tcgetattr(STDIN_FILENO, &term);
    term.c_lflag |= (ICANON | ECHO);
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

        if (ip_header->ip_p == IPPROTO_TCP)
        {
            struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            if (tcp_header->syn && !tcp_header->ack)
            {
                detect_syn_flood(src_ip);
            }
            detect_sequential_scan(src_ip, ntohs(tcp_header->dest));
        }

        detect_geolocation(src_ip);

        if (ip_header->ip_p == IPPROTO_UDP)
        {
            struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
            // Add UDP-specific detection logic if needed
        }
    }
}

void start_packet_capture(const char *interface)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    fd_set readfds;

    setup_log_file();

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!handle)
    {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    printf("Starting packet capture on interface %s... Press 'q' to stop.\n", interface);

    enable_raw_mode();
    while (keep_running)
    {
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        struct timeval timeout = {1, 0};

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

        pcap_dispatch(handle, 1, packet_handler, NULL);
    }
    disable_raw_mode();
    pcap_close(handle);
    printf("Packet capture stopped.\n");
}
