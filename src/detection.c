#include "detection.h"
#include "logging.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#define PORT_SCAN_THRESHOLD 10
#define TIME_WINDOW 10                // seconds
#define HIGH_FREQUENCY_THRESHOLD 1000 // Packets per second

#include <maxminddb.h>

void detect_geolocation(const char *src_ip)
{
    MMDB_s mmdb;
    int status = MMDB_open("GeoLite2-City.mmdb", MMDB_MODE_MMAP, &mmdb);
    if (status != MMDB_SUCCESS)
    {
        fprintf(stderr, "Failed to open GeoLite2 database: %s\n", MMDB_strerror(status));
        return;
    }

    int gai_error, mmdb_error;
    MMDB_lookup_result_s result = MMDB_lookup_string(&mmdb, src_ip, &gai_error, &mmdb_error);
    if (gai_error != 0)
    {
        fprintf(stderr, "Error from getaddrinfo for %s: %s\n", src_ip, gai_strerror(gai_error));
        MMDB_close(&mmdb);
        return;
    }
    if (mmdb_error != MMDB_SUCCESS)
    {
        fprintf(stderr, "Error from libmaxminddb: %s\n", MMDB_strerror(mmdb_error));
        MMDB_close(&mmdb);
        return;
    }

    if (result.found_entry)
    {
        MMDB_entry_data_s entry_data;
        if (MMDB_get_value(&result.entry, &entry_data, "country", "names", "en", NULL) == MMDB_SUCCESS)
        {
            if (entry_data.has_data)
            {
                printf("Traffic from %s: %.*s\n", src_ip, entry_data.data_size, entry_data.utf8_string);
                char log_message[256];
                snprintf(log_message, sizeof(log_message), "Traffic from %s: %.*s", src_ip, entry_data.data_size, entry_data.utf8_string);
                log_event(log_message, "INFO");

                if (strncmp(entry_data.utf8_string, "SuspiciousCountry", entry_data.data_size) == 0)
                {
                    // Add logic for handling traffic from suspicious countries
                    snprintf(log_message, sizeof(log_message), "Suspicious traffic detected from %.*s (IP: %s)", entry_data.data_size, entry_data.utf8_string, src_ip);
                    log_event(log_message, "HIGH");
                }
            }
            else
            {
                fprintf(stderr, "No valid country name found for IP: %s\n", src_ip);
            }
        }
        else
        {
            fprintf(stderr, "Failed to get country name for IP: %s\n", src_ip);
        }
    }
    else
    {
        fprintf(stderr, "No entry found for IP: %s\n", src_ip);
    }

    MMDB_close(&mmdb);
}

void detect_http_attack(const char *payload, const char *src_ip)
{
    if (strstr(payload, "DROP TABLE") || strstr(payload, "../"))
    {
        char alert[256];
        snprintf(alert, sizeof(alert), "Potential HTTP attack detected from %s: %s", src_ip, payload);
        printf("ALERT: %s\n", alert);
        log_event(alert, "HIGH");
    }
}

void detect_sequential_scan(const char *src_ip, int dst_port)
{
    static int last_port = 0;
    static char last_ip[INET_ADDRSTRLEN] = "";
    static int sequential_count = 0;

    if (strcmp(src_ip, last_ip) == 0 && dst_port == last_port + 1)
    {
        sequential_count++;
        if (sequential_count >= 5)
        {
            char alert[256];
            snprintf(alert, sizeof(alert), "Sequential port scan detected from %s", src_ip);
            printf("ALERT: %s\n", alert);
            log_event(alert, "HIGH");
            sequential_count = 0;
        }
    }
    else
    {
        sequential_count = 1;
    }
    strncpy(last_ip, src_ip, INET_ADDRSTRLEN);
    last_port = dst_port;
}

#define MAX_ENTRIES 100
static PortScanEntry port_scan_table[MAX_ENTRIES];
static int table_size = 0;

// Whitelist and blacklist
static char whitelist[MAX_ENTRIES][INET_ADDRSTRLEN];
static char blacklist[MAX_ENTRIES][INET_ADDRSTRLEN];
static int whitelist_size = 0;
static int blacklist_size = 0;

void reset_old_entries()
{
    time_t now = time(NULL);
    for (int i = 0; i < table_size; ++i)
    {
        if (difftime(now, port_scan_table[i].last_attempt) > TIME_WINDOW)
        {
            // Reset old entries
            port_scan_table[i] = port_scan_table[table_size - 1];
            table_size--;
        }
    }
}

int is_whitelisted(const char *ip)
{
    for (int i = 0; i < whitelist_size; i++)
    {
        if (strcmp(whitelist[i], ip) == 0)
        {
            return 1;
        }
    }
    return 0;
}

int is_blacklisted(const char *ip)
{
    for (int i = 0; i < blacklist_size; i++)
    {
        if (strcmp(blacklist[i], ip) == 0)
        {
            return 1;
        }
    }
    return 0;
}

void add_to_whitelist(const char *ip)
{
    if (whitelist_size < MAX_ENTRIES)
    {
        strncpy(whitelist[whitelist_size], ip, INET_ADDRSTRLEN);
        whitelist_size++;
        char message[256];
        snprintf(message, sizeof(message), "Added to whitelist: %s", ip);
        log_event(message, "CONFIG");
    }
}

void add_to_blacklist(const char *ip)
{
    if (blacklist_size < MAX_ENTRIES)
    {
        strncpy(blacklist[blacklist_size], ip, INET_ADDRSTRLEN);
        blacklist_size++;
        char message[256];
        snprintf(message, sizeof(message), "Added to blacklist: %s", ip);
        log_event(message, "CONFIG");
    }
}

#define SYN_THRESHOLD 10

typedef struct
{
    char src_ip[INET_ADDRSTRLEN];
    int syn_count;
    time_t last_syn_time;
} SynFloodEntry;

static SynFloodEntry syn_table[MAX_ENTRIES];
static int syn_table_size = 0;

void detect_syn_flood(const char *src_ip)
{
    time_t now = time(NULL);
    for (int i = 0; i < syn_table_size; i++)
    {
        if (strcmp(syn_table[i].src_ip, src_ip) == 0)
        {
            syn_table[i].syn_count++;
            syn_table[i].last_syn_time = now;

            if (syn_table[i].syn_count > SYN_THRESHOLD)
            {
                char alert[256];
                snprintf(alert, sizeof(alert), "SYN flood detected from %s", src_ip);
                printf("ALERT: %s\n", alert);
                log_event(alert, "INFO");
            }
            return;
        }
    }

    if (syn_table_size < MAX_ENTRIES)
    {
        strncpy(syn_table[syn_table_size].src_ip, src_ip, INET_ADDRSTRLEN);
        syn_table[syn_table_size].syn_count = 1;
        syn_table[syn_table_size].last_syn_time = now;
        syn_table_size++;
    }
}

void detect_port_scan(const char *src_ip)
{
    reset_old_entries();

    if (is_whitelisted(src_ip))
    {
        return; // Skip whitelisted IPs
    }

    for (int i = 0; i < table_size; ++i)
    {
        if (strcmp(port_scan_table[i].src_ip, src_ip) == 0)
        {
            port_scan_table[i].port_attempts++;
            port_scan_table[i].last_attempt = time(NULL);

            if (port_scan_table[i].port_attempts > PORT_SCAN_THRESHOLD)
            {
                char alert[256];
                snprintf(alert, sizeof(alert), "Port scanning detected from %s", src_ip);
                printf("ALERT: %s\n", alert);
                log_event(alert, "MEDIUM");

                if (is_blacklisted(src_ip))
                {
                    char blacklist_alert[256];
                    snprintf(blacklist_alert, sizeof(blacklist_alert), "Blacklisted IP activity detected: %s", src_ip);
                    log_event(blacklist_alert, "HIGH");
                }
            }
            return;
        }
    }

    // Add a new entry
    if (table_size < MAX_ENTRIES)
    {
        strncpy(port_scan_table[table_size].src_ip, src_ip, INET_ADDRSTRLEN);
        port_scan_table[table_size].port_attempts = 1;
        port_scan_table[table_size].last_attempt = time(NULL);
        table_size++;
    }
}

void analyze_packet(const unsigned char *packet, int length, const char *src_ip, const char *dst_ip, int src_port, int dst_port)
{
    // Detect large packets
    if (length > 1500)
    {
        char alert[256];
        snprintf(alert, sizeof(alert), "Large packet detected: Src IP: %s, Dst IP: %s, Length: %d", src_ip, dst_ip, length);
        printf("ALERT: %s\n", alert);
        log_event(alert, "LOW");
    }

    // Detect port scanning
    detect_port_scan(src_ip);

    // Detect suspicious ports
    if (dst_port == 22 || dst_port == 23)
    {
        char alert[256];
        snprintf(alert, sizeof(alert), "Suspicious access detected: Src IP: %s, Dst Port: %d", src_ip, dst_port);
        printf("ALERT: %s\n", alert);
        log_event(alert, "INFO");
    }
}