#include "monitoring.h"
#include "logging.h"
#include "detection.h"
#include "packet_capture.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define ANSI_COLOR_RED "\033[31m"
#define ANSI_COLOR_GREEN "\033[32m"
#define ANSI_COLOR_YELLOW "\033[33m"
#define ANSI_COLOR_RESET "\033[0m"

void print_menu()
{
    printf(ANSI_COLOR_GREEN "\n==========================\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW "Basic Intrusion Detection System\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_GREEN "==========================\n" ANSI_COLOR_RESET);
    printf("Available Commands:\n");
    printf(ANSI_COLOR_GREEN "1. start" ANSI_COLOR_RESET " - Begin packet capture\n");
    printf(ANSI_COLOR_GREEN "2. monitor" ANSI_COLOR_RESET " - Start real-time monitoring\n");
    printf(ANSI_COLOR_GREEN "3. view logs" ANSI_COLOR_RESET " - Display intrusion logs\n");
    printf(ANSI_COLOR_GREEN "4. help" ANSI_COLOR_RESET " - Show this menu\n");
    printf(ANSI_COLOR_GREEN "5. exit" ANSI_COLOR_RESET " - Exit the program\n");
    printf(ANSI_COLOR_GREEN "==========================\n" ANSI_COLOR_RESET);
}

int main(int argc, char *argv[])
{
    const char *interface = "wlan0"; // Default interface
    if (argc > 1)
    {
        interface = argv[1];
    }

    char command[100];
    print_menu();

    while (1)
    {
        printf(ANSI_COLOR_YELLOW "> " ANSI_COLOR_RESET);
        fgets(command, sizeof(command), stdin);
        command[strcspn(command, "\n")] = 0; // Remove newline

        if (strcmp(command, "start") == 0)
        {
            printf(ANSI_COLOR_GREEN "Starting packet capture...\n" ANSI_COLOR_RESET);
            start_packet_capture(interface);
        }
        else if (strcmp(command, "monitor") == 0)
        {
            printf(ANSI_COLOR_GREEN "Starting real-time monitoring...\n" ANSI_COLOR_RESET);
            start_monitoring(interface);
        }
        else if (strcmp(command, "view logs") == 0)
        {
            printf(ANSI_COLOR_GREEN "Displaying logs:\n" ANSI_COLOR_RESET);
            system("cat logs/intrusion_log.txt");
        }
        else if (strcmp(command, "help") == 0)
        {
            print_menu();
        }
        else if (strcmp(command, "exit") == 0)
        {
            printf(ANSI_COLOR_RED "Exiting the program. Goodbye!\n" ANSI_COLOR_RESET);
            break;
        }
        else
        {
            printf(ANSI_COLOR_RED "Unknown command. Type 'help' to see available commands.\n" ANSI_COLOR_RESET);
        }
    }

    return 0;
}
