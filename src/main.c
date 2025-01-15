#include "packet_capture.h"
#include "logging.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char command[100];
    const char *interface;

    if (argc > 1)
    {
        interface = argv[1];
    }
    else
    {
        interface = "wlan0"; // Default interface
    }

    printf("Welcome to the Basic IDS. Type 'start' to begin or 'exit' to quit.\n");
    while (1)
    {
        printf("> ");
        fgets(command, sizeof(command), stdin);
        command[strcspn(command, "\n")] = 0; // Remove newline

        if (strcmp(command, "start") == 0)
        {
            start_packet_capture(interface);
        }
        else if (strcmp(command, "view logs") == 0)
        {
            printf("Displaying logs:\n");
            system("cat logs/intrusion_log*.txt");
        }
        else if (strcmp(command, "exit") == 0)
        {
            break;
        }
        else
        {
            printf("Unknown command. Try 'start', 'view logs', or 'exit'.\n");
        }
    }
    return 0;
}
