#include "logging.h"
#include <stdio.h>

void log_event(const char *event)
{
    FILE *file = fopen("intrusion_log.txt", "a");
    if (!file)
    {
        perror("Error opening log file");
        return;
    }
    fprintf(file, "%s\n", event);
    fclose(file);
}