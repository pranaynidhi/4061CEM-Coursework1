#include "logging.h"
#include <stdio.h>
#include <time.h>
#include <sys/stat.h>

static char log_file_path[256];

void setup_log_file()
{
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char dir_path[64] = "logs";

    // Create logs directory if it doesn't exist
    mkdir(dir_path, 0777);

    // Generate unique log file name with timestamp
    snprintf(log_file_path, sizeof(log_file_path), "%s/intrusion_log_%04d%02d%02d_%02d%02d%02d.txt",
             dir_path, t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    printf("Logs will be saved in: %s\n", log_file_path);
}

void log_event(const char *event, const char *severity)
{
    FILE *file = fopen(log_file_path, "a");
    if (!file)
    {
        perror("Error opening log file");
        return;
    }
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    fprintf(file, "[%04d-%02d-%02d %02d:%02d:%02d] [%s] %s\n",
            t->tm_year + 1900, t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, severity, event);
    fclose(file);
}
