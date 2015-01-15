#ifndef LOG_H 
#define LOG_H
#include <stdarg.h>

// From http://stackoverflow.com/questions/6508461/logging-library-for-c
void log_error(const char* message, ...);
void log_warning(const char* message, ...);
void log_info(const char* message, ...);
void log_debug(const char* message, ...);

#endif