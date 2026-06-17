#ifndef CUSTOM_API_H
#define CUSTOM_API_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

__declspec(dllimport) int CustomApiVersion(void);
__declspec(dllimport) void CustomApiPrintf(const char *format, ...);
__declspec(dllimport) void *CustomApiAlloc(size_t size);
__declspec(dllimport) void CustomApiFree(void *ptr);

#ifdef __cplusplus
};
#endif

#endif /* CUSTOM_API */
