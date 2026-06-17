#ifndef MYLIB_H
#define MYLIB_H

#include <windows.h>

int MylibAdd(int, int);

HMODULE MylibGetModuleHandle(LPCWSTR);
void *MylibGetProcAddress(HMODULE, LPCSTR);

#endif /* MYLIB_H */
