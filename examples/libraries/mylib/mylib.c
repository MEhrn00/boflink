#include "mylib.h"

#include <windows.h>

int MylibAdd(int a, int b) {
  return a + b;
}

HMODULE MylibGetModuleHandle(LPCWSTR name) {
  return GetModuleHandleW(name);
}

void *MylibGetProcAddress(HMODULE mod, LPCSTR name) {
  return GetProcAddress(mod, name);
}
