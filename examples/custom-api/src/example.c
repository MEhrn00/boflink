#include <windows.h>

#include <custom-api/custom-api.h>

void go() {
  int version = CustomApiVersion();
  CustomApiPrintf("CustomApiVersion: %d", version);

  int *value = CustomApiAlloc(sizeof(int));

  *value = 123;
  CustomApiPrintf("value: %d", *value);

  CustomApiFree(value);

  DWORD pid = GetCurrentProcessId();
  CustomApiPrintf("current process id: %lu\n", pid);
}
