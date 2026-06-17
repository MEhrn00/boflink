#include <windows.h>

#include <lmcons.h>

#include "beacon.h"
#include <mylib/mylib.h>

void go() {
  int ret = MylibAdd(1, 2);
  BeaconPrintf(CALLBACK_OUTPUT, "MylibAdd(1, 2) = %d", ret);

  HMODULE kernel32 = MylibGetModuleHandle(L"kernel32.dll");
  BeaconPrintf(CALLBACK_OUTPUT, "MylibGetModuleHandle(L\"kernel32.dll\") = %p", kernel32);

  void *GetCurrentProcessIdFnPtr = MylibGetProcAddress(kernel32, "GetCurrentProcessId");
  BeaconPrintf(CALLBACK_OUTPUT,
               "MylibGetProcAddress(kernel32, \"GetCurrentProcessId\") = %p",
               GetCurrentProcessIdFnPtr);
}
