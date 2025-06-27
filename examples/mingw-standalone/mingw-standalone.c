#include <windows.h>

#include <lmcons.h>

#include "beacon.h"

void go(void) {
    BeaconPrintf(CALLBACK_OUTPUT, "Hello, World!");

    DWORD pid = GetCurrentProcessId();
    BeaconPrintf(CALLBACK_OUTPUT, "Current process id is %lu", pid);

    char username[UNLEN + 1] = {0};
    if (GetUserNameA(username, &(DWORD){sizeof(username)}) != 0) {
        BeaconPrintf(CALLBACK_OUTPUT, "Your username is %s", username);
    }
}
